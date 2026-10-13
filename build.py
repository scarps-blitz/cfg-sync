#!/usr/bin/env python3
"""Собирает профиль маршрутизации Happ: базовый профиль roscomvpn + Gemini через SNI-прокси.

Для каждого домена из config.json подбирается живой IP SNI-прокси (свой -> malw -> запасные),
он попадает в DnsHosts, а сам домен в DirectSites. Домен без живого прокси в профиль
не добавляется и продолжает идти через VPN-сервер, как в базовом профиле.
"""

import base64
import ipaddress
import json
import os
import socket
import ssl
import struct
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
GOOGLE_RANGES_URL = "https://www.gstatic.com/ipranges/goog.json"
CONTROL_DOH_URL = "https://1.1.1.1/dns-query"
USER_AGENT = "cfg-sync/1.0"
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"


def log(message):
    print(message, flush=True)


def tls_context():
    context = ssl.create_default_context()
    # Python с python.org на macOS не знает системных корневых сертификатов
    if not context.get_ca_certs() and os.path.exists("/etc/ssl/cert.pem"):
        context.load_verify_locations("/etc/ssl/cert.pem")
    return context


TLS_CONTEXT = tls_context()


def http_get(url, data=None, headers=None, timeout=15):
    request = urllib.request.Request(url, data=data, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(request, timeout=timeout, context=TLS_CONTEXT) as response:
        return response.read()


# --- DNS-over-HTTPS (RFC 8484), только A-записи ---

def dns_query(name):
    message = struct.pack(">HHHHHH", 0, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        message += bytes([len(label)]) + label.encode()
    return message + b"\x00" + struct.pack(">HH", 1, 1)


def skip_name(data, offset):
    while True:
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0:
            return offset + 2
        offset += length + 1


def dns_answers(data):
    _, _, questions, answers, _, _ = struct.unpack(">HHHHHH", data[:12])
    offset = 12
    for _ in range(questions):
        offset = skip_name(data, offset) + 4
    ips = []
    for _ in range(answers):
        offset = skip_name(data, offset)
        rtype, _, _, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        if rtype == 1 and rdlength == 4:
            ips.append(str(ipaddress.IPv4Address(data[offset:offset + 4])))
        offset += rdlength
    return ips


def doh_resolve(url, name):
    try:
        body = http_get(
            url,
            data=dns_query(name),
            headers={"Content-Type": "application/dns-message", "Accept": "application/dns-message"},
            timeout=8,
        )
        return dns_answers(body)
    except Exception:
        return []


# --- Источники адресов прокси ---

def parse_hosts(text):
    mapping = {}
    for line in text.splitlines():
        parts = line.split("#", 1)[0].split()
        if len(parts) >= 2:
            for domain in parts[1:]:
                mapping.setdefault(domain.lower(), []).append(parts[0])
    return mapping


def load_google_networks():
    try:
        prefixes = json.loads(http_get(GOOGLE_RANGES_URL))["prefixes"]
        return [ipaddress.ip_network(p["ipv4Prefix"]) for p in prefixes if "ipv4Prefix" in p]
    except Exception as error:
        log(f"! не удалось загрузить диапазоны Google: {error}")
        return []


def is_proxy_candidate(ip, google_networks, real_ips):
    """Отсекает заглушки и настоящие адреса Google: они не обходят геоблок."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if address.version != 4 or not address.is_global:
        return False
    if ip in real_ips:
        return False
    return not any(address in network for network in google_networks)


def collect_candidates(config):
    """Возвращает {домен: [(ip, источник), ...]} в порядке приоритета."""
    domains = config["domains"]
    google_networks = load_google_networks()
    candidates = {domain: [] for domain in domains}

    def add(domain, ip, source, real_ips):
        if not is_proxy_candidate(ip, google_networks, real_ips):
            return
        if all(ip != known for known, _ in candidates[domain]):
            candidates[domain].append((ip, source))

    with ThreadPoolExecutor(max_workers=8) as pool:
        real = dict(zip(domains, pool.map(lambda d: set(doh_resolve(CONTROL_DOH_URL, d)), domains)))

        for domain in domains:
            for ip in config.get("own_proxy_ips", []):
                add(domain, ip, "own", set())

        for source in config["sources"]:
            if source["type"] == "hosts":
                try:
                    mapping = parse_hosts(http_get(source["url"]).decode("utf-8", "replace"))
                except Exception as error:
                    log(f"! источник {source['name']} недоступен: {error}")
                    continue
                answers = {domain: mapping.get(domain, []) for domain in domains}
            elif source["type"] == "doh":
                resolved = pool.map(lambda d, url=source["url"]: doh_resolve(url, d), domains)
                answers = dict(zip(domains, resolved))
            else:
                raise ValueError(f"неизвестный тип источника: {source['type']}")
            for domain in domains:
                # DoH отдаёт пул в случайном порядке; сортируем, чтобы выбор не прыгал между запусками
                for ip in sorted(answers[domain]):
                    add(domain, ip, source["name"], real[domain])
    return candidates


# --- Проверка прокси ---

def proxy_check(ip, domain, timeout, attempts):
    """Запрос к домену через прокси: "ok", "flagged" (Google отдаёт капчу) или "dead"."""
    request = (
        f"GET / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: {BROWSER_UA}\r\n"
        "Accept: */*\r\nConnection: close\r\n\r\n"
    ).encode()
    for _ in range(attempts):
        try:
            with socket.create_connection((ip, 443), timeout=timeout) as raw:
                with TLS_CONTEXT.wrap_socket(raw, server_hostname=domain) as tls:
                    tls.sendall(request)
                    head = tls.recv(4096).decode("latin-1").lower()
        except (OSError, ssl.SSLError):
            continue
        if not head.startswith("http/"):
            continue
        if head.split(" ", 2)[1] == "429" or "/sorry/" in head:
            return "flagged"
        return "ok"
    return "dead"


def pick_proxies(candidates, timeout, attempts):
    """Возвращает {домен: (ip, источник)} — первый рабочий кандидат по приоритету."""
    pairs = sorted({(ip, domain) for domain, items in candidates.items() for ip, _ in items})
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = pool.map(lambda pair: proxy_check(pair[0], pair[1], timeout, attempts), pairs)
        status = dict(zip(pairs, results))
    # Адрес, с которого Google хоть раз отдал капчу, не берём ни для одного домена
    flagged = {ip for (ip, _), result in status.items() if result == "flagged"}
    for ip in sorted(flagged):
        log(f"! {ip} отдаёт капчу Google — пропущен")
    chosen = {}
    for domain, items in candidates.items():
        for ip, source in items:
            if ip not in flagged and status[(ip, domain)] == "ok":
                chosen[domain] = (ip, source)
                break
    return chosen


# --- Сборка профиля ---

def merge_profile(base, chosen):
    profile = json.loads(json.dumps(base))
    hosts = dict(profile.get("DnsHosts") or {})
    direct = list(profile.get("DirectSites") or [])
    for domain, (ip, _) in chosen.items():
        hosts[domain] = ip
        rule = f"full:{domain}"
        if rule not in direct:
            direct.append(rule)
    profile["DnsHosts"] = hosts
    profile["DirectSites"] = direct
    return profile


def without_timestamp(profile):
    return {key: value for key, value in profile.items() if key != "LastUpdated"}


def write_outputs(profile, name):
    DIST.mkdir(exist_ok=True)
    json_path = DIST / f"{name}.JSON"
    # LastUpdated меняем только при реальных изменениях, чтобы Happ не перекачивал профиль зря
    profile["LastUpdated"] = str(int(time.time()))
    if json_path.exists():
        try:
            previous = json.loads(json_path.read_text(encoding="utf-8"))
            if without_timestamp(previous) == without_timestamp(profile):
                log("= профиль не изменился")
                return False
        except ValueError:
            pass
    text = json.dumps(profile, ensure_ascii=False, indent=2) + "\n"
    json_path.write_text(text, encoding="utf-8")
    deeplink = "happ://routing/onadd/" + base64.b64encode(text.encode()).decode()
    (DIST / f"{name}.DEEPLINK").write_text(deeplink + "\n", encoding="utf-8")
    log(f"+ записан {json_path.relative_to(ROOT)}")
    return True


def main():
    config = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))
    # Без базового профиля не публикуем ничего: в dist остаётся последняя рабочая версия
    base = json.loads(http_get(config["base_profile_url"]))

    candidates = collect_candidates(config)
    chosen = pick_proxies(candidates, config["check_timeout_seconds"], config["check_attempts"])

    for domain in config["domains"]:
        if domain in chosen:
            ip, source = chosen[domain]
            log(f"  {domain:52} {ip:16} {source}")
        else:
            tried = ", ".join(ip for ip, _ in candidates[domain]) or "нет кандидатов"
            log(f"! {domain:52} нет живого прокси ({tried}) — пойдёт через VPN")

    write_outputs(merge_profile(base, chosen), config["output_name"])
    if not chosen:
        log("! ни одного живого прокси: профиль равен базовому")


if __name__ == "__main__":
    sys.exit(main())
