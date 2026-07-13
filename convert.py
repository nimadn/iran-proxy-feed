#!/usr/bin/env python3

import concurrent.futures
import json
import subprocess
import urllib.request
from pathlib import Path
from typing import Any

SOURCE_URL = (
    "https://cdn.jsdelivr.net/gh/"
    "proxyscrape/free-proxy-list@main/proxies/all/data.json"
)

OUTPUT_FILE = Path("docs/iran-proxies.yaml")

COUNTRY_CODE = "IR"
SUPPORTED_PROTOCOLS = {"http", "socks5"}

MIN_UPTIME_PERCENT = 5
MAX_REPORTED_LATENCY_MS = 15_000

MAX_CANDIDATES_TO_TEST = 250
MAX_WORKING_PROXIES = 50

TEST_TIMEOUT_SECONDS = 7
TEST_WORKERS = 30

TEST_URL = "https://www.gstatic.com/generate_204"


def download_json() -> list[dict[str, Any]]:
    request = urllib.request.Request(
        SOURCE_URL,
        headers={
            "User-Agent": "IranProxyFeed/1.0",
            "Accept": "application/json",
        },
    )

    with urllib.request.urlopen(request, timeout=30) as response:
        data = json.load(response)

    if not isinstance(data, list):
        raise ValueError("ProxyScrape response is not a JSON list")

    return data


def number(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def normalize_proxy(item: dict[str, Any]) -> dict[str, Any] | None:
    protocol = str(item.get("protocol", "")).lower()
    country = str(item.get("country_code", "")).upper()
    ip = str(item.get("ip", "")).strip()

    try:
        port = int(item.get("port"))
    except (TypeError, ValueError):
        return None

    if country != COUNTRY_CODE:
        return None

    if protocol not in SUPPORTED_PROTOCOLS:
        return None

    if not ip or port < 1 or port > 65535:
        return None

    uptime = number(item.get("uptime_percent"), 0)
    latency = number(item.get("latency_ms"), 999_999)

    if uptime < MIN_UPTIME_PERCENT:
        return None

    if latency > MAX_REPORTED_LATENCY_MS:
        return None

    return {
        "protocol": protocol,
        "ip": ip,
        "port": port,
        "uptime": uptime,
        "reported_latency": latency,
    }


def test_proxy(proxy: dict[str, Any]) -> dict[str, Any] | None:
    proxy_url = (
        f"{proxy['protocol']}://"
        f"{proxy['ip']}:{proxy['port']}"
    )

    command = [
        "curl",
        "--silent",
        "--show-error",
        "--output",
        "/dev/null",
        "--proxy",
        proxy_url,
        "--connect-timeout",
        str(TEST_TIMEOUT_SECONDS),
        "--max-time",
        str(TEST_TIMEOUT_SECONDS),
        "--write-out",
        "%{http_code} %{time_total}",
        TEST_URL,
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=TEST_TIMEOUT_SECONDS + 3,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None

    if result.returncode != 0:
        return None

    output = result.stdout.strip().split()

    if len(output) != 2:
        return None

    status_code, elapsed = output

    if status_code != "204":
        return None

    try:
        measured_latency = float(elapsed)
    except ValueError:
        return None

    tested = dict(proxy)
    tested["measured_latency"] = measured_latency

    return tested


def quote_yaml(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def build_clash_yaml(proxies: list[dict[str, Any]]) -> str:
    lines = [
        "mixed-port: 7890",
        "allow-lan: false",
        "mode: rule",
        "log-level: warning",
        "",
        "proxies:",
    ]

    names: list[str] = []

    for index, proxy in enumerate(proxies, start=1):
        protocol = proxy["protocol"]
        name = f"IR-{protocol.upper()}-{index:02d}"
        names.append(name)

        lines.extend(
            [
                f"  - name: {quote_yaml(name)}",
                f"    type: {protocol}",
                f"    server: {quote_yaml(proxy['ip'])}",
                f"    port: {proxy['port']}",
            ]
        )

        if protocol == "socks5":
            lines.append("    udp: false")

    lines.extend(
        [
            "",
            "proxy-groups:",
            "  - name: 'IR-AUTO'",
            "    type: url-test",
            "    url: 'https://www.gstatic.com/generate_204'",
            "    interval: 300",
            "    tolerance: 150",
            "    proxies:",
        ]
    )

    if names:
        for name in names:
            lines.append(f"      - {quote_yaml(name)}")
    else:
        lines.append("      - DIRECT")

    lines.extend(
        [
            "",
            "  - name: 'IR-SELECT'",
            "    type: select",
            "    proxies:",
            "      - 'IR-AUTO'",
        ]
    )

    for name in names:
        lines.append(f"      - {quote_yaml(name)}")

    lines.extend(
        [
            "      - DIRECT",
            "",
            "rules:",
            "  - MATCH,IR-SELECT",
            "",
        ]
    )

    return "\n".join(lines)


def main() -> None:
    raw_items = download_json()

    unique: dict[tuple[str, str, int], dict[str, Any]] = {}

    for item in raw_items:
        normalized = normalize_proxy(item)

        if normalized is None:
            continue

        key = (
            normalized["protocol"],
            normalized["ip"],
            normalized["port"],
        )

        current = unique.get(key)

        if current is None or normalized["uptime"] > current["uptime"]:
            unique[key] = normalized

    candidates = list(unique.values())

    candidates.sort(
        key=lambda proxy: (
            -proxy["uptime"],
            proxy["reported_latency"],
        )
    )

    candidates = candidates[:MAX_CANDIDATES_TO_TEST]

    working: list[dict[str, Any]] = []

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=TEST_WORKERS
    ) as executor:
        futures = [
            executor.submit(test_proxy, proxy)
            for proxy in candidates
        ]

        for future in concurrent.futures.as_completed(futures):
            tested = future.result()

            if tested is not None:
                working.append(tested)
                print(
                    "Working:",
                    tested["protocol"],
                    tested["ip"],
                    tested["port"],
                    f"{tested['measured_latency']:.2f}s",
                )

    working.sort(
        key=lambda proxy: (
            proxy["measured_latency"],
            -proxy["uptime"],
        )
    )

    working = working[:MAX_WORKING_PROXIES]

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    temporary_file = OUTPUT_FILE.with_suffix(".tmp")
    temporary_file.write_text(
        build_clash_yaml(working),
        encoding="utf-8",
    )
    temporary_file.replace(OUTPUT_FILE)

    print(f"Raw records: {len(raw_items)}")
    print(f"Candidates tested: {len(candidates)}")
    print(f"Working proxies published: {len(working)}")


if __name__ == "__main__":
    main()
