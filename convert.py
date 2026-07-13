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

YAML_OUTPUT = Path("docs/iran-proxies.yaml")
JSON_OUTPUT = Path("docs/iran-proxies.json")

SUPPORTED_PROTOCOLS = {"http", "socks4", "socks5"}

TEST_TIMEOUT_SECONDS = 8
TEST_WORKERS = 40
TEST_URL = "https://www.gstatic.com/generate_204"


def download_json() -> list[dict[str, Any]]:
    request = urllib.request.Request(
        SOURCE_URL,
        headers={
            "User-Agent": "IranProxyFeed/2.0",
            "Accept": "application/json",
        },
    )

    with urllib.request.urlopen(request, timeout=60) as response:
        data = json.load(response)

    if not isinstance(data, list):
        raise ValueError("The source response is not a JSON list")

    return data


def is_iranian(item: dict[str, Any]) -> bool:
    country_code = str(item.get("country_code", "")).strip().upper()
    country = str(item.get("country", "")).strip().lower()
    city = str(item.get("city", "")).strip().lower()

    return (
        country_code == "IR"
        or "iran" in country
        or "tehran" in city
    )


def normalize_proxy(
    item: dict[str, Any],
) -> dict[str, Any] | None:
    protocol = str(item.get("protocol", "")).strip().lower()
    ip = str(item.get("ip", "")).strip()

    try:
        port = int(item.get("port"))
    except (TypeError, ValueError):
        return None

    if protocol not in SUPPORTED_PROTOCOLS:
        return None

    if not is_iranian(item):
        return None

    if not ip or not 1 <= port <= 65535:
        return None

    return {
        "protocol": protocol,
        "ip": ip,
        "port": port,
        "country": str(item.get("country", "")),
        "country_code": str(item.get("country_code", "")),
        "city": str(item.get("city", "")),
        "uptime": item.get("uptime_percent", 0),
        "latency": item.get("latency_ms", 0),
    }


def proxy_url(proxy: dict[str, Any]) -> str:
    protocol = proxy["protocol"]

    if protocol == "socks5":
        protocol = "socks5h"

    return f"{protocol}://{proxy['ip']}:{proxy['port']}"


def test_proxy(
    proxy: dict[str, Any],
) -> dict[str, Any] | None:
    command = [
        "curl",
        "--silent",
        "--output",
        "/dev/null",
        "--proxy",
        proxy_url(proxy),
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
            timeout=TEST_TIMEOUT_SECONDS + 3,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None

    if result.returncode != 0:
        return None

    parts = result.stdout.strip().split()

    if len(parts) != 2 or parts[0] != "204":
        return None

    tested = dict(proxy)

    try:
        tested["measured_latency"] = float(parts[1])
    except ValueError:
        tested["measured_latency"] = 999

    return tested


def yaml_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def build_clash_yaml(
    proxies: list[dict[str, Any]],
) -> str:
    # Clash/Hiddify YAML feed: HTTP and SOCKS5 only.
    compatible = [
        proxy
        for proxy in proxies
        if proxy["protocol"] in {"http", "socks5"}
    ]

    lines = [
        "mixed-port: 7890",
        "allow-lan: false",
        "mode: rule",
        "log-level: warning",
        "",
        "proxies:",
    ]

    names = []

    for index, proxy in enumerate(compatible, start=1):
        protocol = proxy["protocol"]
        name = f"IR-{protocol.upper()}-{index:03d}"
        names.append(name)

        lines.extend(
            [
                f"  - name: {yaml_quote(name)}",
                f"    type: {protocol}",
                f"    server: {yaml_quote(proxy['ip'])}",
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
            "    tolerance: 200",
            "    proxies:",
        ]
    )

    if names:
        for name in names:
            lines.append(f"      - {yaml_quote(name)}")
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
        lines.append(f"      - {yaml_quote(name)}")

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


def make_singbox_outbound(
    proxy: dict[str, Any],
    index: int,
) -> tuple[str, dict[str, Any]]:
    protocol = proxy["protocol"]
    tag = f"IR-{protocol.upper()}-{index:03d}"

    if protocol == "http":
        outbound = {
            "type": "http",
            "tag": tag,
            "server": proxy["ip"],
            "server_port": proxy["port"],
        }
    else:
        outbound = {
            "type": "socks",
            "tag": tag,
            "server": proxy["ip"],
            "server_port": proxy["port"],
            "version": "4" if protocol == "socks4" else "5",
        }

    return tag, outbound


def build_singbox_json(
    proxies: list[dict[str, Any]],
) -> dict[str, Any]:
    tags = []
    proxy_outbounds = []

    for index, proxy in enumerate(proxies, start=1):
        tag, outbound = make_singbox_outbound(proxy, index)
        tags.append(tag)
        proxy_outbounds.append(outbound)

    if not tags:
        return {
            "log": {"level": "warn"},
            "outbounds": [
                {
                    "type": "direct",
                    "tag": "DIRECT",
                }
            ],
            "route": {
                "final": "DIRECT",
                "auto_detect_interface": True,
            },
        }

    return {
        "log": {
            "level": "warn",
            "timestamp": True,
        },
        "outbounds": [
            {
                "type": "selector",
                "tag": "IR-SELECT",
                "outbounds": ["IR-AUTO", *tags, "DIRECT"],
                "default": "IR-AUTO",
            },
            {
                "type": "urltest",
                "tag": "IR-AUTO",
                "outbounds": tags,
                "url": TEST_URL,
                "interval": "10m",
                "tolerance": 200,
            },
            *proxy_outbounds,
            {
                "type": "direct",
                "tag": "DIRECT",
            },
        ],
        "route": {
            "final": "IR-SELECT",
            "auto_detect_interface": True,
        },
    }


def main() -> None:
    raw_items = download_json()

    unique: dict[
        tuple[str, str, int],
        dict[str, Any],
    ] = {}

    for item in raw_items:
        normalized = normalize_proxy(item)

        if normalized is None:
            continue

        key = (
            normalized["protocol"],
            normalized["ip"],
            normalized["port"],
        )

        unique[key] = normalized

    all_iranian = list(unique.values())

    all_iranian.sort(
        key=lambda proxy: (
            proxy["protocol"],
            proxy["ip"],
            proxy["port"],
        )
    )

    print(f"All matched Iranian proxies: {len(all_iranian)}")

    protocol_counts = {
        protocol: sum(
            proxy["protocol"] == protocol
            for proxy in all_iranian
        )
        for protocol in sorted(SUPPORTED_PROTOCOLS)
    }

    print(f"Protocol counts: {protocol_counts}")

    # Test all matching proxies. No initial uptime or latency filtering.
    working: list[dict[str, Any]] = []

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=TEST_WORKERS
    ) as executor:
        futures = [
            executor.submit(test_proxy, proxy)
            for proxy in all_iranian
        ]

        for future in concurrent.futures.as_completed(futures):
            tested = future.result()

            if tested is not None:
                working.append(tested)

    working.sort(
        key=lambda proxy: proxy.get(
            "measured_latency",
            999,
        )
    )

    print(f"Working from GitHub runner: {len(working)}")

    YAML_OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    # Tested HTTP/SOCKS5 feed.
    YAML_OUTPUT.write_text(
        build_clash_yaml(working),
        encoding="utf-8",
    )

    # Complete feed: every Iranian HTTP/SOCKS4/SOCKS5 entry.
    JSON_OUTPUT.write_text(
        json.dumps(
            build_singbox_json(all_iranian),
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print(f"Tested YAML written to: {YAML_OUTPUT}")
    print(f"Complete JSON written to: {JSON_OUTPUT}")


if __name__ == "__main__":
    main()
