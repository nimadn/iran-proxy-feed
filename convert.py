#!/usr/bin/env python3

import base64
import ipaddress
import json
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

SOURCE_URL = (
    "https://cdn.jsdelivr.net/gh/proxyscrape/"
    "free-proxy-list@main/proxies/all/data.json"
)

SINGBOX_OUTPUT = Path("docs/iran-all.json")
PLAIN_OUTPUT = Path("docs/iran-all-plain.txt")

V2RAY_OUTPUT = Path("docs/iran-v2ray.txt")
V2RAY_PLAIN_OUTPUT = Path("docs/iran-v2ray-plain.txt")

SUPPORTED_PROTOCOLS = {
    "http",
    "socks4",
    "socks5",
}


def download_source() -> list[dict[str, Any]]:
    request = urllib.request.Request(
        SOURCE_URL,
        headers={
            "User-Agent": "IranProxyFeed/7.0",
            "Accept": "application/json",
        },
    )

    with urllib.request.urlopen(request, timeout=90) as response:
        data = json.load(response)

    if not isinstance(data, list):
        raise ValueError("ProxyScrape response is not a JSON list")

    return data


def is_iranian(item: dict[str, Any]) -> bool:
    country = str(
        item.get("country", "")
    ).strip().casefold()

    country_code = str(
        item.get("country_code", "")
    ).strip().upper()

    return (
        country == "iran"
        or country_code == "IR"
    )


def normalize_host(host: str) -> str | None:
    value = host.strip().strip("[]")

    if not value:
        return None

    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass

    if (
        len(value) <= 253
        and "." in value
        and " " not in value
    ):
        return value.lower()

    return None


def normalize_proxy(
    item: dict[str, Any],
) -> dict[str, Any] | None:
    if not is_iranian(item):
        return None

    protocol = str(
        item.get("protocol", "")
    ).strip().lower()

    if protocol not in SUPPORTED_PROTOCOLS:
        return None

    host = normalize_host(
        str(item.get("ip", ""))
    )

    if host is None:
        return None

    try:
        port = int(item.get("port"))
    except (TypeError, ValueError):
        return None

    if not 1 <= port <= 65535:
        return None

    return {
        "protocol": protocol,
        "host": host,
        "port": port,
        "country": str(item.get("country", "")).strip(),
        "country_code": str(
            item.get("country_code", "")
        ).strip(),
        "city": str(item.get("city", "")).strip(),
        "uptime_percent": item.get(
            "uptime_percent",
            0,
        ),
        "latency_ms": item.get(
            "latency_ms",
            0,
        ),
        "ssl": bool(item.get("ssl", False)),
    }


def number(
    value: Any,
    default: float,
) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def format_host(host: str) -> str:
    try:
        address = ipaddress.ip_address(host)

        if address.version == 6:
            return f"[{host}]"
    except ValueError:
        pass

    return host


def make_outbound(
    proxy: dict[str, Any],
    index: int,
) -> tuple[str, dict[str, Any]]:
    protocol = proxy["protocol"]
    host = proxy["host"]
    port = proxy["port"]

    tag = f"IR-{protocol.upper()}-{index:03d}"

    if protocol == "http":
        outbound = {
            "type": "http",
            "tag": tag,
            "server": host,
            "server_port": port,
        }

    elif protocol == "socks4":
        outbound = {
            "type": "socks",
            "tag": tag,
            "server": host,
            "server_port": port,
            "version": "4",
            "network": "tcp",
        }

    else:
        outbound = {
            "type": "socks",
            "tag": tag,
            "server": host,
            "server_port": port,
            "version": "5",
        }

    return tag, outbound


def build_singbox_config(
    proxies: list[dict[str, Any]],
) -> dict[str, Any]:
    tags: list[str] = []
    proxy_outbounds: list[dict[str, Any]] = []

    for index, proxy in enumerate(proxies, start=1):
        tag, outbound = make_outbound(
            proxy,
            index,
        )

        tags.append(tag)
        proxy_outbounds.append(outbound)

    if not tags:
        raise RuntimeError(
            "No Iranian proxies were found"
        )

    return {
        "log": {
            "level": "info",
            "timestamp": True,
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 2080,
            }
        ],
        "outbounds": [
            {
                "type": "selector",
                "tag": "PROXY",
                "outbounds": [
                    "AUTO",
                    *tags,
                    "DIRECT",
                ],
                "default": "AUTO",
                "interrupt_exist_connections": True,
            },
            {
                "type": "urltest",
                "tag": "AUTO",
                "outbounds": tags,
                "url": (
                    "https://www.gstatic.com/"
                    "generate_204"
                ),
                "interval": "5m",
                "tolerance": 200,
                "interrupt_exist_connections": True,
            },
            *proxy_outbounds,
            {
                "type": "direct",
                "tag": "DIRECT",
            },
        ],
        "route": {
            "final": "PROXY",
            "auto_detect_interface": True,
        },
    }


def build_v2ray_links(
    proxies: list[dict[str, Any]],
) -> list[str]:
    links: list[str] = []

    # Keep SOCKS4 and SOCKS5 for the v2rayN-style feed.
    socks_proxies = [
        proxy
        for proxy in proxies
        if proxy["protocol"] in {
            "socks4",
            "socks5",
        }
    ]

    for index, proxy in enumerate(
        socks_proxies,
        start=1,
    ):
        protocol = proxy["protocol"]
        host = format_host(proxy["host"])
        port = proxy["port"]

        city = proxy["city"] or "Iran"

        name = urllib.parse.quote(
            (
                f"IR-{protocol.upper()}-"
                f"{index:03d}-{city}"
            ),
            safe="",
        )

        links.append(
            f"{protocol}://{host}:{port}#{name}"
        )

    return links


def write_v2ray_subscription(
    links: list[str],
) -> None:
    plain_content = "\n".join(links)

    encoded_content = base64.b64encode(
        plain_content.encode("utf-8")
    ).decode("ascii")

    V2RAY_PLAIN_OUTPUT.write_text(
        plain_content
        + ("\n" if plain_content else ""),
        encoding="utf-8",
    )

    V2RAY_OUTPUT.write_text(
        encoded_content,
        encoding="ascii",
    )


def main() -> None:
    raw_items = download_source()

    unique: dict[
        tuple[str, str, int],
        dict[str, Any],
    ] = {}

    country_matches = 0
    code_matches = 0

    for item in raw_items:
        country = str(
            item.get("country", "")
        ).strip().casefold()

        country_code = str(
            item.get("country_code", "")
        ).strip().upper()

        if country == "iran":
            country_matches += 1

        if country_code == "IR":
            code_matches += 1

        proxy = normalize_proxy(item)

        if proxy is None:
            continue

        key = (
            proxy["protocol"],
            proxy["host"],
            proxy["port"],
        )

        existing = unique.get(key)

        # Keep the duplicate with the better reported uptime.
        if existing is None:
            unique[key] = proxy
        elif number(
            proxy["uptime_percent"],
            0,
        ) > number(
            existing["uptime_percent"],
            0,
        ):
            unique[key] = proxy

    proxies = list(unique.values())

    # Better reported entries appear first.
    proxies.sort(
        key=lambda proxy: (
            -number(
                proxy["uptime_percent"],
                0,
            ),
            number(
                proxy["latency_ms"],
                999999,
            ),
            proxy["protocol"],
            proxy["host"],
            proxy["port"],
        )
    )

    if not proxies:
        raise RuntimeError(
            "No Iranian proxies were found in the global JSON"
        )

    SINGBOX_OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    config = build_singbox_config(proxies)

    SINGBOX_OUTPUT.write_text(
        json.dumps(
            config,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    plain_lines = []

    for proxy in proxies:
        host = format_host(proxy["host"])

        plain_lines.append(
            (
                f"{proxy['protocol']}://"
                f"{host}:{proxy['port']}"
            )
        )

    PLAIN_OUTPUT.write_text(
        "\n".join(plain_lines) + "\n",
        encoding="utf-8",
    )

    v2ray_links = build_v2ray_links(proxies)
    write_v2ray_subscription(v2ray_links)

    counts = {
        protocol: sum(
            proxy["protocol"] == protocol
            for proxy in proxies
        )
        for protocol in sorted(
            SUPPORTED_PROTOCOLS
        )
    }

    print(f"Global records: {len(raw_items)}")
    print(
        "Records matching country=Iran: "
        f"{country_matches}"
    )
    print(
        "Records matching country_code=IR: "
        f"{code_matches}"
    )
    print(
        f"Unique Iranian proxies: {len(proxies)}"
    )
    print(f"Protocol counts: {counts}")
    print(
        "v2rayN SOCKS links: "
        f"{len(v2ray_links)}"
    )


if __name__ == "__main__":
    main()
