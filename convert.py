#!/usr/bin/env python3

import base64
import ipaddress
import json
import re
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

SOURCE_URL = (
    "https://cdn.jsdelivr.net/gh/proxyscrape/"
    "free-proxy-list@main/proxies/countries/ir/data.txt"
)

SINGBOX_OUTPUT = Path("docs/iran-all.json")
PLAIN_OUTPUT = Path("docs/iran-all-plain.txt")

V2RAY_OUTPUT = Path("docs/iran-v2ray.txt")
V2RAY_PLAIN_OUTPUT = Path("docs/iran-v2ray-plain.txt")

SUPPORTED_SCHEMES = {
    "http",
    "https",
    "socks4",
    "socks4a",
    "socks5",
}


def download_source() -> str:
    request = urllib.request.Request(
        SOURCE_URL,
        headers={
            "User-Agent": "IranProxyFeed/6.0",
            "Accept": "text/plain",
        },
    )

    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read().decode(
            "utf-8",
            errors="replace",
        )


def extract_proxy_values(text: str) -> list[str]:
    pattern = re.compile(
        r"(?:https?|socks4a?|socks5)://"
        r"(?:\[[0-9a-fA-F:]+\]|[^ \t\r\n:/#]+)"
        r":\d{1,5}"
        r"(?:#[^ \t\r\n]+)?",
        flags=re.IGNORECASE,
    )

    return pattern.findall(text)


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
        and " " not in value
        and "." in value
    ):
        return value.lower()

    return None


def parse_proxy(value: str) -> dict[str, Any] | None:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None

    scheme = parsed.scheme.lower()

    if scheme not in SUPPORTED_SCHEMES:
        return None

    host = normalize_host(parsed.hostname or "")

    if host is None:
        return None

    try:
        port = parsed.port
    except ValueError:
        return None

    if port is None or not 1 <= port <= 65535:
        return None

    return {
        "scheme": scheme,
        "host": host,
        "port": port,
    }


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
    scheme = proxy["scheme"]
    host = proxy["host"]
    port = proxy["port"]

    tag = f"IR-{scheme.upper()}-{index:03d}"

    if scheme in {"http", "https"}:
        outbound = {
            "type": "http",
            "tag": tag,
            "server": host,
            "server_port": port,
        }

    elif scheme == "socks4":
        outbound = {
            "type": "socks",
            "tag": tag,
            "server": host,
            "server_port": port,
            "version": "4",
            "network": "tcp",
        }

    elif scheme == "socks4a":
        outbound = {
            "type": "socks",
            "tag": tag,
            "server": host,
            "server_port": port,
            "version": "4a",
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
        tag, outbound = make_outbound(proxy, index)
        tags.append(tag)
        proxy_outbounds.append(outbound)

    if not tags:
        raise RuntimeError("No proxies found in source")

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
                "url": "https://www.gstatic.com/generate_204",
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
    """
    v2rayN subscription output.

    HTTP entries are excluded because v2rayN's documented subscription
    protocol list includes SOCKS but not HTTP proxy subscriptions.
    """

    links: list[str] = []

    socks_proxies = [
        proxy
        for proxy in proxies
        if proxy["scheme"] in {
            "socks4",
            "socks4a",
            "socks5",
        }
    ]

    for index, proxy in enumerate(socks_proxies, start=1):
        scheme = proxy["scheme"]
        host = format_host(proxy["host"])
        port = proxy["port"]

        name = urllib.parse.quote(
            f"IR-{scheme.upper()}-{index:03d}",
            safe="",
        )

        links.append(
            f"{scheme}://{host}:{port}#{name}"
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
        plain_content + ("\n" if plain_content else ""),
        encoding="utf-8",
    )

    V2RAY_OUTPUT.write_text(
        encoded_content,
        encoding="ascii",
    )


def main() -> None:
    source_text = download_source()
    raw_values = extract_proxy_values(source_text)

    unique: dict[
        tuple[str, str, int],
        dict[str, Any],
    ] = {}

    for value in raw_values:
        proxy = parse_proxy(value)

        if proxy is None:
            continue

        key = (
            proxy["scheme"],
            proxy["host"],
            proxy["port"],
        )

        unique[key] = proxy

    proxies = list(unique.values())

    proxies.sort(
        key=lambda item: (
            item["scheme"],
            item["host"],
            item["port"],
        )
    )

    if not proxies:
        raise RuntimeError(
            "No valid proxies were found in the source"
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

    plain_lines = [
        (
            f"{proxy['scheme']}://"
            f"{format_host(proxy['host'])}:"
            f"{proxy['port']}"
        )
        for proxy in proxies
    ]

    PLAIN_OUTPUT.write_text(
        "\n".join(plain_lines) + "\n",
        encoding="utf-8",
    )

    v2ray_links = build_v2ray_links(proxies)
    write_v2ray_subscription(v2ray_links)

    counts = {
        scheme: sum(
            proxy["scheme"] == scheme
            for proxy in proxies
        )
        for scheme in sorted(SUPPORTED_SCHEMES)
    }

    print(f"Source entries: {len(raw_values)}")
    print(f"Unique proxies: {len(proxies)}")
    print(f"Protocol counts: {counts}")
    print(f"v2rayN SOCKS nodes: {len(v2ray_links)}")
    print(f"Sing-box config: {SINGBOX_OUTPUT}")
    print(f"v2rayN subscription: {V2RAY_OUTPUT}")


if __name__ == "__main__":
    main()
