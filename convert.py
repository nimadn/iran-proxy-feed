#!/usr/bin/env python3

import ipaddress
import json
import re
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

SOURCE_URL = (
    "https://cdn.jsdelivr.net/gh/proxyscrape/"
    "free-proxy-list@main/proxies/countries/ir/data.txt"
)

OUTPUT_FILE = Path("docs/iran-all.json")
PLAIN_FILE = Path("docs/iran-all-plain.txt")

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
            "User-Agent": "IranProxyFeed/5.0",
            "Accept": "text/plain",
        },
    )

    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read().decode(
            "utf-8",
            errors="replace",
        )


def extract_proxy_values(text: str) -> list[str]:
    """
    Supports both newline-separated and whitespace-separated sources.
    """

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

    # Permit a conventional hostname if one appears in the source.
    if (
        len(value) <= 253
        and " " not in value
        and "." in value
    ):
        return value.lower()

    return None


def parse_proxy(
    value: str,
) -> dict[str, Any] | None:
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


def make_outbound(
    proxy: dict[str, Any],
    index: int,
) -> tuple[str, dict[str, Any]]:
    scheme = proxy["scheme"]
    host = proxy["host"]
    port = proxy["port"]

    tag = f"IR-{scheme.upper()}-{index:03d}"

    if scheme in {"http", "https"}:
        # ProxyScrape's HTTPS entries generally identify HTTP proxies
        # capable of HTTPS CONNECT, not necessarily TLS-wrapped proxy
        # servers. Therefore both are represented as HTTP outbounds.
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


def build_config(
    proxies: list[dict[str, Any]],
) -> dict[str, Any]:
    tags: list[str] = []
    outbounds: list[dict[str, Any]] = []

    for index, proxy in enumerate(proxies, start=1):
        tag, outbound = make_outbound(proxy, index)
        tags.append(tag)
        outbounds.append(outbound)

    selector_members = ["AUTO", *tags, "DIRECT"]

    config: dict[str, Any] = {
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
                "outbounds": selector_members,
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
            *outbounds,
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

    return config


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

    config = build_config(proxies)

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUTPUT_FILE.write_text(
        json.dumps(
            config,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    plain_lines = [
        f"{proxy['scheme']}://"
        f"{proxy['host']}:{proxy['port']}"
        for proxy in proxies
    ]

    PLAIN_FILE.write_text(
        "\n".join(plain_lines)
        + ("\n" if plain_lines else ""),
        encoding="utf-8",
    )

    counts = {
        scheme: sum(
            proxy["scheme"] == scheme
            for proxy in proxies
        )
        for scheme in sorted(SUPPORTED_SCHEMES)
    }

    print(f"Source entries found: {len(raw_values)}")
    print(f"Unique valid proxies: {len(proxies)}")
    print(f"Protocol counts: {counts}")
    print(f"Config written to: {OUTPUT_FILE}")
    print(f"Plain list written to: {PLAIN_FILE}")

    if not proxies:
        raise RuntimeError(
            "No valid proxies were found in the source."
        )


if __name__ == "__main__":
    main()
