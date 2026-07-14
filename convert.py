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

DOCS_DIR = Path("docs")

SINGBOX_OUTPUT = DOCS_DIR / "iran-all.json"
PLAIN_OUTPUT = DOCS_DIR / "iran-all-plain.txt"

MIXED_SUB_OUTPUT = DOCS_DIR / "iran-v2ray.txt"
MIXED_SUB_PLAIN_OUTPUT = DOCS_DIR / "iran-v2ray-plain.txt"

REPORT_OUTPUT = DOCS_DIR / "iran-report.json"

SUPPORTED_PROTOCOLS = {
    "http",
    "https",
    "socks4",
    "socks4a",
    "socks5",
}


def download_source() -> list[dict[str, Any]]:
    request = urllib.request.Request(
        SOURCE_URL,
        headers={
            "User-Agent": "IranProxyFeed/10.0",
            "Accept": "application/json",
            "Cache-Control": "no-cache",
        },
    )

    with urllib.request.urlopen(
        request,
        timeout=120,
    ) as response:
        data = json.load(response)

    if not isinstance(data, list):
        raise ValueError(
            "ProxyScrape response is not a JSON array"
        )

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


def normalize_protocol(value: Any) -> str:
    protocol = str(value or "").strip().lower()

    aliases = {
        "sock4": "socks4",
        "sock5": "socks5",
        "socks": "socks5",
    }

    return aliases.get(protocol, protocol)


def normalize_host(value: Any) -> str | None:
    host = str(value or "").strip().strip("[]")

    if not host:
        return None

    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    if (
        len(host) <= 253
        and "." in host
        and " " not in host
        and "/" not in host
    ):
        return host.lower()

    return None


def normalize_proxy(
    item: dict[str, Any],
) -> dict[str, Any] | None:
    if not is_iranian(item):
        return None

    protocol = normalize_protocol(
        item.get("protocol")
    )

    if protocol not in SUPPORTED_PROTOCOLS:
        return None

    host = normalize_host(
        item.get("ip")
        or item.get("host")
        or item.get("server")
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
        "country": str(
            item.get("country", "")
        ).strip(),
        "country_code": str(
            item.get("country_code", "")
        ).strip(),
        "city": str(
            item.get("city", "")
        ).strip(),
        "uptime_percent": to_float(
            item.get("uptime_percent"),
            0,
        ),
        "latency_ms": to_float(
            item.get("latency_ms"),
            999999,
        ),
        "ssl": bool(
            item.get("ssl", False)
        ),
        "anonymity": str(
            item.get("anonymity", "")
        ).strip(),
    }


def to_float(
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


def make_tag(
    proxy: dict[str, Any],
    index: int,
) -> str:
    protocol = proxy["protocol"].upper()
    city = proxy["city"] or "Iran"

    safe_city = "".join(
        character
        if character.isalnum()
        else "-"
        for character in city
    ).strip("-")

    safe_city = safe_city or "Iran"

    return (
        f"IR-{protocol}-"
        f"{index:03d}-{safe_city}"
    )


def make_singbox_outbound(
    proxy: dict[str, Any],
    index: int,
) -> tuple[str, dict[str, Any]]:
    protocol = proxy["protocol"]
    host = proxy["host"]
    port = proxy["port"]

    tag = make_tag(proxy, index)

    if protocol in {"http", "https"}:
        outbound: dict[str, Any] = {
            "type": "http",
            "tag": tag,
            "server": host,
            "server_port": port,
        }

        # ProxyScrape "https" commonly means an HTTP proxy
        # capable of HTTPS CONNECT. It does not always mean
        # that the proxy endpoint itself uses TLS.
        #
        # Therefore no TLS block is added here.

    elif protocol == "socks4":
        outbound = {
            "type": "socks",
            "tag": tag,
            "server": host,
            "server_port": port,
            "version": "4",
            "network": "tcp",
        }

    elif protocol == "socks4a":
        outbound = {
            "type": "socks",
            "tag": tag,
            "server": host,
            "server_port": port,
            "version": "4a",
            "network": "tcp",
        }

    elif protocol == "socks5":
        outbound = {
            "type": "socks",
            "tag": tag,
            "server": host,
            "server_port": port,
            "version": "5",
        }

    else:
        raise ValueError(
            f"Unsupported protocol: {protocol}"
        )

    return tag, outbound


def build_singbox_config(
    proxies: list[dict[str, Any]],
) -> dict[str, Any]:
    tags: list[str] = []
    outbounds: list[dict[str, Any]] = []

    for index, proxy in enumerate(
        proxies,
        start=1,
    ):
        tag, outbound = make_singbox_outbound(
            proxy,
            index,
        )

        tags.append(tag)
        outbounds.append(outbound)

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


def build_share_link(
    proxy: dict[str, Any],
    index: int,
) -> str:
    protocol = proxy["protocol"]
    host = format_host(proxy["host"])
    port = proxy["port"]

    tag = make_tag(proxy, index)

    encoded_tag = urllib.parse.quote(
        tag,
        safe="",
    )

    if protocol in {"http", "https"}:
        # HTTPS-classified ProxyScrape records are exposed
        # as HTTP proxy share links because the classification
        # usually means CONNECT support.
        scheme = "http"

    elif protocol == "socks4":
        scheme = "socks4"

    elif protocol == "socks4a":
        scheme = "socks4a"

    elif protocol == "socks5":
        scheme = "socks5"

    else:
        raise ValueError(
            f"Unsupported protocol: {protocol}"
        )

    return (
        f"{scheme}://{host}:{port}"
        f"#{encoded_tag}"
    )


def write_text(
    path: Path,
    content: str,
) -> None:
    path.write_text(
        content,
        encoding="utf-8",
    )


def count_protocols(
    proxies: list[dict[str, Any]],
) -> dict[str, int]:
    counts = {
        protocol: 0
        for protocol in sorted(
            SUPPORTED_PROTOCOLS
        )
    }

    for proxy in proxies:
        protocol = proxy["protocol"]

        counts[protocol] = (
            counts.get(protocol, 0) + 1
        )

    return counts


def main() -> None:
    DOCS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    raw_items = download_source()

    raw_iranian_items = [
        item
        for item in raw_items
        if is_iranian(item)
    ]

    normalized_records: list[
        dict[str, Any]
    ] = []

    rejected_records = 0

    for item in raw_iranian_items:
        proxy = normalize_proxy(item)

        if proxy is None:
            rejected_records += 1
            continue

        normalized_records.append(proxy)

    # Deduplicate only exact protocol + host + port duplicates.
    unique: dict[
        tuple[str, str, int],
        dict[str, Any],
    ] = {}

    duplicate_records = 0

    for proxy in normalized_records:
        key = (
            proxy["protocol"],
            proxy["host"],
            proxy["port"],
        )

        existing = unique.get(key)

        if existing is None:
            unique[key] = proxy
            continue

        duplicate_records += 1

        # Keep the duplicate record with the higher reported uptime.
        if (
            proxy["uptime_percent"]
            > existing["uptime_percent"]
        ):
            unique[key] = proxy

    proxies = list(unique.values())

    proxies.sort(
        key=lambda proxy: (
            -proxy["uptime_percent"],
            proxy["latency_ms"],
            proxy["protocol"],
            proxy["host"],
            proxy["port"],
        )
    )

    if not proxies:
        raise RuntimeError(
            "No valid Iranian proxies were found"
        )

    singbox_config = build_singbox_config(
        proxies
    )

    SINGBOX_OUTPUT.write_text(
        json.dumps(
            singbox_config,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    share_links = [
        build_share_link(
            proxy,
            index,
        )
        for index, proxy in enumerate(
            proxies,
            start=1,
        )
    ]

    plain_content = "\n".join(
        share_links
    ) + "\n"

    write_text(
        PLAIN_OUTPUT,
        plain_content,
    )

    write_text(
        MIXED_SUB_PLAIN_OUTPUT,
        plain_content,
    )

    base64_content = base64.b64encode(
        plain_content.encode("utf-8")
    ).decode("ascii")

    write_text(
        MIXED_SUB_OUTPUT,
        base64_content,
    )

    raw_protocol_counts: dict[str, int] = {}

    for item in raw_iranian_items:
        protocol = normalize_protocol(
            item.get("protocol")
        )

        raw_protocol_counts[protocol] = (
            raw_protocol_counts.get(
                protocol,
                0,
            )
            + 1
        )

    report = {
        "source_url": SOURCE_URL,
        "global_records": len(raw_items),
        "raw_iranian_records": len(
            raw_iranian_items
        ),
        "raw_iranian_protocol_counts": (
            raw_protocol_counts
        ),
        "normalized_records": len(
            normalized_records
        ),
        "rejected_records": rejected_records,
        "duplicate_records_removed": (
            duplicate_records
        ),
        "published_unique_proxies": len(
            proxies
        ),
        "published_protocol_counts": (
            count_protocols(proxies)
        ),
        "subscription_links_written": len(
            share_links
        ),
        "filter": {
            "country": "Iran",
            "country_code": "IR",
            "operator": "OR",
        },
    }

    REPORT_OUTPUT.write_text(
        json.dumps(
            report,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    print(
        json.dumps(
            report,
            indent=2,
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
