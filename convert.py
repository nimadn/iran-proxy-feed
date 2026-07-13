#!/usr/bin/env python3

import base64
import json
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

SOURCE_URL = (
    "https://cdn.jsdelivr.net/gh/"
    "proxyscrape/free-proxy-list@main/proxies/all/data.json"
)

OUTPUT_BASE64 = Path("docs/iran-proxies.txt")
OUTPUT_PLAIN = Path("docs/iran-proxies-plain.txt")

SUPPORTED_PROTOCOLS = {"http", "socks4", "socks5"}


def download_proxy_data() -> list[dict[str, Any]]:
    request = urllib.request.Request(
        SOURCE_URL,
        headers={
            "User-Agent": "IranProxyFeed/3.0",
            "Accept": "application/json",
        },
    )

    with urllib.request.urlopen(request, timeout=60) as response:
        data = json.load(response)

    if not isinstance(data, list):
        raise ValueError("Proxy source is not a JSON list")

    return data


def is_iranian(item: dict[str, Any]) -> bool:
    country_code = str(
        item.get("country_code", "")
    ).strip().upper()

    country = str(
        item.get("country", "")
    ).strip().lower()

    city = str(
        item.get("city", "")
    ).strip().lower()

    return (
        country_code == "IR"
        or country == "iran"
        or "iran" in country
        or city == "tehran"
        or "tehran" in city
    )


def normalize_proxy(
    item: dict[str, Any],
) -> dict[str, Any] | None:
    protocol = str(
        item.get("protocol", "")
    ).strip().lower()

    ip = str(
        item.get("ip", "")
    ).strip()

    try:
        port = int(item.get("port"))
    except (TypeError, ValueError):
        return None

    if not is_iranian(item):
        return None

    if protocol not in SUPPORTED_PROTOCOLS:
        return None

    if not ip:
        return None

    if not 1 <= port <= 65535:
        return None

    return {
        "protocol": protocol,
        "ip": ip,
        "port": port,
        "city": str(item.get("city", "")).strip(),
        "country": str(item.get("country", "")).strip(),
    }


def build_proxy_link(
    proxy: dict[str, Any],
    number: int,
) -> str:
    protocol = proxy["protocol"]
    ip = proxy["ip"]
    port = proxy["port"]

    city = proxy["city"] or "Iran"

    name = (
        f"IR-{protocol.upper()}-"
        f"{number:03d}-{city}"
    )

    encoded_name = urllib.parse.quote(
        name,
        safe="",
    )

    # Use conventional URI schemes.
    if protocol == "http":
        return (
            f"http://{ip}:{port}"
            f"#{encoded_name}"
        )

    if protocol == "socks5":
        return (
            f"socks5://{ip}:{port}"
            f"#{encoded_name}"
        )

    return (
        f"socks4://{ip}:{port}"
        f"#{encoded_name}"
    )


def main() -> None:
    raw_items = download_proxy_data()

    unique: dict[
        tuple[str, str, int],
        dict[str, Any],
    ] = {}

    for item in raw_items:
        proxy = normalize_proxy(item)

        if proxy is None:
            continue

        key = (
            proxy["protocol"],
            proxy["ip"],
            proxy["port"],
        )

        unique[key] = proxy

    proxies = list(unique.values())

    proxies.sort(
        key=lambda proxy: (
            proxy["protocol"],
            proxy["ip"],
            proxy["port"],
        )
    )

    links = [
        build_proxy_link(proxy, number)
        for number, proxy in enumerate(
            proxies,
            start=1,
        )
    ]

    plain_subscription = "\n".join(links)

    encoded_subscription = base64.b64encode(
        plain_subscription.encode("utf-8")
    ).decode("ascii")

    OUTPUT_BASE64.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUTPUT_PLAIN.write_text(
        plain_subscription + "\n",
        encoding="utf-8",
    )

    OUTPUT_BASE64.write_text(
        encoded_subscription,
        encoding="ascii",
    )

    counts = {
        protocol: sum(
            proxy["protocol"] == protocol
            for proxy in proxies
        )
        for protocol in sorted(SUPPORTED_PROTOCOLS)
    }

    print(f"Total Iranian proxies: {len(proxies)}")
    print(f"Protocol counts: {counts}")
    print(f"Base64 subscription: {OUTPUT_BASE64}")
    print(f"Plain list: {OUTPUT_PLAIN}")


if __name__ == "__main__":
    main()
