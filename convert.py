#!/usr/bin/env python3

import base64
import ipaddress
import urllib.parse
import urllib.request
from pathlib import Path

SOURCES = {
    "http": (
        "https://cdn.jsdelivr.net/gh/proxyscrape/"
        "free-proxy-list@main/proxies/countries/ir/http/data.txt"
    ),
    "https": (
        "https://cdn.jsdelivr.net/gh/proxyscrape/"
        "free-proxy-list@main/proxies/countries/ir/https/data.txt"
    ),
    "socks4": (
        "https://cdn.jsdelivr.net/gh/proxyscrape/"
        "free-proxy-list@main/proxies/countries/ir/socks4/data.txt"
    ),
}

OUTPUT_DIRECTORY = Path("docs")


def download_text(url: str) -> str:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "IranProxyFeed/4.0",
            "Accept": "text/plain",
        },
    )

    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read().decode("utf-8", errors="replace")


def parse_proxy_line(line: str) -> tuple[str, int] | None:
    value = line.strip()

    if not value or value.startswith("#"):
        return None

    # Also tolerate source lines that already contain a scheme.
    if "://" in value:
        value = value.split("://", 1)[1]

    # Remove an existing fragment or path.
    value = value.split("#", 1)[0]
    value = value.split("/", 1)[0]

    try:
        host, port_text = value.rsplit(":", 1)
        port = int(port_text)
    except (ValueError, TypeError):
        return None

    host = host.strip().strip("[]")

    if not 1 <= port <= 65535:
        return None

    try:
        ipaddress.ip_address(host)
    except ValueError:
        # Keep valid-looking domain names too.
        if not host or " " in host:
            return None

    return host, port


def read_source(source_name: str) -> list[tuple[str, int]]:
    text = download_text(SOURCES[source_name])

    unique: dict[tuple[str, int], None] = {}

    for line in text.splitlines():
        parsed = parse_proxy_line(line)

        if parsed is not None:
            unique[parsed] = None

    return list(unique.keys())


def format_host(host: str) -> str:
    try:
        address = ipaddress.ip_address(host)

        if address.version == 6:
            return f"[{host}]"
    except ValueError:
        pass

    return host


def build_links(
    proxies: list[tuple[str, int]],
    source_type: str,
) -> list[str]:
    links: list[str] = []

    for index, (host, port) in enumerate(proxies, start=1):
        label = urllib.parse.quote(
            f"IR-{source_type.upper()}-{index:03d}",
            safe="",
        )

        formatted_host = format_host(host)

        if source_type == "socks4":
            scheme = "socks4"
        else:
            # Both ProxyScrape HTTP and HTTPS proxy lists are HTTP proxy
            # servers. HTTPS means they support HTTPS CONNECT tunnelling.
            scheme = "http"

        link = (
            f"{scheme}://{formatted_host}:{port}"
            f"#{label}"
        )

        links.append(link)

    return links


def write_subscription(
    filename: str,
    links: list[str],
) -> None:
    plain_content = "\n".join(links)

    encoded_content = base64.b64encode(
        plain_content.encode("utf-8")
    ).decode("ascii")

    output_path = OUTPUT_DIRECTORY / filename
    output_path.write_text(
        encoded_content,
        encoding="ascii",
    )

    debug_path = OUTPUT_DIRECTORY / filename.replace(
        ".txt",
        "-plain.txt",
    )
    debug_path.write_text(
        plain_content + ("\n" if plain_content else ""),
        encoding="utf-8",
    )


def main() -> None:
    OUTPUT_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    http_proxies = read_source("http")
    https_proxies = read_source("https")
    socks4_proxies = read_source("socks4")

    http_links = build_links(
        http_proxies,
        "http",
    )

    https_links = build_links(
        https_proxies,
        "https",
    )

    socks4_links = build_links(
        socks4_proxies,
        "socks4",
    )

    # Deduplicate the combined feed while preserving order.
    all_links = list(
        dict.fromkeys(
            http_links
            + https_links
            + socks4_links
        )
    )

    write_subscription(
        "iran-http.txt",
        http_links,
    )

    write_subscription(
        "iran-https.txt",
        https_links,
    )

    write_subscription(
        "iran-socks4.txt",
        socks4_links,
    )

    write_subscription(
        "iran-all.txt",
        all_links,
    )

    print(f"HTTP proxies: {len(http_links)}")
    print(f"HTTPS proxies: {len(https_links)}")
    print(f"SOCKS4 proxies: {len(socks4_links)}")
    print(f"Combined unique links: {len(all_links)}")


if __name__ == "__main__":
    main()
