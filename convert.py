#!/usr/bin/env python3

import base64
import concurrent.futures
import ipaddress
import json
import socket
import subprocess
import urllib.parse
import urllib.request

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


SOURCE_URL = (
    "https://raw.githubusercontent.com/"
    "ProxyScrape/free-proxy-list/main/"
    "proxies/all/data.json"
)

DOCS_DIR = Path("docs")

HISTORY_FILE = DOCS_DIR / "proxy-history.json"
REPORT_FILE = DOCS_DIR / "iran-report.json"

SINGBOX_OUTPUT = DOCS_DIR / "iran-all.json"
PLAIN_OUTPUT = DOCS_DIR / "iran-all-plain.txt"

SUB_OUTPUT = DOCS_DIR / "iran-v2ray.txt"
SUB_PLAIN_OUTPUT = DOCS_DIR / "iran-v2ray-plain.txt"

SUPPORTED_PROTOCOLS = {
    "http",
    "socks4",
    "socks5",
}

RETENTION_DAYS = 30

TCP_TIMEOUT_SECONDS = 4
PROXY_TIMEOUT_SECONDS = 10
TEST_WORKERS = 20

TEST_URLS = [
    "https://www.isna.ir/",
    "https://www.gstatic.com/generate_204",
]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_time(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat()


def parse_time(value: Any) -> datetime | None:
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(str(value))

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    except ValueError:
        return None


def download_source() -> list[dict[str, Any]]:
    request = urllib.request.Request(
        SOURCE_URL,
        headers={
            "User-Agent": "IranProxyFeed/12.0",
            "Accept": "application/json",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
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


def to_float(
    value: Any,
    default: float,
) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


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
    }


def proxy_key(proxy: dict[str, Any]) -> str:
    return (
        f"{proxy['protocol']}://"
        f"{proxy['host']}:{proxy['port']}"
    )


def load_history() -> dict[str, dict[str, Any]]:
    if not HISTORY_FILE.exists():
        return {}

    try:
        data = json.loads(
            HISTORY_FILE.read_text(
                encoding="utf-8"
            )
        )
    except (json.JSONDecodeError, OSError):
        return {}

    if not isinstance(data, dict):
        return {}

    return {
        str(key): value
        for key, value in data.items()
        if isinstance(value, dict)
    }


def tcp_test(proxy: dict[str, Any]) -> bool:
    try:
        with socket.create_connection(
            (
                proxy["host"],
                proxy["port"],
            ),
            timeout=TCP_TIMEOUT_SECONDS,
        ):
            return True
    except OSError:
        return False


def curl_proxy_url(
    proxy: dict[str, Any],
) -> str:
    protocol = proxy["protocol"]

    if protocol == "socks5":
        protocol = "socks5h"

    return (
        f"{protocol}://"
        f"{proxy['host']}:{proxy['port']}"
    )


def test_proxy(
    proxy: dict[str, Any],
) -> dict[str, Any]:
    result = {
        "working": False,
        "tcp_open": False,
        "tested_url": None,
        "http_code": None,
        "measured_seconds": None,
    }

    if not tcp_test(proxy):
        return result

    result["tcp_open"] = True

    for test_url in TEST_URLS:
        command = [
            "curl",
            "--silent",
            "--show-error",
            "--location",
            "--output",
            "/dev/null",
            "--proxy",
            curl_proxy_url(proxy),
            "--connect-timeout",
            str(PROXY_TIMEOUT_SECONDS),
            "--max-time",
            str(PROXY_TIMEOUT_SECONDS),
            "--write-out",
            "%{http_code} %{time_total}",
            test_url,
        ]

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=PROXY_TIMEOUT_SECONDS + 3,
                check=False,
            )
        except (
            subprocess.TimeoutExpired,
            OSError,
        ):
            continue

        if completed.returncode != 0:
            continue

        parts = completed.stdout.strip().split()

        if len(parts) != 2:
            continue

        code_text, time_text = parts

        try:
            code = int(code_text)
            measured_seconds = float(time_text)
        except ValueError:
            continue

        # Accept normal success and redirect responses.
        if 200 <= code < 400:
            result.update(
                {
                    "working": True,
                    "tested_url": test_url,
                    "http_code": code,
                    "measured_seconds": (
                        measured_seconds
                    ),
                }
            )

            return result

    return result


def merge_current_source(
    history: dict[str, dict[str, Any]],
    source_proxies: list[dict[str, Any]],
    now: datetime,
) -> None:
    for proxy in source_proxies:
        key = proxy_key(proxy)

        existing = history.get(key, {})

        history[key] = {
            **existing,
            **proxy,
            "first_seen": existing.get(
                "first_seen",
                iso_time(now),
            ),
            "last_seen_in_source": iso_time(now),
            "currently_in_source": True,
        }

    current_keys = {
        proxy_key(proxy)
        for proxy in source_proxies
    }

    for key, record in history.items():
        if key not in current_keys:
            record["currently_in_source"] = False


def select_test_candidates(
    history: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    candidates = []

    for record in history.values():
        if (
            record.get("protocol")
            not in SUPPORTED_PROTOCOLS
        ):
            continue

        if not record.get("host"):
            continue

        if not record.get("port"):
            continue

        candidates.append(record)

    return candidates


def update_test_results(
    history: dict[str, dict[str, Any]],
    candidates: list[dict[str, Any]],
    now: datetime,
) -> None:
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=TEST_WORKERS
    ) as executor:
        future_map = {
            executor.submit(
                test_proxy,
                proxy,
            ): proxy
            for proxy in candidates
        }

        for future in concurrent.futures.as_completed(
            future_map
        ):
            proxy = future_map[future]
            key = proxy_key(proxy)

            try:
                test_result = future.result()
            except Exception as error:
                test_result = {
                    "working": False,
                    "error": str(error),
                }

            record = history[key]

            record["last_tested"] = iso_time(now)
            record["last_test_result"] = (
                test_result
            )

            if test_result.get("working"):
                record["last_success"] = iso_time(
                    now
                )

                success_count = int(
                    record.get(
                        "success_count",
                        0,
                    )
                )

                record["success_count"] = (
                    success_count + 1
                )
            else:
                failure_count = int(
                    record.get(
                        "failure_count",
                        0,
                    )
                )

                record["failure_count"] = (
                    failure_count + 1
                )


def remove_expired(
    history: dict[str, dict[str, Any]],
    now: datetime,
) -> int:
    cutoff = now - timedelta(
        days=RETENTION_DAYS
    )

    expired_keys = []

    for key, record in history.items():
        last_success = parse_time(
            record.get("last_success")
        )

        currently_in_source = bool(
            record.get(
                "currently_in_source",
                False,
            )
        )

        # Current source records remain in history even if
        # they have not passed a test yet.
        if currently_in_source:
            continue

        # Disappeared proxies are retained only when they
        # succeeded within the retention period.
        if (
            last_success is None
            or last_success < cutoff
        ):
            expired_keys.append(key)

    for key in expired_keys:
        del history[key]

    return len(expired_keys)


def select_published_proxies(
    history: dict[str, dict[str, Any]],
    now: datetime,
) -> list[dict[str, Any]]:
    cutoff = now - timedelta(
        days=RETENTION_DAYS
    )

    published = []

    for record in history.values():
        last_success = parse_time(
            record.get("last_success")
        )

        currently_in_source = bool(
            record.get(
                "currently_in_source",
                False,
            )
        )

        # Publish current source entries immediately.
        # Also publish old entries that worked within 30 days.
        keep = (
            currently_in_source
            or (
                last_success is not None
                and last_success >= cutoff
            )
        )

        if keep:
            published.append(record)

    published.sort(
        key=lambda proxy: (
            0
            if proxy.get("last_test_result", {}).get(
                "working"
            )
            else 1,
            -to_float(
                proxy.get("uptime_percent"),
                0,
            ),
            to_float(
                proxy.get("latency_ms"),
                999999,
            ),
            proxy["protocol"],
            proxy["host"],
            proxy["port"],
        )
    )

    return published


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
    city = proxy.get("city") or "Iran"

    safe_city = "".join(
        character
        if character.isalnum()
        else "-"
        for character in city
    ).strip("-")

    return (
        f"IR-{proxy['protocol'].upper()}-"
        f"{index:03d}-{safe_city or 'Iran'}"
    )


def make_outbound(
    proxy: dict[str, Any],
    index: int,
) -> tuple[str, dict[str, Any]]:
    protocol = proxy["protocol"]
    tag = make_tag(proxy, index)

    if protocol == "http":
        outbound = {
            "type": "http",
            "tag": tag,
            "server": proxy["host"],
            "server_port": proxy["port"],
        }

    elif protocol == "socks4":
        outbound = {
            "type": "socks",
            "tag": tag,
            "server": proxy["host"],
            "server_port": proxy["port"],
            "version": "4",
            "network": "tcp",
        }

    else:
        outbound = {
            "type": "socks",
            "tag": tag,
            "server": proxy["host"],
            "server_port": proxy["port"],
            "version": "5",
        }

    return tag, outbound


def build_singbox_config(
    proxies: list[dict[str, Any]],
) -> dict[str, Any]:
    tags = []
    outbounds = []

    for index, proxy in enumerate(
        proxies,
        start=1,
    ):
        tag, outbound = make_outbound(
            proxy,
            index,
        )

        tags.append(tag)
        outbounds.append(outbound)

    if not tags:
        raise RuntimeError(
            "No proxies are available for publication"
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
            },
            {
                "type": "urltest",
                "tag": "AUTO",
                "outbounds": tags,
                "url": (
                    "https://www.gstatic.com/"
                    "generate_204"
                ),
                "interval": "10m",
                "tolerance": 200,
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
    host = format_host(proxy["host"])

    tag = urllib.parse.quote(
        make_tag(proxy, index),
        safe="",
    )

    return (
        f"{proxy['protocol']}://"
        f"{host}:{proxy['port']}#{tag}"
    )


def main() -> None:
    DOCS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    now = utc_now()

    raw_items = download_source()

    source_proxies = []

    for item in raw_items:
        proxy = normalize_proxy(item)

        if proxy is not None:
            source_proxies.append(proxy)

    # Remove only exact duplicate protocol/IP/port entries.
    unique_source = {}

    for proxy in source_proxies:
        unique_source[
            proxy_key(proxy)
        ] = proxy

    source_proxies = list(
        unique_source.values()
    )

    history = load_history()

    merge_current_source(
        history,
        source_proxies,
        now,
    )

    candidates = select_test_candidates(
        history
    )

    update_test_results(
        history,
        candidates,
        now,
    )

    expired_removed = remove_expired(
        history,
        now,
    )

    published = select_published_proxies(
        history,
        now,
    )

    HISTORY_FILE.write_text(
        json.dumps(
            history,
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    config = build_singbox_config(
        published
    )

    SINGBOX_OUTPUT.write_text(
        json.dumps(
            config,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    links = [
        build_share_link(
            proxy,
            index,
        )
        for index, proxy in enumerate(
            published,
            start=1,
        )
    ]

    plain_content = "\n".join(
        links
    ) + "\n"

    PLAIN_OUTPUT.write_text(
        plain_content,
        encoding="utf-8",
    )

    SUB_PLAIN_OUTPUT.write_text(
        plain_content,
        encoding="utf-8",
    )

    SUB_OUTPUT.write_text(
        base64.b64encode(
            plain_content.encode("utf-8")
        ).decode("ascii"),
        encoding="ascii",
    )

    working_now = sum(
        bool(
            proxy.get(
                "last_test_result",
                {},
            ).get("working")
        )
        for proxy in published
    )

    retained_from_history = sum(
        not proxy.get(
            "currently_in_source",
            False,
        )
        for proxy in published
    )

    protocol_counts = {}

    for proxy in published:
        protocol = proxy["protocol"]

        protocol_counts[protocol] = (
            protocol_counts.get(
                protocol,
                0,
            )
            + 1
        )

    report = {
        "generated_at": iso_time(now),
        "source_url": SOURCE_URL,
        "global_records": len(raw_items),
        "current_iranian_unique_records": len(
            source_proxies
        ),
        "history_records": len(history),
        "tested_records": len(candidates),
        "working_now": working_now,
        "retained_from_history": (
            retained_from_history
        ),
        "expired_records_removed": (
            expired_removed
        ),
        "retention_days": RETENTION_DAYS,
        "published_proxies": len(
            published
        ),
        "published_protocol_counts": (
            protocol_counts
        ),
        "test_urls": TEST_URLS,
    }

    REPORT_FILE.write_text(
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
