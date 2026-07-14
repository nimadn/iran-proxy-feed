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
TEST_RESULTS_FILE = DOCS_DIR / "iran-test-results.json"

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
REQUEST_TIMEOUT_SECONDS = 12
TEST_WORKERS = 20

TEST_URLS = [
    {
        "name": "ISNA",
        "url": "https://www.isna.ir/",
        "accepted_codes": range(200, 400),
    },
    {
        "name": "Google",
        "url": "https://www.gstatic.com/generate_204",
        "accepted_codes": {204},
    },
]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_time(value: datetime) -> str:
    return value.replace(
        microsecond=0
    ).isoformat()


def parse_time(value: Any) -> datetime | None:
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(
            str(value)
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

        return parsed.astimezone(
            timezone.utc
        )

    except ValueError:
        return None


def to_float(
    value: Any,
    default: float,
) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def download_source() -> list[dict[str, Any]]:
    request = urllib.request.Request(
        SOURCE_URL,
        headers={
            "User-Agent": "IranProxyFeed/15.0",
            "Accept": "application/json",
            "Cache-Control": "no-cache, no-store",
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
    protocol = str(
        value or ""
    ).strip().lower()

    aliases = {
        "sock4": "socks4",
        "sock5": "socks5",
        "socks": "socks5",
    }

    return aliases.get(
        protocol,
        protocol,
    )


def normalize_host(value: Any) -> str | None:
    host = str(
        value or ""
    ).strip().strip("[]")

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
        "anonymity": str(
            item.get("anonymity", "")
        ).strip(),
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
    except (
        json.JSONDecodeError,
        OSError,
    ):
        return {}

    if not isinstance(data, dict):
        return {}

    return {
        str(key): value
        for key, value in data.items()
        if isinstance(value, dict)
    }


def tcp_test(
    proxy: dict[str, Any],
) -> dict[str, Any]:
    started = datetime.now(
        timezone.utc
    )

    try:
        with socket.create_connection(
            (
                proxy["host"],
                int(proxy["port"]),
            ),
            timeout=TCP_TIMEOUT_SECONDS,
        ):
            elapsed = (
                datetime.now(timezone.utc)
                - started
            ).total_seconds()

            return {
                "success": True,
                "seconds": round(
                    elapsed,
                    3,
                ),
            }

    except OSError as error:
        return {
            "success": False,
            "error": str(error),
        }


def curl_proxy_url(
    proxy: dict[str, Any],
) -> str:
    protocol = proxy["protocol"]

    if protocol == "socks5":
        # Let the proxy resolve domain names.
        protocol = "socks5h"

    return (
        f"{protocol}://"
        f"{proxy['host']}:{proxy['port']}"
    )


def test_one_url(
    proxy: dict[str, Any],
    test_definition: dict[str, Any],
) -> dict[str, Any]:
    url = test_definition["url"]
    proxy_url = curl_proxy_url(proxy)

    command = [
        "curl",
        "--silent",
        "--show-error",
        "--location",
        "--output",
        "/dev/null",
        "--proxy",
        proxy_url,
        "--connect-timeout",
        str(REQUEST_TIMEOUT_SECONDS),
        "--max-time",
        str(REQUEST_TIMEOUT_SECONDS),
        "--write-out",
        (
            "%{http_code}|"
            "%{time_total}|"
            "%{remote_ip}|"
            "%{url_effective}"
        ),
        url,
    ]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=REQUEST_TIMEOUT_SECONDS + 4,
            check=False,
        )
    except (
        subprocess.TimeoutExpired,
        OSError,
    ) as error:
        return {
            "name": test_definition["name"],
            "url": url,
            "success": False,
            "proxy_argument": proxy_url,
            "error": str(error),
        }

    output = completed.stdout.strip()
    parts = output.split("|", 3)

    result: dict[str, Any] = {
        "name": test_definition["name"],
        "url": url,
        "success": False,
        "proxy_argument": proxy_url,
        "curl_returncode": completed.returncode,
    }

    if completed.stderr.strip():
        result["stderr"] = (
            completed.stderr.strip()
        )

    if (
        completed.returncode != 0
        or len(parts) != 4
    ):
        result["raw_output"] = output
        return result

    code_text = parts[0]
    time_text = parts[1]
    remote_ip = parts[2]
    effective_url = parts[3]

    try:
        http_code = int(code_text)
        measured_seconds = float(
            time_text
        )
    except ValueError:
        result["raw_output"] = output
        return result

    accepted_codes = test_definition[
        "accepted_codes"
    ]

    result.update(
        {
            "http_code": http_code,
            "measured_seconds": round(
                measured_seconds,
                3,
            ),
            "remote_ip": remote_ip,
            "effective_url": effective_url,
            "success": (
                http_code in accepted_codes
            ),
        }
    )

    return result


def test_proxy(
    proxy: dict[str, Any],
) -> dict[str, Any]:
    tcp_result = tcp_test(proxy)

    result: dict[str, Any] = {
        "working": False,
        "passed_all_tests": False,
        "proxy": proxy_key(proxy),
        "tested_at": iso_time(
            utc_now()
        ),
        "tcp": tcp_result,
        "url_tests": [],
    }

    if not tcp_result.get("success"):
        return result

    for test_definition in TEST_URLS:
        test_result = test_one_url(
            proxy,
            test_definition,
        )

        result["url_tests"].append(
            test_result
        )

    passed_all = all(
        test.get("success", False)
        for test in result["url_tests"]
    )

    result["passed_all_tests"] = (
        passed_all
    )
    result["working"] = passed_all

    return result


def merge_current_source(
    history: dict[str, dict[str, Any]],
    source_proxies: list[dict[str, Any]],
    now: datetime,
) -> None:
    current_keys = {
        proxy_key(proxy)
        for proxy in source_proxies
    }

    for record in history.values():
        record["currently_in_source"] = (
            False
        )

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
            "last_seen_in_source": iso_time(
                now
            ),
            "currently_in_source": True,
        }

    for key, record in history.items():
        record["currently_in_source"] = (
            key in current_keys
        )


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

        try:
            port = int(record.get("port"))
        except (TypeError, ValueError):
            continue

        if not 1 <= port <= 65535:
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

        for future in (
            concurrent.futures.as_completed(
                future_map
            )
        ):
            proxy = future_map[future]
            key = proxy_key(proxy)

            try:
                test_result = future.result()
            except Exception as error:
                test_result = {
                    "working": False,
                    "passed_all_tests": False,
                    "proxy": key,
                    "tested_at": iso_time(now),
                    "error": str(error),
                }

            record = history[key]

            record["last_tested"] = (
                iso_time(now)
            )
            record["last_test_result"] = (
                test_result
            )

            if test_result.get(
                "passed_all_tests"
            ):
                record["last_success"] = (
                    iso_time(now)
                )

                record["success_count"] = (
                    int(
                        record.get(
                            "success_count",
                            0,
                        )
                    )
                    + 1
                )
            else:
                record["failure_count"] = (
                    int(
                        record.get(
                            "failure_count",
                            0,
                        )
                    )
                    + 1
                )


def remove_expired_history(
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

        # Keep current source records in history so
        # they can be tested again later.
        if currently_in_source:
            continue

        # Once a proxy disappears from the source,
        # remove it after 30 days without success.
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

        working_now = bool(
            record.get(
                "last_test_result",
                {},
            ).get(
                "passed_all_tests",
                False,
            )
        )

        recently_worked = (
            last_success is not None
            and last_success >= cutoff
        )

        # Do not publish merely because it appears in
        # ProxyScrape. It must pass both tests now or
        # have passed both within the last 30 days.
        if working_now or recently_worked:
            published.append(record)

    published.sort(
        key=lambda proxy: (
            0
            if proxy.get(
                "last_test_result",
                {},
            ).get(
                "passed_all_tests",
                False,
            )
            else 1,
            -to_float(
                proxy.get(
                    "uptime_percent"
                ),
                0,
            ),
            to_float(
                proxy.get(
                    "latency_ms"
                ),
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
        address = ipaddress.ip_address(
            host
        )

        if address.version == 6:
            return f"[{host}]"

    except ValueError:
        pass

    return host


def safe_city_name(value: Any) -> str:
    city = str(
        value or "Iran"
    ).strip()

    cleaned = "".join(
        character
        if character.isalnum()
        else "-"
        for character in city
    ).strip("-")

    return cleaned or "Iran"


def make_tag(
    proxy: dict[str, Any],
    index: int,
) -> str:
    return (
        f"IR-"
        f"{proxy['protocol'].upper()}-"
        f"{index:03d}-"
        f"{safe_city_name(proxy.get('city'))}"
    )


def make_outbound(
    proxy: dict[str, Any],
    index: int,
) -> tuple[str, dict[str, Any]]:
    protocol = proxy["protocol"]
    tag = make_tag(
        proxy,
        index,
    )

    if protocol == "http":
        outbound: dict[str, Any] = {
            "type": "http",
            "tag": tag,
            "server": proxy["host"],
            "server_port": int(
                proxy["port"]
            ),
        }

    elif protocol == "socks4":
        outbound = {
            "type": "socks",
            "tag": tag,
            "server": proxy["host"],
            "server_port": int(
                proxy["port"]
            ),
            "version": "4",
            "network": "tcp",
        }

    elif protocol == "socks5":
        outbound = {
            "type": "socks",
            "tag": tag,
            "server": proxy["host"],
            "server_port": int(
                proxy["port"]
            ),
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
    if not proxies:
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
                    "type": "direct",
                    "tag": "DIRECT",
                }
            ],
            "route": {
                "final": "DIRECT",
                "auto_detect_interface": True,
            },
        }

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
    host = format_host(
        proxy["host"]
    )

    tag = urllib.parse.quote(
        make_tag(proxy, index),
        safe="",
    )

    return (
        f"{proxy['protocol']}://"
        f"{host}:{proxy['port']}#{tag}"
    )


def create_test_results(
    history: dict[str, dict[str, Any]],
    now: datetime,
) -> dict[str, Any]:
    records = []

    for key, record in sorted(
        history.items()
    ):
        records.append(
            {
                "proxy": key,
                "currently_in_source": (
                    record.get(
                        "currently_in_source",
                        False,
                    )
                ),
                "first_seen": record.get(
                    "first_seen"
                ),
                "last_seen_in_source": (
                    record.get(
                        "last_seen_in_source"
                    )
                ),
                "last_tested": record.get(
                    "last_tested"
                ),
                "last_success": record.get(
                    "last_success"
                ),
                "success_count": record.get(
                    "success_count",
                    0,
                ),
                "failure_count": record.get(
                    "failure_count",
                    0,
                ),
                "test_result": record.get(
                    "last_test_result"
                ),
            }
        )

    return {
        "generated_at": iso_time(now),
        "requirement": (
            "A successful proxy must pass TCP, "
            "ISNA and Google tests."
        ),
        "records": records,
    }


def main() -> None:
    DOCS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    now = utc_now()
    raw_items = download_source()

    raw_iranian_records = [
        item
        for item in raw_items
        if is_iranian(item)
    ]

    unique_source: dict[
        str,
        dict[str, Any],
    ] = {}

    rejected_records = 0

    for item in raw_iranian_records:
        proxy = normalize_proxy(item)

        if proxy is None:
            rejected_records += 1
            continue

        key = proxy_key(proxy)
        existing = unique_source.get(key)

        if existing is None:
            unique_source[key] = proxy
            continue

        # Keep the duplicate entry with the
        # higher reported uptime.
        if (
            proxy["uptime_percent"]
            > existing["uptime_percent"]
        ):
            unique_source[key] = proxy

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

    expired_removed = remove_expired_history(
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

    test_results = create_test_results(
        history,
        now,
    )

    TEST_RESULTS_FILE.write_text(
        json.dumps(
            test_results,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    singbox_config = build_singbox_config(
        published
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
    )

    if plain_content:
        plain_content += "\n"

    PLAIN_OUTPUT.write_text(
        plain_content,
        encoding="utf-8",
    )

    SUB_PLAIN_OUTPUT.write_text(
        plain_content,
        encoding="utf-8",
    )

    encoded_subscription = (
        base64.b64encode(
            plain_content.encode("utf-8")
        ).decode("ascii")
    )

    SUB_OUTPUT.write_text(
        encoded_subscription,
        encoding="ascii",
    )

    working_now = sum(
        bool(
            proxy.get(
                "last_test_result",
                {},
            ).get(
                "passed_all_tests",
                False,
            )
        )
        for proxy in published
    )

    retained_from_history = sum(
        not bool(
            proxy.get(
                "last_test_result",
                {},
            ).get(
                "passed_all_tests",
                False,
            )
        )
        for proxy in published
    )

    published_protocol_counts: dict[
        str,
        int,
    ] = {}

    for proxy in published:
        protocol = proxy["protocol"]

        published_protocol_counts[
            protocol
        ] = (
            published_protocol_counts.get(
                protocol,
                0,
            )
            + 1
        )

    raw_protocol_counts: dict[
        str,
        int,
    ] = {}

    for item in raw_iranian_records:
        protocol = normalize_protocol(
            item.get("protocol")
        )

        raw_protocol_counts[
            protocol
        ] = (
            raw_protocol_counts.get(
                protocol,
                0,
            )
            + 1
        )

    report = {
        "generated_at": iso_time(now),
        "source_url": SOURCE_URL,
        "global_records": len(raw_items),
        "raw_iranian_records": len(
            raw_iranian_records
        ),
        "raw_iranian_protocol_counts": (
            raw_protocol_counts
        ),
        "rejected_iranian_records": (
            rejected_records
        ),
        "current_iranian_unique_records": (
            len(source_proxies)
        ),
        "history_records": len(history),
        "tested_records": len(candidates),
        "working_now_passed_both_urls": (
            working_now
        ),
        "retained_from_previous_success": (
            retained_from_history
        ),
        "retention_days": RETENTION_DAYS,
        "expired_history_removed": (
            expired_removed
        ),
        "published_proxies": len(
            published
        ),
        "published_protocol_counts": (
            published_protocol_counts
        ),
        "test_requirements": {
            "tcp_must_open": True,
            "all_urls_must_pass": True,
            "urls": [
                test["url"]
                for test in TEST_URLS
            ],
        },
        "output_files": {
            "singbox": (
                "iran-all.json"
            ),
            "base64_subscription": (
                "iran-v2ray.txt"
            ),
            "plain_subscription": (
                "iran-v2ray-plain.txt"
            ),
            "test_results": (
                "iran-test-results.json"
            ),
            "history": (
                "proxy-history.json"
            ),
        },
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
