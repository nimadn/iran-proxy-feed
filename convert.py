#!/usr/bin/env python3

import base64
import concurrent.futures
import ipaddress
import json
import re
import socket
import subprocess
import urllib.parse
import urllib.request

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

PROXYSCRAPE_URL = (
    "https://raw.githubusercontent.com/"
    "ProxyScrape/free-proxy-list/main/"
    "proxies/all/data.json"
)

OPENRAY_URL = (
    "https://raw.githubusercontent.com/"
    "sakha1370/OpenRay/refs/heads/main/"
    "output/country/IR.txt"
)

DANIYAL_URL = (
    "https://daniyal-abbassi.github.io/iran-proxy/"
    "proxies.json"
)

VAKHOV_URL = (
    "https://vakhov.github.io/"
    "fresh-proxy-list/proxylist.json"
)

PROXIFLY_URL = (
    "https://raw.githubusercontent.com/"
    "proxifly/free-proxy-list/main/"
    "proxies/countries/IR/data.txt"
)

DATABAY_URL = (
    "https://databay.com/api/v1/"
    "proxy-list?format=json&country=IR"
)


# ---------------------------------------------------------------------------
# Output files
# ---------------------------------------------------------------------------

DOCS_DIR = Path("docs")

HISTORY_FILE = DOCS_DIR / "proxy-history.json"
REPORT_FILE = DOCS_DIR / "iran-report.json"
TEST_RESULTS_FILE = DOCS_DIR / "iran-test-results.json"

SINGBOX_OUTPUT = DOCS_DIR / "iran-all.json"

VERIFIED_PLAIN_OUTPUT = (
    DOCS_DIR / "iran-verified-proxies-plain.txt"
)
VERIFIED_SUB_OUTPUT = (
    DOCS_DIR / "iran-verified-proxies.txt"
)

OPENRAY_PLAIN_OUTPUT = (
    DOCS_DIR / "iran-openray-plain.txt"
)
OPENRAY_SUB_OUTPUT = (
    DOCS_DIR / "iran-openray.txt"
)

COMBINED_PLAIN_OUTPUT = (
    DOCS_DIR / "iran-combined-plain.txt"
)
COMBINED_SUB_OUTPUT = (
    DOCS_DIR / "iran-combined.txt"
)


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

SUPPORTED_PROXY_PROTOCOLS = {
    "http",
    "socks4",
    "socks5",
}

SUPPORTED_SHARE_SCHEMES = {
    "vless",
    "vmess",
    "trojan",
    "ss",
    "ssr",
    "hysteria2",
    "hy2",
    "tuic",
}

RETENTION_DAYS = 30
HISTORICAL_RETEST_HOURS = 24
MAX_HISTORICAL_RETESTS_PER_RUN = 200

TCP_TIMEOUT_SECONDS = 5
REQUEST_TIMEOUT_SECONDS = 15
DOWNLOAD_TIMEOUT_SECONDS = 120
TEST_WORKERS = 20

TEST_DEFINITIONS = [
    {
        "name": "ISNA",
        "url": "https://www.isna.ir/",
        "accepted_codes": set(range(200, 400)),
    },
    {
        "name": "Google",
        "url": (
            "https://www.gstatic.com/"
            "generate_204"
        ),
        "accepted_codes": {204},
    },
]

USER_AGENT = "IranProxyFeed/20.0"


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

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
            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

        return parsed.astimezone(timezone.utc)

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


def to_nonnegative_int(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def normalize_protocol(value: Any) -> str:
    protocol = str(value or "").strip().lower()

    aliases = {
        "sock4": "socks4",
        "sock5": "socks5",
        "socks": "socks5",
        "https": "http",
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


def format_host(host: str) -> str:
    try:
        address = ipaddress.ip_address(host)

        if address.version == 6:
            return f"[{host}]"

    except ValueError:
        pass

    return host


def is_iranian_record(
    item: dict[str, Any],
) -> bool:
    country = str(
        item.get("country")
        or item.get("country_name")
        or ""
    ).strip().casefold()

    country_code = str(
        item.get("country_code")
        or item.get("countryCode")
        or item.get("country_iso")
        or item.get("country_iso_code")
        or ""
    ).strip().upper()

    return (
        country == "iran"
        or country_code == "IR"
    )


def download_bytes(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
            "Cache-Control": "no-cache, no-store",
            "Pragma": "no-cache",
        },
    )

    with urllib.request.urlopen(
        request,
        timeout=DOWNLOAD_TIMEOUT_SECONDS,
    ) as response:
        return response.read()


def download_text(url: str) -> str:
    return download_bytes(url).decode(
        "utf-8",
        errors="replace",
    )


def download_json(url: str) -> Any:
    return json.loads(download_text(url))


def deduplicate_strings(
    values: Iterable[str],
) -> list[str]:
    return list(dict.fromkeys(values))


# ---------------------------------------------------------------------------
# Proxy parsing
# ---------------------------------------------------------------------------

def normalize_proxy(
    protocol: Any,
    host: Any,
    port: Any,
    source: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    normalized_protocol = normalize_protocol(
        protocol
    )

    if normalized_protocol not in (
        SUPPORTED_PROXY_PROTOCOLS
    ):
        return None

    normalized_host = normalize_host(host)

    if normalized_host is None:
        return None

    try:
        normalized_port = int(port)
    except (TypeError, ValueError):
        return None

    if not 1 <= normalized_port <= 65535:
        return None

    metadata = metadata or {}

    return {
        "protocol": normalized_protocol,
        "host": normalized_host,
        "port": normalized_port,
        "source_names": [source],
        "country": str(
            metadata.get("country", "")
        ).strip(),
        "country_code": str(
            metadata.get("country_code", "")
        ).strip(),
        "city": str(
            metadata.get("city", "")
        ).strip(),
        "uptime_percent": to_float(
            metadata.get("uptime_percent"),
            0,
        ),
        "latency_ms": to_float(
            metadata.get("latency_ms"),
            999999,
        ),
        "anonymity": str(
            metadata.get("anonymity", "")
        ).strip(),
    }


def parse_proxy_uri(
    value: str,
    source: str,
) -> dict[str, Any] | None:
    cleaned = value.strip().strip(
        "\"'(),[]{}"
    )

    if not cleaned:
        return None

    try:
        parsed = urllib.parse.urlsplit(
            cleaned
        )
    except ValueError:
        return None

    protocol = normalize_protocol(
        parsed.scheme
    )

    if protocol not in SUPPORTED_PROXY_PROTOCOLS:
        return None

    try:
        port = parsed.port
    except ValueError:
        return None

    return normalize_proxy(
        protocol=protocol,
        host=parsed.hostname,
        port=port,
        source=source,
    )


def parse_host_port(
    value: str,
    protocol: str,
    source: str,
) -> dict[str, Any] | None:
    cleaned = value.strip().strip(
        "\"'(),[]{}"
    )

    if not cleaned:
        return None

    if "://" in cleaned:
        return parse_proxy_uri(
            cleaned,
            source,
        )

    cleaned = cleaned.split("#", 1)[0]
    cleaned = cleaned.split("/", 1)[0]

    try:
        host, port_text = cleaned.rsplit(
            ":",
            1,
        )
        port = int(port_text)
    except (ValueError, TypeError):
        return None

    return normalize_proxy(
        protocol=protocol,
        host=host,
        port=port,
        source=source,
    )


def extract_proxy_uris(
    text: str,
    source: str,
) -> list[dict[str, Any]]:
    pattern = re.compile(
        r"(?i)\b(?:https?|socks4|socks5)://"
        r"(?:\[[0-9a-f:]+\]|"
        r"[a-z0-9._-]+)"
        r":\d{1,5}"
    )

    results = []

    for match in pattern.findall(text):
        parsed = parse_proxy_uri(
            match,
            source,
        )

        if parsed is not None:
            results.append(parsed)

    return results


def proxy_key(proxy: dict[str, Any]) -> str:
    return (
        f"{proxy['protocol']}://"
        f"{proxy['host']}:{proxy['port']}"
    )


# ---------------------------------------------------------------------------
# Source loaders
# ---------------------------------------------------------------------------

def load_proxyscrape() -> list[dict[str, Any]]:
    data = download_json(PROXYSCRAPE_URL)

    if not isinstance(data, list):
        raise ValueError(
            "ProxyScrape response is not a list"
        )

    results = []

    for item in data:
        if not isinstance(item, dict):
            continue

        if not is_iranian_record(item):
            continue

        proxy = normalize_proxy(
            protocol=item.get("protocol"),
            host=(
                item.get("ip")
                or item.get("host")
            ),
            port=item.get("port"),
            source="proxyscrape",
            metadata=item,
        )

        if proxy is not None:
            results.append(proxy)

    return results


def load_proxifly() -> list[dict[str, Any]]:
    text = download_text(PROXIFLY_URL)
    results = []

    for token in re.split(r"\s+", text):
        proxy = parse_proxy_uri(
            token,
            "proxifly",
        )

        if proxy is not None:
            results.append(proxy)

    return results


def vakhov_protocols(
    item: dict[str, Any],
) -> list[str]:
    protocols = []

    direct_protocol = normalize_protocol(
        item.get("protocol")
        or item.get("type")
    )

    if direct_protocol in SUPPORTED_PROXY_PROTOCOLS:
        protocols.append(direct_protocol)

    if item.get("http") is True:
        protocols.append("http")

    # In this dataset SSL normally means that the
    # HTTP proxy can tunnel HTTPS. It is still used
    # as an HTTP proxy endpoint.
    if item.get("ssl") is True:
        protocols.append("http")

    if item.get("https") is True:
        protocols.append("http")

    if item.get("socks4") is True:
        protocols.append("socks4")

    if item.get("socks5") is True:
        protocols.append("socks5")

    return deduplicate_strings(protocols)


def load_vakhov() -> list[dict[str, Any]]:
    data = download_json(VAKHOV_URL)

    if isinstance(data, dict):
        records = (
            data.get("data")
            or data.get("proxies")
            or data.get("results")
            or []
        )
    else:
        records = data

    if not isinstance(records, list):
        raise ValueError(
            "Vakhov response has no proxy list"
        )

    results = []

    for item in records:
        if not isinstance(item, dict):
            continue

        if not is_iranian_record(item):
            continue

        host = (
            item.get("ip")
            or item.get("host")
            or item.get("server")
        )
        port = item.get("port")

        for protocol in vakhov_protocols(
            item
        ):
            proxy = normalize_proxy(
                protocol=protocol,
                host=host,
                port=port,
                source="vakhov",
                metadata=item,
            )

            if proxy is not None:
                results.append(proxy)

    return results


def flatten_databay_records(
    value: Any,
) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [
            item
            for item in value
            if isinstance(item, dict)
        ]

    if not isinstance(value, dict):
        return []

    for key in (
        "data",
        "results",
        "proxies",
        "items",
        "proxy_list",
    ):
        nested = value.get(key)

        if isinstance(nested, list):
            return [
                item
                for item in nested
                if isinstance(item, dict)
            ]

        if isinstance(nested, dict):
            nested_records = (
                flatten_databay_records(
                    nested
                )
            )

            if nested_records:
                return nested_records

    # Some APIs return one proxy as the root object.
    if (
        value.get("ip")
        or value.get("host")
        or value.get("proxy")
    ):
        return [value]

    return []


def load_databay() -> list[dict[str, Any]]:
    data = download_json(DATABAY_URL)

    records = flatten_databay_records(data)

    results = []

    for item in records:
        host = (
            item.get("ip")
            or item.get("host")
            or item.get("server")
        )

        port = item.get("port")

        protocol_values: list[str] = []

        raw_protocol = (
            item.get("protocol")
            or item.get("type")
            or item.get("scheme")
        )

        if isinstance(raw_protocol, list):
            protocol_values.extend(
                str(value)
                for value in raw_protocol
            )
        elif raw_protocol:
            protocol_values.append(
                str(raw_protocol)
            )

        if item.get("http") is True:
            protocol_values.append("http")

        if item.get("https") is True:
            protocol_values.append("http")

        if item.get("socks4") is True:
            protocol_values.append("socks4")

        if item.get("socks5") is True:
            protocol_values.append("socks5")

        if not protocol_values:
            proxy_string = str(
                item.get("proxy", "")
            )

            parsed = parse_proxy_uri(
                proxy_string,
                "databay",
            )

            if parsed is not None:
                results.append(parsed)

            continue

        for protocol in deduplicate_strings(
            normalize_protocol(value)
            for value in protocol_values
        ):
            proxy = normalize_proxy(
                protocol=protocol,
                host=host,
                port=port,
                source="databay",
                metadata=item,
            )

            if proxy is not None:
                results.append(proxy)

    return results


def load_daniyal() -> list[dict[str, Any]]:
    data = download_json(DANIYAL_URL)

    if not isinstance(data, list):
        raise ValueError(
            "Daniyal proxies.json response is not a list"
        )

    results = []

    for item in data:
        if not isinstance(item, dict):
            continue

        proxy = normalize_proxy(
            protocol=item.get("protocol"),
            host=item.get("host") or item.get("ip"),
            port=item.get("port"),
            source="daniyal",
            metadata={
                **item,
                "latency_ms": item.get("latency"),
            },
        )

        if proxy is not None:
            results.append(proxy)

    return results

# ---------------------------------------------------------------------------
# OpenRay share links
# ---------------------------------------------------------------------------

def extract_share_links(text: str) -> list[str]:
    prefixes = "|".join(
        re.escape(scheme)
        for scheme in sorted(
            SUPPORTED_SHARE_SCHEMES,
            key=len,
            reverse=True,
        )
    )

    pattern = re.compile(
        rf"(?i)(?:{prefixes})://[^\s\"'<>]+"
    )

    links = []

    for match in pattern.findall(text):
        cleaned = match.strip().rstrip(
            ".,;)]}"
        )

        scheme = cleaned.split(
            "://",
            1,
        )[0].lower()

        if scheme in SUPPORTED_SHARE_SCHEMES:
            links.append(cleaned)

    return deduplicate_strings(links)


def normalize_share_link_for_dedup(
    link: str,
) -> str:
    # Keep authentication and transport parameters.
    # Only remove the display name fragment.
    return link.split("#", 1)[0].strip()


def deduplicate_share_links(links: Iterable[str]) -> list[str]:
    unique: dict[str, str] = {}
    for link in links:
        key = normalize_share_link_for_dedup(link)
        if key and key not in unique:
            unique[key] = link
    return list(unique.values())


def load_openray() -> list[str]:
    text = download_text(OPENRAY_URL)
    links = extract_share_links(text)
    return deduplicate_share_links(links)


# ---------------------------------------------------------------------------
# Merge all conventional proxy sources
# ---------------------------------------------------------------------------

def merge_proxy_records(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    unique: dict[
        str,
        dict[str, Any],
    ] = {}

    for proxy in records:
        key = proxy_key(proxy)
        existing = unique.get(key)

        if existing is None:
            unique[key] = proxy
            continue

        source_names = deduplicate_strings(
            list(
                existing.get(
                    "source_names",
                    [],
                )
            )
            + list(
                proxy.get(
                    "source_names",
                    [],
                )
            )
        )

        existing["source_names"] = (
            source_names
        )

        if (
            proxy.get(
                "uptime_percent",
                0,
            )
            > existing.get(
                "uptime_percent",
                0,
            )
        ):
            existing[
                "uptime_percent"
            ] = proxy.get(
                "uptime_percent",
                0,
            )

        if (
            proxy.get(
                "latency_ms",
                999999,
            )
            < existing.get(
                "latency_ms",
                999999,
            )
        ):
            existing[
                "latency_ms"
            ] = proxy.get(
                "latency_ms",
                999999,
            )

        for field in (
            "country",
            "country_code",
            "city",
            "anonymity",
        ):
            if (
                not existing.get(field)
                and proxy.get(field)
            ):
                existing[field] = proxy[field]

    return list(unique.values())


# ---------------------------------------------------------------------------
# Testing conventional proxies
# ---------------------------------------------------------------------------

def tcp_test(
    proxy: dict[str, Any],
) -> dict[str, Any]:
    started = utc_now()

    try:
        with socket.create_connection(
            (
                proxy["host"],
                int(proxy["port"]),
            ),
            timeout=TCP_TIMEOUT_SECONDS,
        ):
            elapsed = (
                utc_now() - started
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
        # Proxy performs DNS resolution.
        protocol = "socks5h"
    elif protocol == "socks4":
        # Prefer proxy-side DNS resolution for SOCKS4.
        protocol = "socks4a"

    return (
        f"{protocol}://"
        f"{format_host(proxy['host'])}:"
        f"{proxy['port']}"
    )


def test_one_url(
    proxy: dict[str, Any],
    definition: dict[str, Any],
) -> dict[str, Any]:
    proxy_argument = curl_proxy_url(proxy)

    command = [
        "curl",
        "--silent",
        "--show-error",
        "--location",
        "--output",
        "/dev/null",
        "--proxy",
        proxy_argument,
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
        definition["url"],
    ]

    empty_evidence: dict[str, Any] = {
        "name": definition["name"],
        "url": definition["url"],
        "success": False,
        "proxy_argument": proxy_argument,
        "curl_returncode": None,
        "http_code": None,
        "http_status": None,
        "measured_seconds": None,
        "response_time": None,
        "remote_ip": "",
        "effective_url": "",
        "stderr": "",
        "error": "",
    }

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=REQUEST_TIMEOUT_SECONDS + 5,
            check=False,
        )
    except (
        subprocess.TimeoutExpired,
        OSError,
    ) as error:
        return {
            **empty_evidence,
            "error": str(error),
        }

    output = completed.stdout.strip()
    parts = output.split("|", 3)
    result = {
        **empty_evidence,
        "curl_returncode": completed.returncode,
        "stderr": completed.stderr.strip(),
    }

    if (
        completed.returncode != 0
        or len(parts) != 4
    ):
        result["raw_output"] = output
        result["error"] = (
            completed.stderr.strip()
            or f"curl exited with {completed.returncode}"
        )
        return result

    try:
        http_code = int(parts[0])
        elapsed = float(parts[1])
    except ValueError:
        result["raw_output"] = output
        result["error"] = "Could not parse curl write-out fields"
        return result

    result.update(
        {
            "http_code": http_code,
            "http_status": http_code,
            "measured_seconds": round(
                elapsed,
                3,
            ),
            "response_time": round(elapsed, 3),
            "remote_ip": parts[2],
            "effective_url": parts[3],
            "success": (
                http_code
                in definition[
                    "accepted_codes"
                ]
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

    for definition in TEST_DEFINITIONS:
        result["url_tests"].append(
            test_one_url(
                proxy,
                definition,
            )
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


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------

def normalize_history_record(
    key: str,
    value: Any,
) -> tuple[str, dict[str, Any]] | None:
    if not isinstance(value, dict):
        return None

    protocol = normalize_protocol(value.get("protocol"))
    host = normalize_host(value.get("host"))

    try:
        port = int(value.get("port"))
    except (TypeError, ValueError):
        port = 0

    if (
        protocol not in SUPPORTED_PROXY_PROTOCOLS
        or host is None
        or not 1 <= port <= 65535
    ):
        parsed = parse_proxy_uri(key, "history")
        if parsed is None:
            return None
        protocol = parsed["protocol"]
        host = parsed["host"]
        port = parsed["port"]

    raw_sources = value.get("source_names", [])
    if isinstance(raw_sources, str):
        raw_sources = [raw_sources]
    if not isinstance(raw_sources, list):
        raw_sources = []
    source_names = deduplicate_strings(
        str(source).strip()
        for source in raw_sources
        if str(source).strip()
    )

    raw_result = value.get("last_test_result")
    result = dict(raw_result) if isinstance(raw_result, dict) else {}
    raw_url_tests = result.get("url_tests")
    result["url_tests"] = (
        [dict(test) for test in raw_url_tests if isinstance(test, dict)]
        if isinstance(raw_url_tests, list)
        else []
    )
    result["passed_all_tests"] = bool(
        result.get("passed_all_tests", False)
    )
    result["working"] = bool(result.get("working", False))

    record = {
        **value,
        "protocol": protocol,
        "host": host,
        "port": port,
        "source_names": source_names,
        "success_count": to_nonnegative_int(
            value.get("success_count")
        ),
        "failure_count": to_nonnegative_int(
            value.get("failure_count")
        ),
        "last_test_result": result,
    }
    return proxy_key(record), record


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

    history: dict[str, dict[str, Any]] = {}
    for key, value in data.items():
        normalized = normalize_history_record(
            str(key), value
        )
        if normalized is not None:
            normalized_key, record = normalized
            history[normalized_key] = record
    return history

def merge_current_proxies_into_history(
    history: dict[str, dict[str, Any]],
    current_proxies: list[dict[str, Any]],
    now: datetime,
) -> None:
    current_keys = {
        proxy_key(proxy)
        for proxy in current_proxies
    }

    for record in history.values():
        record["currently_in_source"] = (
            False
        )

    for proxy in current_proxies:
        key = proxy_key(proxy)
        existing = history.get(key, {})

        old_sources = list(
            existing.get(
                "source_names",
                [],
            )
        )

        new_sources = list(
            proxy.get(
                "source_names",
                [],
            )
        )

        history[key] = {
            **existing,
            **proxy,
            "source_names": (
                deduplicate_strings(
                    old_sources + new_sources
                )
            ),
            "first_seen": existing.get(
                "first_seen",
                iso_time(now),
            ),
            "last_seen_in_source": (
                iso_time(now)
            ),
            "currently_in_source": True,
        }

    for key, record in history.items():
        record["currently_in_source"] = (
            key in current_keys
        )


def test_all_history_records(
    history: dict[str, dict[str, Any]],
    now: datetime,
) -> int:
    current_candidates = []
    historical_candidates = []
    historical_cutoff = now - timedelta(
        hours=HISTORICAL_RETEST_HOURS
    )

    for record in history.values():
        if (
            record.get("protocol")
            not in SUPPORTED_PROXY_PROTOCOLS
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

        if record.get("currently_in_source", False):
            current_candidates.append(record)
            continue

        last_tested = parse_time(record.get("last_tested"))
        if (
            last_tested is None
            or last_tested <= historical_cutoff
        ):
            historical_candidates.append(record)

    historical_candidates.sort(
        key=lambda record: (
            parse_time(record.get("last_tested"))
            or datetime.min.replace(tzinfo=timezone.utc),
            proxy_key(record),
        )
    )
    candidates = current_candidates + historical_candidates[
        :MAX_HISTORICAL_RETESTS_PER_RUN
    ]

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
                result = future.result()
            except Exception as error:
                result = {
                    "working": False,
                    "passed_all_tests": False,
                    "proxy": key,
                    "tested_at": iso_time(now),
                    "tcp": {
                        "success": False,
                        "error": "Unhandled test exception",
                    },
                    "url_tests": [],
                    "error": str(error),
                }

            record = history[key]

            record["last_tested"] = (
                iso_time(now)
            )
            record["last_test_result"] = (
                result
            )

            if result.get(
                "passed_all_tests"
            ):
                record["last_success"] = (
                    iso_time(now)
                )
                record["success_count"] = (
                    to_nonnegative_int(
                        record.get("success_count")
                    ) + 1
                )
            else:
                record["failure_count"] = (
                    to_nonnegative_int(
                        record.get("failure_count")
                    ) + 1
                )

    return len(candidates)

def remove_expired_history(
    history: dict[str, dict[str, Any]],
    now: datetime,
) -> int:
    cutoff = now - timedelta(
        days=RETENTION_DAYS
    )

    expired = []

    for key, record in history.items():
        if record.get(
            "currently_in_source",
            False,
        ):
            continue

        last_success = parse_time(
            record.get("last_success")
        )

        if (
            last_success is None
            or last_success < cutoff
        ):
            expired.append(key)

    for key in expired:
        del history[key]

    return len(expired)


def select_verified_proxies(
    history: dict[str, dict[str, Any]],
    now: datetime,
) -> list[dict[str, Any]]:
    cutoff = now - timedelta(
        days=RETENTION_DAYS
    )

    selected = []

    for record in history.values():
        result = record.get("last_test_result")
        passed_now = bool(
            isinstance(result, dict)
            and result.get("passed_all_tests", False)
        )

        last_success = parse_time(
            record.get("last_success")
        )

        passed_recently = (
            last_success is not None
            and last_success >= cutoff
        )

        if passed_now or passed_recently:
            selected.append(record)

    def latest_test_latency(proxy: dict[str, Any]) -> float:
        result = proxy.get("last_test_result")
        if not isinstance(result, dict):
            return 999999
        url_tests = result.get("url_tests")
        if not isinstance(url_tests, list) or not url_tests:
            return 999999
        latest = url_tests[-1]
        if not isinstance(latest, dict):
            return 999999
        return to_float(
            latest.get("measured_seconds"),
            999999,
        )

    selected.sort(
        key=lambda proxy: (
            0
            if (
                isinstance(proxy.get("last_test_result"), dict)
                and proxy["last_test_result"].get(
                    "passed_all_tests", False
                )
            )
            else 1,
            latest_test_latency(proxy),
            -to_float(
                proxy.get(
                    "uptime_percent"
                ),
                0,
            ),
            proxy["protocol"],
            proxy["host"],
            proxy["port"],
        )
    )

    return selected

# ---------------------------------------------------------------------------
# Output generation
# ---------------------------------------------------------------------------

def safe_name(value: Any) -> str:
    text = str(value or "Iran").strip()

    cleaned = "".join(
        character
        if character.isalnum()
        else "-"
        for character in text
    ).strip("-")

    return cleaned or "Iran"


def proxy_display_tag(
    proxy: dict[str, Any],
    index: int,
) -> str:
    sources = "-".join(
        proxy.get(
            "source_names",
            ["unknown"],
        )
    )

    return (
        f"IR-"
        f"{proxy['protocol'].upper()}-"
        f"{index:03d}-"
        f"{safe_name(proxy.get('city'))}-"
        f"{safe_name(sources)}"
    )


def build_proxy_share_link(
    proxy: dict[str, Any],
    index: int,
) -> str:
    tag = urllib.parse.quote(
        proxy_display_tag(
            proxy,
            index,
        ),
        safe="",
    )

    return (
        f"{proxy['protocol']}://"
        f"{format_host(proxy['host'])}:"
        f"{proxy['port']}#{tag}"
    )


def build_singbox_config(
    proxies: list[dict[str, Any]],
) -> dict[str, Any]:
    if not proxies:
        return {
            "log": {
                "level": "info",
                "timestamp": True,
            },
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
        tag = proxy_display_tag(
            proxy,
            index,
        )

        tags.append(tag)

        if proxy["protocol"] == "http":
            outbound = {
                "type": "http",
                "tag": tag,
                "server": proxy["host"],
                "server_port": proxy["port"],
            }

        elif proxy["protocol"] == "socks4":
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

        outbounds.append(outbound)

    return {
        "log": {
            "level": "info",
            "timestamp": True,
        },
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


def write_plain_and_base64(
    plain_path: Path,
    encoded_path: Path,
    links: list[str],
) -> None:
    plain = "\n".join(links)

    if plain:
        plain += "\n"

    plain_path.write_text(
        plain,
        encoding="utf-8",
    )

    encoded = base64.b64encode(
        plain.encode("utf-8")
    ).decode("ascii")

    encoded_path.write_text(
        encoded,
        encoding="ascii",
    )


def write_test_results(
    history: dict[str, dict[str, Any]],
    now: datetime,
) -> None:
    records = []

    for key, record in sorted(
        history.items()
    ):
        records.append(
            {
                "proxy": key,
                "source_names": record.get(
                    "source_names",
                    [],
                ),
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

    document = {
        "generated_at": iso_time(now),
        "verification_rule": (
            "TCP, ISNA and Google must all pass."
        ),
        "records": records,
    }

    TEST_RESULTS_FILE.write_text(
        json.dumps(
            document,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def collect_conventional_sources(
    source_loaders: dict[str, Any],
) -> tuple[
    list[dict[str, Any]],
    dict[str, int],
    dict[str, str],
]:
    records: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    errors: dict[str, str] = {}

    for name, loader in source_loaders.items():
        try:
            source_records = loader()
            if not isinstance(source_records, list):
                raise TypeError("source loader did not return a list")
            counts[name] = len(source_records)
            records.extend(source_records)
        except Exception as error:
            counts[name] = 0
            errors[name] = f"{type(error).__name__}: {error}"

    return records, counts, errors


def main() -> None:
    DOCS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    now = utc_now()

    source_loaders = {
        "proxyscrape": load_proxyscrape,
        "proxifly": load_proxifly,
        "vakhov": load_vakhov,
        "databay": load_databay,
        "daniyal": load_daniyal,
    }

    (
        conventional_records,
        source_counts,
        source_errors,
    ) = collect_conventional_sources(source_loaders)

    try:
        openray_links = load_openray()
        source_counts["openray"] = len(
            openray_links
        )
    except Exception as error:
        openray_links = []
        source_counts["openray"] = 0
        source_errors["openray"] = (
            f"{type(error).__name__}: {error}"
        )

    current_proxies = merge_proxy_records(
        conventional_records
    )

    history = load_history()

    merge_current_proxies_into_history(
        history,
        current_proxies,
        now,
    )

    tested_count = test_all_history_records(
        history,
        now,
    )

    expired_removed = remove_expired_history(
        history,
        now,
    )

    verified_proxies = select_verified_proxies(
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

    write_test_results(
        history,
        now,
    )

    singbox_config = build_singbox_config(
        verified_proxies
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

    verified_links = [
        build_proxy_share_link(
            proxy,
            index,
        )
        for index, proxy in enumerate(
            verified_proxies,
            start=1,
        )
    ]

    write_plain_and_base64(
        VERIFIED_PLAIN_OUTPUT,
        VERIFIED_SUB_OUTPUT,
        verified_links,
    )

    write_plain_and_base64(
        OPENRAY_PLAIN_OUTPUT,
        OPENRAY_SUB_OUTPUT,
        openray_links,
    )

    combined_links = deduplicate_strings(
        verified_links + openray_links
    )

    write_plain_and_base64(
        COMBINED_PLAIN_OUTPUT,
        COMBINED_SUB_OUTPUT,
        combined_links,
    )

    current_run_time = iso_time(now)
    working_now = sum(
        bool(
            proxy.get("last_tested") == current_run_time
            and isinstance(proxy.get("last_test_result"), dict)
            and proxy["last_test_result"].get(
                "passed_all_tests",
                False,
            )
        )
        for proxy in verified_proxies
    )

    retained_from_history = (
        len(verified_proxies)
        - working_now
    )

    protocol_counts: dict[str, int] = {}

    for proxy in verified_proxies:
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
        "generation_time": iso_time(now),
        "source_counts_before_deduplication": source_counts,
        "source_errors": source_errors,
        "source_failures": source_errors,
        "conventional_records_before_deduplication": len(
            conventional_records
        ),
        "count_before_deduplication": len(
            conventional_records
        ),
        "current_unique_conventional_proxies": len(
            current_proxies
        ),
        "count_after_deduplication": len(
            current_proxies
        ),
        "history_records": len(history),
        "tested_count": tested_count,
        "working_now_passed_all_tests": working_now,
        "working_now_count": working_now,
        "retained_from_previous_success": retained_from_history,
        "retained_history_count": retained_from_history,
        "retention_days": RETENTION_DAYS,
        "historical_retest_hours": HISTORICAL_RETEST_HOURS,
        "historical_retest_cap": MAX_HISTORICAL_RETESTS_PER_RUN,
        "expired_history_removed": expired_removed,
        "published_verified_proxies": len(verified_proxies),
        "verified_protocol_counts": protocol_counts,
        "protocol_counts": protocol_counts,
        "openray_share_links": len(openray_links),
        "openray_count": len(openray_links),
        "combined_subscription_links": len(combined_links),
        "combined_count": len(combined_links),
        "openray_verification_notice": (
            "OpenRay share links are not verified by curl; "
            "they are published separately and in the combined feed."
        ),
        "verification": {
            "conventional_proxy_tcp_required": True,
            "all_urls_must_pass": True,
            "test_urls": [
                definition["url"]
                for definition in TEST_DEFINITIONS
            ],
            "openray_links_verified": False,
            "openray_reason": (
                "VLESS, VMess, Shadowsocks, SSR, Trojan, "
                "Hysteria2 and TUIC links are not supported "
                "by curl --proxy."
            ),
        },
        "outputs": {
            "verified_proxy_subscription": (
                "iran-verified-proxies.txt"
            ),
            "verified_proxy_plain": (
                "iran-verified-proxies-plain.txt"
            ),
            "openray_subscription": "iran-openray.txt",
            "openray_plain": "iran-openray-plain.txt",
            "combined_subscription": "iran-combined.txt",
            "combined_plain": "iran-combined-plain.txt",
            "singbox_verified_proxies": "iran-all.json",
            "test_results": "iran-test-results.json",
            "history": "proxy-history.json",
        },
        "output_filenames": [
            "iran-all.json",
            "iran-verified-proxies-plain.txt",
            "iran-verified-proxies.txt",
            "iran-openray-plain.txt",
            "iran-openray.txt",
            "iran-combined-plain.txt",
            "iran-combined.txt",
            "iran-report.json",
            "iran-test-results.json",
            "proxy-history.json",
        ],
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
