#!/usr/bin/env python3

from datetime import timedelta
from typing import Any

import convert


def _safe_latency(record: dict[str, Any]) -> float:
    result = record.get("last_test_result")
    if not isinstance(result, dict):
        return 999999.0

    tests = result.get("url_tests")
    if not isinstance(tests, list) or not tests:
        return 999999.0

    last = tests[-1]
    if not isinstance(last, dict):
        return 999999.0

    return convert.to_float(last.get("measured_seconds"), 999999.0)


def safe_select_verified_proxies(
    history: dict[str, dict[str, Any]],
    now,
) -> list[dict[str, Any]]:
    cutoff = now - timedelta(days=convert.RETENTION_DAYS)
    selected: list[dict[str, Any]] = []

    for record in history.values():
        if not isinstance(record, dict):
            continue

        result = record.get("last_test_result")
        passed_now = (
            isinstance(result, dict)
            and bool(result.get("passed_all_tests", False))
        )

        last_success = convert.parse_time(record.get("last_success"))
        passed_recently = last_success is not None and last_success >= cutoff

        if passed_now or passed_recently:
            selected.append(record)

    selected.sort(
        key=lambda proxy: (
            0
            if isinstance(proxy.get("last_test_result"), dict)
            and proxy["last_test_result"].get("passed_all_tests", False)
            else 1,
            _safe_latency(proxy),
            -convert.to_float(proxy.get("uptime_percent"), 0),
            str(proxy.get("protocol", "")),
            str(proxy.get("host", "")),
            int(proxy.get("port", 0)),
        )
    )

    return selected


if __name__ == "__main__":
    convert.select_verified_proxies = safe_select_verified_proxies
    convert.main()
