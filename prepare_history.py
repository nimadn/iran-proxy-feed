#!/usr/bin/env python3

import json
from pathlib import Path

HISTORY_FILE = Path("docs/proxy-history.json")


def main() -> None:
    if not HISTORY_FILE.exists():
        return

    try:
        history = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return

    if not isinstance(history, dict):
        return

    changed = False

    for record in history.values():
        if not isinstance(record, dict):
            continue

        result = record.get("last_test_result")
        if not isinstance(result, dict):
            continue

        url_tests = result.get("url_tests")
        if url_tests == []:
            result["url_tests"] = [
                {
                    "name": "No successful URL test in latest run",
                    "success": False,
                    "measured_seconds": 999999,
                }
            ]
            changed = True

    if changed:
        HISTORY_FILE.write_text(
            json.dumps(history, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
