import base64
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import convert


class ConvertTests(unittest.TestCase):
    def test_iranian_country_filtering(self) -> None:
        self.assertTrue(convert.is_iranian_record({"country": "Iran"}))
        self.assertTrue(convert.is_iranian_record({"country_code": "ir"}))
        self.assertTrue(convert.is_iranian_record({"countryCode": "IR"}))
        self.assertFalse(convert.is_iranian_record({"country": "Iraq"}))

    def test_protocol_normalization(self) -> None:
        cases = {
            "HTTPS": "http",
            "sock4": "socks4",
            "SOCK5": "socks5",
            "socks": "socks5",
            "http": "http",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(convert.normalize_protocol(value), expected)

    def test_proxy_arguments_use_remote_dns(self) -> None:
        socks4 = {"protocol": "socks4", "host": "1.2.3.4", "port": 1080}
        socks5 = {"protocol": "socks5", "host": "1.2.3.4", "port": 1080}
        self.assertEqual(
            convert.curl_proxy_url(socks4), "socks4a://1.2.3.4:1080"
        )
        self.assertEqual(
            convert.curl_proxy_url(socks5), "socks5h://1.2.3.4:1080"
        )

    def test_conventional_proxy_deduplication_merges_sources(self) -> None:
        first = convert.normalize_proxy("http", "1.2.3.4", 8080, "one")
        second = convert.normalize_proxy("https", "1.2.3.4", "8080", "two")
        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        merged = convert.merge_proxy_records([first, second])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["source_names"], ["one", "two"])

    def test_share_link_deduplication_ignores_only_fragment(self) -> None:
        links = [
            "vless://id@example.com:443?security=tls#first",
            "vless://id@example.com:443?security=tls#second",
            "vless://id@example.com:443?security=none#third",
        ]
        deduplicated = convert.deduplicate_share_links(links)
        self.assertEqual(deduplicated, [links[0], links[2]])

    def test_empty_url_tests_is_safe(self) -> None:
        now = datetime(2026, 7, 14, tzinfo=timezone.utc)
        record = {
            "protocol": "http",
            "host": "1.2.3.4",
            "port": 80,
            "last_success": "2026-07-13T00:00:00+00:00",
            "last_test_result": {
                "passed_all_tests": False,
                "url_tests": [],
            },
        }
        selected = convert.select_verified_proxies({"proxy": record}, now)
        self.assertEqual(selected, [record])

    def test_malformed_history_is_normalized_or_skipped(self) -> None:
        data = {
            "http://1.2.3.4:80": {
                "source_names": "legacy",
                "success_count": "bad",
                "failure_count": -4,
                "last_test_result": {"url_tests": None},
            },
            "not-a-proxy": {"host": None, "port": "bad"},
            "wrong-type": ["not", "a", "record"],
        }
        with tempfile.TemporaryDirectory() as directory:
            history_path = Path(directory) / "history.json"
            history_path.write_text(json.dumps(data), encoding="utf-8")
            with mock.patch.object(convert, "HISTORY_FILE", history_path):
                history = convert.load_history()

        self.assertEqual(list(history), ["http://1.2.3.4:80"])
        record = history["http://1.2.3.4:80"]
        self.assertEqual(record["source_names"], ["legacy"])
        self.assertEqual(record["success_count"], 0)
        self.assertEqual(record["failure_count"], 0)
        self.assertEqual(record["last_test_result"]["url_tests"], [])

    def test_source_failure_isolation(self) -> None:
        proxy = convert.normalize_proxy("http", "1.2.3.4", 80, "good")

        def failed_source():
            raise RuntimeError("source changed")

        records, counts, errors = convert.collect_conventional_sources(
            {"bad": failed_source, "good": lambda: [proxy]}
        )
        self.assertEqual(records, [proxy])
        self.assertEqual(counts, {"bad": 0, "good": 1})
        self.assertIn("RuntimeError: source changed", errors["bad"])

    def test_base64_output_validation(self) -> None:
        links = [
            "http://1.2.3.4:80#one",
            "socks5://[2001:db8::1]:1080#two",
        ]
        with tempfile.TemporaryDirectory() as directory:
            plain = Path(directory) / "plain.txt"
            encoded = Path(directory) / "encoded.txt"
            convert.write_plain_and_base64(plain, encoded, links)
            decoded = base64.b64decode(
                encoded.read_text(encoding="ascii"), validate=True
            ).decode("utf-8")

        self.assertEqual(decoded.splitlines(), links)

    def test_app_protocol_filters(self) -> None:
        links = [
            "vless://one",
            "vmess://two",
            "trojan://three",
            "ss://four",
            "ssr://five",
            "hysteria2://six",
            "tuic://seven",
        ]
        self.assertEqual(
            convert.filter_share_links(
                links,
                convert.HAPP_SHARE_SCHEMES,
            ),
            links[:4],
        )
        self.assertEqual(
            convert.filter_share_links(
                links,
                convert.HIDDIFY_SHARE_SCHEMES,
            ),
            [*links[:4], *links[5:]],
        )

    def test_socks5_links_use_app_compatible_scheme(self) -> None:
        socks5 = convert.normalize_proxy(
            "socks5",
            "1.2.3.4",
            1080,
            "test",
        )
        socks4 = convert.normalize_proxy(
            "socks4",
            "5.6.7.8",
            1080,
            "test",
        )
        self.assertIsNotNone(socks5)
        self.assertIsNotNone(socks4)

        links = convert.build_socks5_share_links(
            [socks4, socks5]
        )

        self.assertEqual(len(links), 1)
        self.assertTrue(
            links[0].startswith(
                "socks://1.2.3.4:1080#"
            )
        )

    def test_client_specific_serialization(self) -> None:
        links = [
            "vless://one",
            "ss://two",
        ]
        with tempfile.TemporaryDirectory() as directory:
            plain = Path(directory) / "happ.txt"
            encoded = Path(directory) / "v2rayn.txt"
            convert.write_plain_subscription(
                plain,
                links,
            )
            convert.write_base64_subscription(
                encoded,
                links,
            )
            plain_text = plain.read_text(
                encoding="utf-8"
            )
            decoded = base64.b64decode(
                encoded.read_text(encoding="ascii"),
                validate=True,
            ).decode("utf-8")

        self.assertEqual(
            plain_text.splitlines(),
            links,
        )
        self.assertEqual(decoded.splitlines(), links)


if __name__ == "__main__":
    unittest.main()
