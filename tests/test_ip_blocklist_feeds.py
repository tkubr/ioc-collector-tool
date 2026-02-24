"""
IP Blocklist Feed Test Suite
Mock HTTP response ile tüm IP blocklist feed'lerinin parse edilmesini test eder.
"""

import unittest
from unittest.mock import MagicMock
from ioc_collector.sources.ip_blocklist_feeds import IPBlocklistFeed
from ioc_collector.sources.remote_fetcher import RemoteFetcher


# --- Mock data ---

MOCK_BLOCKLIST_DE = """# Blocklist.de all.txt
# Last updated: 2025-01-01
192.168.1.1
10.0.0.1
203.0.113.50
198.51.100.25
"""

MOCK_EMERGING_THREATS = """# Emerging Threats compromised IPs
# Updated daily
172.16.0.10
192.0.2.100
10.10.10.10
"""

MOCK_SPAMHAUS_DROP = """; Spamhaus DROP List
; Last-Modified: 2025-01-01
; Entries: 3
1.10.16.0/20 ; SB123456
5.8.37.0/24 ; SB654321
27.126.160.0/20 ; SB789012
"""

MOCK_CINSSCORE = """# CI Army Bad Guys List
# https://cinsscore.com
185.220.100.240
185.220.101.1
23.129.64.100
"""

MOCK_TALOS = """192.168.50.1
10.20.30.40
172.217.0.1
"""


class TestIPBlocklistHelpers(unittest.TestCase):
    """Yardımcı methodların testi"""

    def setUp(self):
        self.fetcher = MagicMock(spec=RemoteFetcher)
        self.feed = IPBlocklistFeed(self.fetcher)

    def test_parse_ip_list_skips_comments(self):
        text = "# comment\n192.168.1.1\n# another\n10.0.0.1\n"
        result = self.feed._parse_ip_list(text)
        self.assertEqual(result, ["192.168.1.1", "10.0.0.1"])

    def test_parse_ip_list_skips_semicolons(self):
        text = "; comment\n192.168.1.1\n"
        result = self.feed._parse_ip_list(text)
        self.assertEqual(result, ["192.168.1.1"])

    def test_parse_ip_list_spamhaus_format(self):
        """Spamhaus DROP CIDR formatını doğru parse etmeli"""
        text = "1.10.16.0/20 ; SB123456\n5.8.37.0/24 ; SB654321\n"
        result = self.feed._parse_ip_list(text)
        self.assertEqual(result, ["1.10.16.0/20", "5.8.37.0/24"])

    def test_parse_ip_list_empty(self):
        result = self.feed._parse_ip_list("# only comments\n")
        self.assertEqual(result, [])


class TestBlocklistDeFeed(unittest.TestCase):
    def setUp(self):
        self.fetcher = MagicMock(spec=RemoteFetcher)
        self.feed = IPBlocklistFeed(self.fetcher)

    def test_fetch_parses_ips(self):
        self.fetcher.fetch.return_value = MOCK_BLOCKLIST_DE
        result = self.feed.fetch_blocklist_de()
        self.assertIsNotNone(result)
        self.assertIn("192.168.1.1", result)
        self.assertIn("203.0.113.50", result)
        self.assertNotIn("#", result)

    def test_fetch_returns_none_on_failure(self):
        self.fetcher.fetch.return_value = None
        result = self.feed.fetch_blocklist_de()
        self.assertIsNone(result)


class TestEmergingThreatsFeed(unittest.TestCase):
    def setUp(self):
        self.fetcher = MagicMock(spec=RemoteFetcher)
        self.feed = IPBlocklistFeed(self.fetcher)

    def test_fetch_parses_ips(self):
        self.fetcher.fetch.return_value = MOCK_EMERGING_THREATS
        result = self.feed.fetch_emerging_threats()
        self.assertIsNotNone(result)
        self.assertIn("172.16.0.10", result)
        self.assertIn("192.0.2.100", result)

    def test_fetch_returns_none_on_failure(self):
        self.fetcher.fetch.return_value = None
        result = self.feed.fetch_emerging_threats()
        self.assertIsNone(result)


class TestSpamhausDROPFeed(unittest.TestCase):
    def setUp(self):
        self.fetcher = MagicMock(spec=RemoteFetcher)
        self.feed = IPBlocklistFeed(self.fetcher)

    def test_fetch_parses_cidr(self):
        self.fetcher.fetch.return_value = MOCK_SPAMHAUS_DROP
        result = self.feed.fetch_spamhaus_drop()
        self.assertIsNotNone(result)
        self.assertIn("1.10.16.0/20", result)
        self.assertIn("5.8.37.0/24", result)
        # Semicolon sonrası SB kodu olmamalı
        self.assertNotIn("SB123456", result)

    def test_fetch_returns_none_on_failure(self):
        self.fetcher.fetch.return_value = None
        result = self.feed.fetch_spamhaus_drop()
        self.assertIsNone(result)


class TestCinsscoreFeed(unittest.TestCase):
    def setUp(self):
        self.fetcher = MagicMock(spec=RemoteFetcher)
        self.feed = IPBlocklistFeed(self.fetcher)

    def test_fetch_parses_ips(self):
        self.fetcher.fetch.return_value = MOCK_CINSSCORE
        result = self.feed.fetch_cinsscore()
        self.assertIsNotNone(result)
        self.assertIn("185.220.100.240", result)
        self.assertIn("23.129.64.100", result)

    def test_fetch_returns_none_on_failure(self):
        self.fetcher.fetch.return_value = None
        result = self.feed.fetch_cinsscore()
        self.assertIsNone(result)


class TestTalosFeed(unittest.TestCase):
    def setUp(self):
        self.fetcher = MagicMock(spec=RemoteFetcher)
        self.feed = IPBlocklistFeed(self.fetcher)

    def test_fetch_parses_ips(self):
        self.fetcher.fetch.return_value = MOCK_TALOS
        result = self.feed.fetch_talos()
        self.assertIsNotNone(result)
        self.assertIn("192.168.50.1", result)
        self.assertIn("10.20.30.40", result)

    def test_fetch_returns_none_on_failure(self):
        self.fetcher.fetch.return_value = None
        result = self.feed.fetch_talos()
        self.assertIsNone(result)


class TestFetchAll(unittest.TestCase):
    def setUp(self):
        self.fetcher = MagicMock(spec=RemoteFetcher)
        self.feed = IPBlocklistFeed(self.fetcher)

    def test_fetch_all_combines_feeds(self):
        self.fetcher.fetch.side_effect = [
            MOCK_BLOCKLIST_DE,
            MOCK_EMERGING_THREATS,
            MOCK_SPAMHAUS_DROP,
            MOCK_CINSSCORE,
            MOCK_TALOS,
        ]
        result = self.feed.fetch_all()
        self.assertIsNotNone(result)
        self.assertIn("Blocklist.de", result)
        self.assertIn("Emerging Threats", result)
        self.assertIn("Spamhaus DROP", result)

    def test_fetch_all_returns_none_when_all_fail(self):
        self.fetcher.fetch.return_value = None
        result = self.feed.fetch_all()
        self.assertIsNone(result)


class TestCLIIPBlocklistArg(unittest.TestCase):
    def test_ip_blocklist_argument_accepted(self):
        from ioc_collector.cli import create_parser
        parser = create_parser()
        args = parser.parse_args(["--ip-blocklist", "blocklist_de"])
        self.assertEqual(args.ip_blocklist, "blocklist_de")

    def test_ip_blocklist_all_accepted(self):
        from ioc_collector.cli import create_parser
        parser = create_parser()
        args = parser.parse_args(["--ip-blocklist", "all"])
        self.assertEqual(args.ip_blocklist, "all")

    def test_ip_blocklist_choices(self):
        from ioc_collector.cli import create_parser
        parser = create_parser()
        for choice in ["blocklist_de", "emerging_threats", "spamhaus", "cinsscore", "talos", "all"]:
            args = parser.parse_args(["--ip-blocklist", choice])
            self.assertEqual(args.ip_blocklist, choice)


if __name__ == "__main__":
    unittest.main()
