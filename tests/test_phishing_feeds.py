"""
Phishing Feed Test Suite
Mock HTTP response ile phishing ve C2 feed'lerinin parse edilmesini test eder.
"""

import unittest
from unittest.mock import MagicMock
from ioc_collector.sources.phishing_feeds import PhishingFeed
from ioc_collector.sources.remote_fetcher import RemoteFetcher


# --- Mock data ---

MOCK_OPENPHISH = """https://phishing-example.com/login
https://fakepaypal.example.org/verify
http://evil-bank.net/update
https://scam-site.xyz/account
"""

MOCK_BAMBENEK_C2 = """# Bambenek C2 Domain Master List
# Updated: 2025-01-01
evil-c2-server.com,192.168.1.1,Emotet,2025-01-01
bad-botnet.net,10.0.0.50,TrickBot,2025-01-01
malware-control.org,203.0.113.42,Dridex,2025-01-01
"""


class TestPhishingFeedHelpers(unittest.TestCase):
    def setUp(self):
        self.fetcher = MagicMock(spec=RemoteFetcher)
        self.feed = PhishingFeed(self.fetcher)

    def test_parse_text_list_skips_comments(self):
        text = "# comment\nline1\n# another\nline2\n\n"
        result = self.feed._parse_text_list(text)
        self.assertEqual(result, ["line1", "line2"])

    def test_parse_text_list_empty(self):
        result = self.feed._parse_text_list("# only comments\n")
        self.assertEqual(result, [])


class TestOpenPhishFeed(unittest.TestCase):
    def setUp(self):
        self.fetcher = MagicMock(spec=RemoteFetcher)
        self.feed = PhishingFeed(self.fetcher)

    def test_fetch_parses_urls(self):
        self.fetcher.fetch.return_value = MOCK_OPENPHISH
        result = self.feed.fetch_openphish()
        self.assertIsNotNone(result)
        self.assertIn("https://phishing-example.com/login", result)
        self.assertIn("https://fakepaypal.example.org/verify", result)
        self.assertIn("http://evil-bank.net/update", result)

    def test_fetch_returns_none_on_failure(self):
        self.fetcher.fetch.return_value = None
        result = self.feed.fetch_openphish()
        self.assertIsNone(result)


class TestBambenekC2Feed(unittest.TestCase):
    def setUp(self):
        self.fetcher = MagicMock(spec=RemoteFetcher)
        self.feed = PhishingFeed(self.fetcher)

    def test_fetch_parses_domains(self):
        self.fetcher.fetch.return_value = MOCK_BAMBENEK_C2
        result = self.feed.fetch_bambenek_c2()
        self.assertIsNotNone(result)
        self.assertIn("evil-c2-server.com", result)
        self.assertIn("bad-botnet.net", result)
        self.assertIn("malware-control.org", result)
        # IP adresleri domain olarak çıkmamalı
        self.assertNotIn("192.168.1.1", result)

    def test_fetch_returns_none_on_failure(self):
        self.fetcher.fetch.return_value = None
        result = self.feed.fetch_bambenek_c2()
        self.assertIsNone(result)


MOCK_PHISHTANK = """phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target
1234,https://phishing-bank.example.com/login,https://phishtank.com/1234,2025-01-01,yes,2025-01-01,yes,ExampleBank
5678,https://fake-paypal.example.net/verify,https://phishtank.com/5678,2025-01-01,yes,2025-01-01,yes,PayPal
"""

MOCK_CYBERCRIME = """http://c2panel1.example.com/gate.php
http://c2panel2.example.net/admin/
http://botnet-control.example.org/cmd
"""


class TestPhishTankFeed(unittest.TestCase):
    def setUp(self):
        self.fetcher = MagicMock(spec=RemoteFetcher)
        self.feed = PhishingFeed(self.fetcher)

    def test_fetch_parses_urls(self):
        self.fetcher.fetch.return_value = MOCK_PHISHTANK
        result = self.feed.fetch_phishtank()
        self.assertIsNotNone(result)
        self.assertIn("https://phishing-bank.example.com/login", result)
        self.assertIn("https://fake-paypal.example.net/verify", result)

    def test_fetch_returns_none_on_failure(self):
        self.fetcher.fetch.return_value = None
        result = self.feed.fetch_phishtank()
        self.assertIsNone(result)


class TestCyberCrimeTrackerFeed(unittest.TestCase):
    def setUp(self):
        self.fetcher = MagicMock(spec=RemoteFetcher)
        self.feed = PhishingFeed(self.fetcher)

    def test_fetch_parses_urls(self):
        self.fetcher.fetch.return_value = MOCK_CYBERCRIME
        result = self.feed.fetch_cybercrime_tracker()
        self.assertIsNotNone(result)
        self.assertIn("http://c2panel1.example.com/gate.php", result)
        self.assertIn("http://botnet-control.example.org/cmd", result)

    def test_fetch_returns_none_on_failure(self):
        self.fetcher.fetch.return_value = None
        result = self.feed.fetch_cybercrime_tracker()
        self.assertIsNone(result)


class TestFetchAll(unittest.TestCase):
    def setUp(self):
        self.fetcher = MagicMock(spec=RemoteFetcher)
        self.feed = PhishingFeed(self.fetcher)

    def test_fetch_all_combines_feeds(self):
        self.fetcher.fetch.side_effect = [
            MOCK_OPENPHISH,
            MOCK_BAMBENEK_C2,
            MOCK_PHISHTANK,
            MOCK_CYBERCRIME,
        ]
        result = self.feed.fetch_all()
        self.assertIsNotNone(result)
        self.assertIn("OpenPhish", result)
        self.assertIn("Bambenek C2", result)
        self.assertIn("PhishTank", result)
        self.assertIn("CyberCrime Tracker", result)

    def test_fetch_all_returns_none_when_all_fail(self):
        self.fetcher.fetch.return_value = None
        result = self.feed.fetch_all()
        self.assertIsNone(result)


class TestCLIPhishingFeedArg(unittest.TestCase):
    def test_phishing_feed_argument_accepted(self):
        from ioc_collector.cli import create_parser
        parser = create_parser()
        args = parser.parse_args(["--phishing-feed", "openphish"])
        self.assertEqual(args.phishing_feed, "openphish")

    def test_phishing_feed_all_accepted(self):
        from ioc_collector.cli import create_parser
        parser = create_parser()
        args = parser.parse_args(["--phishing-feed", "all"])
        self.assertEqual(args.phishing_feed, "all")

    def test_phishing_feed_choices(self):
        from ioc_collector.cli import create_parser
        parser = create_parser()
        for choice in ["openphish", "bambenek", "phishtank", "cybercrime", "all"]:
            args = parser.parse_args(["--phishing-feed", choice])
            self.assertEqual(args.phishing_feed, choice)


if __name__ == "__main__":
    unittest.main()
