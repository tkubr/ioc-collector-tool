"""
abuse.ch Feed Test Suite
Mock HTTP response ile tüm abuse.ch feed'lerinin parse edilmesini test eder.
"""

import unittest
from unittest.mock import MagicMock, patch
from ioc_collector.sources.abuse_ch_feeds import AbuseCHFeed
from ioc_collector.sources.remote_fetcher import RemoteFetcher


# --- Mock data ---

MOCK_URLHAUS_CSV = """# URLhaus feed
# https://urlhaus.abuse.ch
# Columns: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
"1234","2025-01-01","http://evil.com/malware.exe","online","2025-01-01","malware_download","elf","https://urlhaus.abuse.ch/url/1234/","reporter1"
"1235","2025-01-01","https://bad-domain.org/phish","online","2025-01-01","phishing","phish","https://urlhaus.abuse.ch/url/1235/","reporter2"
"1236","2025-01-01","http://192.168.1.100:8080/dropper","offline","2025-01-01","malware_download","exe","https://urlhaus.abuse.ch/url/1236/","reporter3"
"""

MOCK_MALBAZAAR_CSV = """# MalBazaar recent
# Columns: sha256_hash, md5_hash, sha1_hash, ...
"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","d41d8cd98f00b204e9800998ecf8427e","da39a3ee5e6b4b0d3255bfef95601890afd80709","2025-01-01","malware"
"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a","7215ee9c7d9dc229d2921a40e899ec5f","356a192b7913b04c54574d18c28d46e6395428ab","2025-01-01","trojan"
"""

MOCK_THREATFOX_CSV = """# ThreatFox IOC export
# Columns: date, ioc_id, ioc_value, ioc_type, threat_type, malware, ...
"2025-01-01","12345","http://evil-c2.com:4443/gate","url","botnet_cc","Emotet",""
"2025-01-01","12346","10.20.30.40:443","ip:port","botnet_cc","TrickBot",""
"2025-01-01","12347","malicious-domain.xyz","domain","payload_delivery","AgentTesla",""
"""

MOCK_FEODO_TEXT = """# Feodo Tracker Botnet C2 IP Blocklist
# https://feodotracker.abuse.ch
#
# IP address
192.168.10.1
10.0.0.50
172.16.0.100
203.0.113.42
"""

MOCK_SSLBL_CSV = """# SSL Blacklist
# Columns: listing_date, ip, port
# https://sslbl.abuse.ch
"2025-01-01","198.51.100.10","443"
"2025-01-01","203.0.113.20","8443"
"2025-01-01","192.0.2.50","443"
"""


class TestAbuseCHFeedHelpers(unittest.TestCase):
    """Yardımcı methodların testi"""

    def setUp(self):
        self.fetcher = MagicMock(spec=RemoteFetcher)
        self.feed = AbuseCHFeed(self.fetcher)

    def test_skip_comments(self):
        text = "# comment\ndata1\n# another comment\ndata2\n\n"
        result = self.feed._skip_comments(text)
        self.assertEqual(result, ["data1", "data2"])

    def test_skip_comments_empty(self):
        text = "# only comments\n# here\n"
        result = self.feed._skip_comments(text)
        self.assertEqual(result, [])

    def test_parse_csv_content(self):
        text = '# header\n"a","b","c"\n"d","e","f"\n'
        result = self.feed._parse_csv_content(text)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], ["a", "b", "c"])


class TestURLhausFeed(unittest.TestCase):
    """URLhaus feed parse testi"""

    def setUp(self):
        self.fetcher = MagicMock(spec=RemoteFetcher)
        self.feed = AbuseCHFeed(self.fetcher)

    def test_fetch_urlhaus_parses_urls(self):
        self.fetcher.fetch.return_value = MOCK_URLHAUS_CSV
        result = self.feed.fetch_urlhaus()
        self.assertIsNotNone(result)
        self.assertIn("http://evil.com/malware.exe", result)
        self.assertIn("https://bad-domain.org/phish", result)
        self.assertIn("http://192.168.1.100:8080/dropper", result)

    def test_fetch_urlhaus_returns_none_on_failure(self):
        self.fetcher.fetch.return_value = None
        result = self.feed.fetch_urlhaus()
        self.assertIsNone(result)


class TestMalBazaarFeed(unittest.TestCase):
    """MalBazaar feed parse testi"""

    def setUp(self):
        self.fetcher = MagicMock(spec=RemoteFetcher)
        self.feed = AbuseCHFeed(self.fetcher)

    def test_fetch_malbazaar_parses_hashes(self):
        self.fetcher.fetch.return_value = MOCK_MALBAZAAR_CSV
        result = self.feed.fetch_malbazaar()
        self.assertIsNotNone(result)
        # SHA256
        self.assertIn("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", result)
        # MD5
        self.assertIn("d41d8cd98f00b204e9800998ecf8427e", result)

    def test_fetch_malbazaar_returns_none_on_failure(self):
        self.fetcher.fetch.return_value = None
        result = self.feed.fetch_malbazaar()
        self.assertIsNone(result)


class TestThreatFoxFeed(unittest.TestCase):
    """ThreatFox feed parse testi"""

    def setUp(self):
        self.fetcher = MagicMock(spec=RemoteFetcher)
        self.feed = AbuseCHFeed(self.fetcher)

    def test_fetch_threatfox_parses_iocs(self):
        self.fetcher.fetch.return_value = MOCK_THREATFOX_CSV
        result = self.feed.fetch_threatfox()
        self.assertIsNotNone(result)
        self.assertIn("http://evil-c2.com:4443/gate", result)
        self.assertIn("10.20.30.40:443", result)
        self.assertIn("malicious-domain.xyz", result)

    def test_fetch_threatfox_returns_none_on_failure(self):
        self.fetcher.fetch.return_value = None
        result = self.feed.fetch_threatfox()
        self.assertIsNone(result)


class TestFeodoTrackerFeed(unittest.TestCase):
    """Feodo Tracker feed parse testi"""

    def setUp(self):
        self.fetcher = MagicMock(spec=RemoteFetcher)
        self.feed = AbuseCHFeed(self.fetcher)

    def test_fetch_feodo_parses_ips(self):
        self.fetcher.fetch.return_value = MOCK_FEODO_TEXT
        result = self.feed.fetch_feodo_tracker()
        self.assertIsNotNone(result)
        self.assertIn("192.168.10.1", result)
        self.assertIn("10.0.0.50", result)
        self.assertIn("203.0.113.42", result)
        # Yorum satırları olmamalı
        self.assertNotIn("# Feodo", result)

    def test_fetch_feodo_returns_none_on_failure(self):
        self.fetcher.fetch.return_value = None
        result = self.feed.fetch_feodo_tracker()
        self.assertIsNone(result)


class TestSSLBlacklistFeed(unittest.TestCase):
    """SSL Blacklist feed parse testi"""

    def setUp(self):
        self.fetcher = MagicMock(spec=RemoteFetcher)
        self.feed = AbuseCHFeed(self.fetcher)

    def test_fetch_ssl_blacklist_parses_ips(self):
        self.fetcher.fetch.return_value = MOCK_SSLBL_CSV
        result = self.feed.fetch_ssl_blacklist()
        self.assertIsNotNone(result)
        self.assertIn("198.51.100.10", result)
        self.assertIn("203.0.113.20", result)
        self.assertIn("192.0.2.50", result)

    def test_fetch_ssl_blacklist_returns_none_on_failure(self):
        self.fetcher.fetch.return_value = None
        result = self.feed.fetch_ssl_blacklist()
        self.assertIsNone(result)


class TestFetchAll(unittest.TestCase):
    """fetch_all() testi"""

    def setUp(self):
        self.fetcher = MagicMock(spec=RemoteFetcher)
        self.feed = AbuseCHFeed(self.fetcher)

    def test_fetch_all_combines_feeds(self):
        self.fetcher.fetch.side_effect = [
            MOCK_URLHAUS_CSV,
            MOCK_MALBAZAAR_CSV,
            MOCK_THREATFOX_CSV,
            MOCK_FEODO_TEXT,
            MOCK_SSLBL_CSV,
        ]
        result = self.feed.fetch_all()
        self.assertIsNotNone(result)
        self.assertIn("URLhaus", result)
        self.assertIn("MalBazaar", result)
        self.assertIn("ThreatFox", result)
        self.assertIn("Feodo Tracker", result)
        self.assertIn("SSL Blacklist", result)

    def test_fetch_all_returns_none_when_all_fail(self):
        self.fetcher.fetch.return_value = None
        result = self.feed.fetch_all()
        self.assertIsNone(result)


class TestCLIAbuseFeedArg(unittest.TestCase):
    """CLI --abuse-feed argüman testi"""

    def test_abuse_feed_argument_accepted(self):
        from ioc_collector.cli import create_parser
        parser = create_parser()
        args = parser.parse_args(["--abuse-feed", "urlhaus"])
        self.assertEqual(args.abuse_feed, "urlhaus")

    def test_abuse_feed_all_accepted(self):
        from ioc_collector.cli import create_parser
        parser = create_parser()
        args = parser.parse_args(["--abuse-feed", "all"])
        self.assertEqual(args.abuse_feed, "all")

    def test_abuse_feed_choices(self):
        from ioc_collector.cli import create_parser
        parser = create_parser()
        for choice in ["urlhaus", "malbazaar", "threatfox", "feodo", "sslbl", "all"]:
            args = parser.parse_args(["--abuse-feed", choice])
            self.assertEqual(args.abuse_feed, choice)


if __name__ == "__main__":
    unittest.main()
