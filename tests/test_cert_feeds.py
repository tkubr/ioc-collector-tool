"""
CERT Feed Test Suite (genişletilmiş)
RSS parse, yeni CERT methodları ve CLI argümanlarını test eder.
"""

import unittest
from unittest.mock import MagicMock
from ioc_collector.sources.cert_feeds import CERTFeed
from ioc_collector.sources.remote_fetcher import RemoteFetcher


# --- Mock RSS data ---

MOCK_RSS_FEED = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Test CERT Feed</title>
    <item>
      <title>CVE-2025-1234: Critical Vulnerability</title>
      <link>https://cert.example.com/advisory/2025-001</link>
      <description>A critical vulnerability in ExampleSoft 1.0 allows remote code execution.</description>
    </item>
    <item>
      <title>CVE-2025-5678: High Severity Issue</title>
      <link>https://cert.example.com/advisory/2025-002</link>
      <description>Buffer overflow in NetworkLib 3.2 affects 192.168.1.0/24 networks.</description>
    </item>
  </channel>
</rss>"""

MOCK_RDF_FEED = """<?xml version="1.0" encoding="UTF-8"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns="http://purl.org/rss/1.0/"
         xmlns:dc="http://purl.org/dc/elements/1.1/">
  <channel>
    <title>JPCERT Test Feed</title>
  </channel>
  <item rdf:about="https://jpcert.example.jp/alert/2025-001">
    <title>Alert on Targeted Attack</title>
    <link>https://jpcert.example.jp/alert/2025-001</link>
    <description>Targeted attack using malware.exe hash a1b2c3d4e5f6</description>
  </item>
  <item rdf:about="https://jpcert.example.jp/alert/2025-002">
    <title>Vulnerability Advisory</title>
    <link>https://jpcert.example.jp/alert/2025-002</link>
    <description>CVE-2025-9999 affects multiple products</description>
  </item>
</rdf:RDF>"""

MOCK_INVALID_XML = """This is not valid XML at all <<<<"""


class TestRSSParsing(unittest.TestCase):
    """RSS/RDF parse yardımcı method testleri"""

    def setUp(self):
        self.fetcher = MagicMock(spec=RemoteFetcher)
        self.feed = CERTFeed(self.fetcher)

    def test_parse_rss_standard(self):
        items = self.feed._parse_rss(MOCK_RSS_FEED)
        self.assertEqual(len(items), 2)
        self.assertIn("CVE-2025-1234", items[0]["title"])
        self.assertIn("https://cert.example.com/advisory/2025-001", items[0]["link"])

    def test_parse_rss_rdf_format(self):
        items = self.feed._parse_rss(MOCK_RDF_FEED)
        self.assertEqual(len(items), 2)
        self.assertIn("Targeted Attack", items[0]["title"])

    def test_parse_rss_invalid_xml(self):
        items = self.feed._parse_rss(MOCK_INVALID_XML)
        self.assertEqual(items, [])

    def test_parse_rss_empty(self):
        items = self.feed._parse_rss("<rss><channel></channel></rss>")
        self.assertEqual(items, [])

    def test_items_to_text(self):
        items = [
            {"title": "Test Title", "link": "https://example.com", "description": "Test desc"},
            {"title": "Another", "link": "https://example2.com"},
        ]
        text = self.feed._items_to_text(items)
        self.assertIn("Test Title", text)
        self.assertIn("https://example.com", text)
        self.assertIn("Another", text)


class TestExistingCERTFeeds(unittest.TestCase):
    """Mevcut TR ve US feed'lerinin hala çalıştığını doğrula"""

    def setUp(self):
        self.fetcher = MagicMock(spec=RemoteFetcher)
        self.feed = CERTFeed(self.fetcher)

    def test_fetch_tr_usom(self):
        self.fetcher.fetch.return_value = "https://evil.com\nhttps://bad.com"
        result = self.feed.fetch_tr_usom()
        self.assertIsNotNone(result)
        self.assertIn("evil.com", result)

    def test_fetch_us_cisa_kev(self):
        self.fetcher.fetch_json.return_value = {"vulnerabilities": []}
        result = self.feed.fetch_us_cisa_kev()
        self.assertIsNotNone(result)


class TestNewCERTFeeds(unittest.TestCase):
    """Yeni NL, FR, JP CERT feed testleri"""

    def setUp(self):
        self.fetcher = MagicMock(spec=RemoteFetcher)
        self.feed = CERTFeed(self.fetcher)

    def test_fetch_nl_ncsc(self):
        self.fetcher.fetch.return_value = MOCK_RSS_FEED
        result = self.feed.fetch_nl_ncsc()
        self.assertIsNotNone(result)
        self.assertIn("CVE-2025-1234", result)

    def test_fetch_nl_ncsc_returns_none_on_failure(self):
        self.fetcher.fetch.return_value = None
        result = self.feed.fetch_nl_ncsc()
        self.assertIsNone(result)

    def test_fetch_fr_cert(self):
        self.fetcher.fetch.return_value = MOCK_RSS_FEED
        result = self.feed.fetch_fr_cert()
        self.assertIsNotNone(result)
        self.assertIn("CVE-2025-5678", result)

    def test_fetch_fr_cert_returns_none_on_failure(self):
        self.fetcher.fetch.return_value = None
        result = self.feed.fetch_fr_cert()
        self.assertIsNone(result)

    def test_fetch_jp_cert(self):
        self.fetcher.fetch.return_value = MOCK_RDF_FEED
        result = self.feed.fetch_jp_cert()
        self.assertIsNotNone(result)
        self.assertIn("Targeted Attack", result)

    def test_fetch_jp_cert_returns_none_on_failure(self):
        self.fetcher.fetch.return_value = None
        result = self.feed.fetch_jp_cert()
        self.assertIsNone(result)


class TestFetchAll(unittest.TestCase):
    def setUp(self):
        self.fetcher = MagicMock(spec=RemoteFetcher)
        self.feed = CERTFeed(self.fetcher)

    def test_fetch_all_returns_none_when_all_fail(self):
        self.fetcher.fetch.return_value = None
        self.fetcher.fetch_json.return_value = None
        result = self.feed.fetch_all()
        self.assertIsNone(result)


class TestCLICertFeedArg(unittest.TestCase):
    """CLI --cert-feed genişletilmiş argüman testleri"""

    def test_cert_feed_nl(self):
        from ioc_collector.cli import create_parser
        parser = create_parser()
        args = parser.parse_args(["--cert-feed", "NL"])
        self.assertEqual(args.cert_feed, "NL")

    def test_cert_feed_fr(self):
        from ioc_collector.cli import create_parser
        parser = create_parser()
        args = parser.parse_args(["--cert-feed", "FR"])
        self.assertEqual(args.cert_feed, "FR")

    def test_cert_feed_jp(self):
        from ioc_collector.cli import create_parser
        parser = create_parser()
        args = parser.parse_args(["--cert-feed", "JP"])
        self.assertEqual(args.cert_feed, "JP")

    def test_cert_feed_all(self):
        from ioc_collector.cli import create_parser
        parser = create_parser()
        args = parser.parse_args(["--cert-feed", "all"])
        self.assertEqual(args.cert_feed, "all")

    def test_cert_feed_eu(self):
        from ioc_collector.cli import create_parser
        parser = create_parser()
        args = parser.parse_args(["--cert-feed", "EU"])
        self.assertEqual(args.cert_feed, "EU")


MOCK_CERT_EU_JSON_LIST = '[{"title": "Critical RCE Vulnerability", "url": "https://cert.europa.eu/advisory/2025-001", "summary": "CVE-2025-0001 affects EU infrastructure"}, {"title": "DDoS Campaign", "url": "https://cert.europa.eu/advisory/2025-002", "summary": "Ongoing DDoS attacks targeting EU"}]'

MOCK_CERT_EU_JSON_DICT = '{"publications": [{"title": "Ransomware Alert", "link": "https://cert.europa.eu/pub/2025-003"}, {"title": "Supply Chain Attack", "url": "https://cert.europa.eu/pub/2025-004"}]}'


class TestCERTEUFeed(unittest.TestCase):
    def setUp(self):
        self.fetcher = MagicMock(spec=RemoteFetcher)
        self.feed = CERTFeed(self.fetcher)

    def test_fetch_eu_cert_json_list(self):
        self.fetcher.fetch.return_value = MOCK_CERT_EU_JSON_LIST
        result = self.feed.fetch_eu_cert()
        self.assertIsNotNone(result)
        self.assertIn("Critical RCE Vulnerability", result)
        self.assertIn("cert.europa.eu", result)

    def test_fetch_eu_cert_json_dict(self):
        self.fetcher.fetch.return_value = MOCK_CERT_EU_JSON_DICT
        result = self.feed.fetch_eu_cert()
        self.assertIsNotNone(result)
        self.assertIn("Ransomware Alert", result)

    def test_fetch_eu_cert_rss_fallback(self):
        self.fetcher.fetch.return_value = MOCK_RSS_FEED
        result = self.feed.fetch_eu_cert()
        self.assertIsNotNone(result)
        self.assertIn("CVE-2025-1234", result)

    def test_fetch_eu_cert_returns_none_on_failure(self):
        self.fetcher.fetch.return_value = None
        result = self.feed.fetch_eu_cert()
        self.assertIsNone(result)

    def test_fetch_eu_cert_raw_text_fallback(self):
        self.fetcher.fetch.return_value = "Some raw CTI data with CVE-2025-9999"
        result = self.feed.fetch_eu_cert()
        self.assertIsNotNone(result)
        self.assertIn("CVE-2025-9999", result)


if __name__ == "__main__":
    unittest.main()
