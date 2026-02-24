"""
OTX AlienVault Enrichment Test Suite
Mock HTTP response ile OTX API sorgu ve zenginleştirme testleri.
"""

import unittest
from unittest.mock import patch, MagicMock
from ioc_collector.utils.enrichment import OTXEnrichment


class TestOTXEnrichmentInit(unittest.TestCase):
    def test_init_with_key(self):
        otx = OTXEnrichment(api_key="test-key-123")
        self.assertTrue(otx.is_configured())
        self.assertEqual(otx.api_key, "test-key-123")

    def test_init_without_key(self):
        with patch.dict("os.environ", {}, clear=True):
            otx = OTXEnrichment()
            self.assertFalse(otx.is_configured())

    @patch.dict("os.environ", {"OTX_API_KEY": "env-key-456"})
    def test_init_from_env(self):
        otx = OTXEnrichment()
        self.assertTrue(otx.is_configured())
        self.assertEqual(otx.api_key, "env-key-456")


class TestOTXCheckIP(unittest.TestCase):
    def setUp(self):
        self.otx = OTXEnrichment(api_key="test-key")

    def test_check_ip_returns_none_without_key(self):
        otx = OTXEnrichment(api_key="")
        result = otx.check_ip("1.2.3.4")
        self.assertIsNone(result)

    @patch("requests.get")
    def test_check_ip_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "pulse_info": {"count": 5},
            "reputation": 3,
            "country_code": "US",
            "asn": "AS12345",
        }
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        result = self.otx.check_ip("8.8.8.8")
        self.assertIsNotNone(result)
        self.assertEqual(result["ip"], "8.8.8.8")
        self.assertEqual(result["pulse_count"], 5)
        self.assertEqual(result["country"], "US")

    @patch("requests.get", side_effect=Exception("API Error"))
    def test_check_ip_error(self, mock_get):
        result = self.otx.check_ip("8.8.8.8")
        self.assertIsNone(result)


class TestOTXCheckDomain(unittest.TestCase):
    def setUp(self):
        self.otx = OTXEnrichment(api_key="test-key")

    @patch("requests.get")
    def test_check_domain_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "pulse_info": {"count": 10},
            "alexa": "500",
            "whois": "Registrar: Example Inc" * 5,
        }
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        result = self.otx.check_domain("evil.com")
        self.assertIsNotNone(result)
        self.assertEqual(result["domain"], "evil.com")
        self.assertEqual(result["pulse_count"], 10)


class TestOTXCheckHash(unittest.TestCase):
    def setUp(self):
        self.otx = OTXEnrichment(api_key="test-key")

    @patch("requests.get")
    def test_check_hash_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "pulse_info": {"count": 2},
        }
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        result = self.otx.check_hash("a" * 64)
        self.assertIsNotNone(result)
        self.assertEqual(result["hash"], "a" * 64)
        self.assertEqual(result["pulse_count"], 2)


class TestOTXEnrichIOCs(unittest.TestCase):
    def setUp(self):
        self.otx = OTXEnrichment(api_key="test-key")

    @patch("requests.get")
    def test_enrich_iocs(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "pulse_info": {"count": 1},
            "reputation": 0,
            "country_code": "DE",
            "asn": "AS99",
        }
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        iocs = {
            "ipv4": ["1.2.3.4", "5.6.7.8"],
            "domains": ["evil.com"],
            "hash_sha256": [],
        }
        result = self.otx.enrich_iocs(iocs, max_lookups=5)
        self.assertIsInstance(result, dict)
        self.assertGreater(len(result), 0)


class TestCLIOTXArg(unittest.TestCase):
    def test_enrich_otx_argument(self):
        from ioc_collector.cli import create_parser
        parser = create_parser()
        args = parser.parse_args(["--enrich-otx", "-f", "test.txt"])
        self.assertTrue(args.enrich_otx)

    def test_enrich_otx_not_set(self):
        from ioc_collector.cli import create_parser
        parser = create_parser()
        args = parser.parse_args(["-f", "test.txt"])
        self.assertFalse(args.enrich_otx)


if __name__ == "__main__":
    unittest.main()
