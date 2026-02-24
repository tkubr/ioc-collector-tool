"""
Enrichment API Test Suite (AbuseIPDB, Shodan, GreyNoise)
Mock HTTP response ile API sorgu ve zenginleştirme testleri.
"""

import unittest
from unittest.mock import patch, MagicMock
from ioc_collector.utils.enrichment import (
    AbuseIPDBEnrichment,
    ShodanEnrichment,
    GreyNoiseEnrichment,
)


# ─── AbuseIPDB Tests ─────────────────────────────────────────

class TestAbuseIPDBInit(unittest.TestCase):
    def test_init_with_key(self):
        e = AbuseIPDBEnrichment(api_key="test-key")
        self.assertTrue(e.is_configured())

    def test_init_without_key(self):
        with patch.dict("os.environ", {}, clear=True):
            e = AbuseIPDBEnrichment()
            self.assertFalse(e.is_configured())

    @patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "env-key"})
    def test_init_from_env(self):
        e = AbuseIPDBEnrichment()
        self.assertTrue(e.is_configured())


class TestAbuseIPDBCheck(unittest.TestCase):
    def setUp(self):
        self.e = AbuseIPDBEnrichment(api_key="test-key")

    def test_check_ip_no_key(self):
        e = AbuseIPDBEnrichment(api_key="")
        self.assertIsNone(e.check_ip("1.2.3.4"))

    @patch("requests.get")
    def test_check_ip_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": {
                "abuseConfidenceScore": 85,
                "totalReports": 42,
                "countryCode": "CN",
                "isp": "Evil ISP",
                "usageType": "Data Center",
                "isPublic": True,
            }
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = self.e.check_ip("1.2.3.4")
        self.assertIsNotNone(result)
        self.assertEqual(result["abuse_confidence_score"], 85)
        self.assertEqual(result["country_code"], "CN")

    @patch("requests.get", side_effect=Exception("API Error"))
    def test_check_ip_error(self, mock_get):
        self.assertIsNone(self.e.check_ip("1.2.3.4"))

    @patch("requests.get")
    def test_enrich_iocs(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"data": {"abuseConfidenceScore": 50, "totalReports": 10, "countryCode": "US"}}
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        iocs = {"ipv4": ["1.1.1.1", "2.2.2.2"]}
        result = self.e.enrich_iocs(iocs, max_lookups=5)
        self.assertIsInstance(result, dict)
        self.assertGreater(len(result), 0)


# ─── Shodan Tests ─────────────────────────────────────────────

class TestShodanInit(unittest.TestCase):
    def test_init_with_key(self):
        e = ShodanEnrichment(api_key="test-key")
        self.assertTrue(e.is_configured())

    def test_init_without_key(self):
        with patch.dict("os.environ", {}, clear=True):
            e = ShodanEnrichment()
            self.assertFalse(e.is_configured())


class TestShodanCheck(unittest.TestCase):
    def setUp(self):
        self.e = ShodanEnrichment(api_key="test-key")

    @patch("requests.get")
    def test_check_ip_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "ports": [80, 443, 22],
            "os": "Linux",
            "country_code": "DE",
            "org": "Hetzner",
            "isp": "Hetzner Online",
            "vulns": ["CVE-2021-44228"],
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = self.e.check_ip("8.8.8.8")
        self.assertIsNotNone(result)
        self.assertEqual(result["ports"], [80, 443, 22])
        self.assertEqual(result["country_code"], "DE")
        self.assertIn("CVE-2021-44228", result["vulns"])

    @patch("requests.get", side_effect=Exception("API Error"))
    def test_check_ip_error(self, mock_get):
        self.assertIsNone(self.e.check_ip("8.8.8.8"))

    def test_check_ip_no_key(self):
        e = ShodanEnrichment(api_key="")
        self.assertIsNone(e.check_ip("1.2.3.4"))


# ─── GreyNoise Tests ─────────────────────────────────────────

class TestGreyNoiseInit(unittest.TestCase):
    def test_init_with_key(self):
        e = GreyNoiseEnrichment(api_key="test-key")
        self.assertTrue(e.is_configured())

    def test_init_without_key(self):
        with patch.dict("os.environ", {}, clear=True):
            e = GreyNoiseEnrichment()
            self.assertFalse(e.is_configured())


class TestGreyNoiseCheck(unittest.TestCase):
    def setUp(self):
        self.e = GreyNoiseEnrichment(api_key="test-key")

    @patch("requests.get")
    def test_check_ip_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "noise": True,
            "riot": False,
            "classification": "malicious",
            "name": "ZMap Client",
            "link": "https://viz.greynoise.io/ip/1.2.3.4",
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = self.e.check_ip("1.2.3.4")
        self.assertIsNotNone(result)
        self.assertTrue(result["noise"])
        self.assertEqual(result["classification"], "malicious")

    @patch("requests.get", side_effect=Exception("API Error"))
    def test_check_ip_error(self, mock_get):
        self.assertIsNone(self.e.check_ip("1.2.3.4"))


class TestCLIEnrichmentArgs(unittest.TestCase):
    def test_enrich_abuseipdb_argument(self):
        from ioc_collector.cli import create_parser
        parser = create_parser()
        args = parser.parse_args(["--enrich-abuseipdb", "-f", "test.txt"])
        self.assertTrue(args.enrich_abuseipdb)

    def test_enrich_shodan_argument(self):
        from ioc_collector.cli import create_parser
        parser = create_parser()
        args = parser.parse_args(["--enrich-shodan", "-f", "test.txt"])
        self.assertTrue(args.enrich_shodan)

    def test_enrich_greynoise_argument(self):
        from ioc_collector.cli import create_parser
        parser = create_parser()
        args = parser.parse_args(["--enrich-greynoise", "-f", "test.txt"])
        self.assertTrue(args.enrich_greynoise)


if __name__ == "__main__":
    unittest.main()
