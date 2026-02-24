"""
Markdown Report Formatter testleri (#3.1 — test_md_report.py)
"""
import unittest
from ioc_collector.formatters.md_report import format_markdown_report


class TestMDReport(unittest.TestCase):
    """Markdown rapor çıktı testleri"""

    def setUp(self):
        self.iocs = {
            "ipv4": ["8.8.8.8", "1.1.1.1"],
            "ipv6": [],
            "domains": ["evil.com"],
            "urls": ["http://evil.com/malware.exe"],
            "emails": ["attacker@evil.com"],
            "cves": ["CVE-2024-12345"],
            "mitre_techniques": ["T1071.001"],
            "hash_md5": ["d41d8cd98f00b204e9800998ecf8427e"],
            "hash_sha1": [],
            "hash_sha256": [],
            "hash_sha512": [],
        }

    def test_contains_title(self):
        """Raporda başlık olmalı"""
        out = format_markdown_report("test.txt", self.iocs, 7, "High")
        self.assertIn("Threat Intelligence Report", out)

    def test_contains_source(self):
        """Raporda kaynak bilgisi olmalı"""
        out = format_markdown_report("test.txt", self.iocs, 7, "High")
        self.assertIn("test.txt", out)

    def test_contains_confidence(self):
        """Raporda confidence bilgisi olmalı"""
        out = format_markdown_report("test.txt", self.iocs, 7, "High")
        self.assertIn("High", out)

    def test_contains_ioc_count(self):
        """Raporda toplam IOC sayısı olmalı"""
        out = format_markdown_report("test.txt", self.iocs, 7, "High")
        self.assertIn("7", out)

    def test_contains_ipv4_section(self):
        """Raporda IPv4 bölümü olmalı"""
        out = format_markdown_report("test.txt", self.iocs, 7, "High")
        self.assertIn("8.8.8.8", out)

    def test_contains_cve(self):
        """Raporda CVE bilgisi olmalı"""
        out = format_markdown_report("test.txt", self.iocs, 7, "High")
        self.assertIn("CVE-2024-12345", out)

    def test_contains_date(self):
        """Raporda tarih bilgisi olmalı"""
        out = format_markdown_report("test.txt", self.iocs, 7, "High")
        # UTC tarih formatı arayalım
        self.assertIn("202", out)  # 2024, 2025, 2026...

    def test_empty_iocs(self):
        """Boş IOC listesiyle rapor üretebilmeli"""
        empty = {
            "ipv4": [], "ipv6": [], "domains": [], "urls": [],
            "emails": [], "cves": [], "mitre_techniques": [],
            "hash_md5": [], "hash_sha1": [], "hash_sha256": [], "hash_sha512": [],
        }
        out = format_markdown_report("empty.txt", empty, 0, "Low")
        self.assertIn("Threat Intelligence Report", out)

    def test_markdown_format(self):
        """Rapor Markdown formatında olmalı (# başlık)"""
        out = format_markdown_report("test.txt", self.iocs, 7, "High")
        self.assertTrue(out.startswith("#"))


class TestTextFormatter(unittest.TestCase):
    """Plain text formatter testleri"""

    def setUp(self):
        self.iocs = {
            "ipv4": ["8.8.8.8"],
            "domains": ["evil.com"],
            "hash_md5": ["d41d8cd98f00b204e9800998ecf8427e"],
        }

    def test_contains_header(self):
        from ioc_collector.formatters.text_formatter import format_text
        out = format_text(self.iocs, source="test")
        self.assertIn("IOC Extraction Report", out)

    def test_contains_source(self):
        from ioc_collector.formatters.text_formatter import format_text
        out = format_text(self.iocs, source="test.txt")
        self.assertIn("test.txt", out)

    def test_contains_ip(self):
        from ioc_collector.formatters.text_formatter import format_text
        out = format_text(self.iocs, source="test")
        self.assertIn("8.8.8.8", out)

    def test_total_count(self):
        from ioc_collector.formatters.text_formatter import format_text
        out = format_text(self.iocs, source="test")
        self.assertIn("Total IOCs:", out)


class TestSTIXFormatter(unittest.TestCase):
    """STIX 2.1 formatter testleri"""

    def setUp(self):
        self.iocs = {
            "ipv4": ["8.8.8.8"],
            "domains": ["evil.com"],
            "hash_sha256": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
        }

    def test_bundle_structure(self):
        import json
        from ioc_collector.formatters.stix_formatter import format_stix_bundle
        out = format_stix_bundle(self.iocs)
        data = json.loads(out)
        self.assertEqual(data["type"], "bundle")
        self.assertIn("objects", data)
        self.assertGreater(len(data["objects"]), 0)

    def test_indicator_type(self):
        import json
        from ioc_collector.formatters.stix_formatter import format_stix_bundle
        out = format_stix_bundle(self.iocs)
        data = json.loads(out)
        for obj in data["objects"]:
            self.assertEqual(obj["type"], "indicator")
            self.assertEqual(obj["spec_version"], "2.1")

    def test_stix_pattern(self):
        import json
        from ioc_collector.formatters.stix_formatter import format_stix_bundle
        out = format_stix_bundle(self.iocs)
        data = json.loads(out)
        patterns = [obj["pattern"] for obj in data["objects"]]
        ip_patterns = [p for p in patterns if "ipv4" in p]
        self.assertTrue(len(ip_patterns) > 0)
        self.assertIn("8.8.8.8", ip_patterns[0])

    def test_tlp_marking(self):
        import json
        from ioc_collector.formatters.stix_formatter import format_stix_bundle
        out = format_stix_bundle(self.iocs, tlp="TLP:RED")
        data = json.loads(out)
        for obj in data["objects"]:
            self.assertIn("object_marking_refs", obj)


if __name__ == "__main__":
    unittest.main()
