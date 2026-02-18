"""
CLI Argüman Parse Test Suite (#3.1)
CLI giriş noktası ve argüman doğrulama testleri.
"""
import unittest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ioc_collector.cli import create_parser, flatten_for_export, filter_ioc_types


class TestCLIParser(unittest.TestCase):
    """CLI argüman parse testleri"""

    def test_file_argument(self):
        parser = create_parser()
        args = parser.parse_args(["-f", "test.txt"])
        self.assertEqual(args.file, ["test.txt"])

    def test_multiple_files(self):
        parser = create_parser()
        args = parser.parse_args(["-f", "a.txt", "b.txt"])
        self.assertEqual(args.file, ["a.txt", "b.txt"])

    def test_refang_flag(self):
        parser = create_parser()
        args = parser.parse_args(["-f", "test.txt", "--refang"])
        self.assertTrue(args.refang)

    def test_unique_flag(self):
        parser = create_parser()
        args = parser.parse_args(["-f", "test.txt", "--unique"])
        self.assertTrue(args.unique)

    def test_export_csv(self):
        parser = create_parser()
        args = parser.parse_args(["-f", "test.txt", "--export-csv", "out.csv"])
        self.assertEqual(args.export_csv, "out.csv")

    def test_export_json(self):
        parser = create_parser()
        args = parser.parse_args(["-f", "test.txt", "--export-json", "out.json"])
        self.assertEqual(args.export_json, "out.json")

    def test_export_md(self):
        parser = create_parser()
        args = parser.parse_args(["-f", "test.txt", "--export-md", "report.md"])
        self.assertEqual(args.export_md, "report.md")

    def test_url_argument(self):
        parser = create_parser()
        args = parser.parse_args(["-u", "https://example.com"])
        self.assertEqual(args.url, "https://example.com")

    def test_cert_feed(self):
        parser = create_parser()
        args = parser.parse_args(["--cert-feed", "TR"])
        self.assertEqual(args.cert_feed, "TR")

    def test_defang_output(self):
        parser = create_parser()
        args = parser.parse_args(["-f", "test.txt", "--defang-output"])
        self.assertTrue(args.defang_output)

    def test_confidence_choices(self):
        parser = create_parser()
        args = parser.parse_args(["-f", "test.txt", "--confidence", "Low"])
        self.assertEqual(args.confidence, "Low")

    def test_verbose_flag(self):
        parser = create_parser()
        args = parser.parse_args(["-f", "test.txt", "-v"])
        self.assertTrue(args.verbose)

    def test_types_filter(self):
        parser = create_parser()
        args = parser.parse_args(["-f", "test.txt", "--types", "ip,hash"])
        self.assertEqual(args.types, "ip,hash")


class TestFlattenForExport(unittest.TestCase):
    """flatten_for_export fonksiyonu testleri"""

    def test_basic_flatten(self):
        iocs = {
            "ipv4": ["1.1.1.1"],
            "domains": ["evil.com"],
        }
        rows = flatten_for_export(iocs, "test", "High")
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["type"], "ipv4")
        self.assertEqual(rows[0]["value"], "1.1.1.1")

    def test_empty_iocs(self):
        iocs = {}
        rows = flatten_for_export(iocs, "test", "High")
        self.assertEqual(len(rows), 0)


class TestFilterIOCTypes(unittest.TestCase):
    """IOC tür filtreleme testleri"""

    def test_filter_ip_only(self):
        iocs = {
            "ipv4": ["1.1.1.1"],
            "domains": ["evil.com"],
            "cves": ["CVE-2024-1234"],
            "metadata": {"extracted_at": "2024-01-01"},
        }
        filtered = filter_ioc_types(iocs, "ip")
        self.assertEqual(filtered["ipv4"], ["1.1.1.1"])
        self.assertEqual(filtered["domains"], [])
        self.assertEqual(filtered["cves"], [])

    def test_filter_multiple_types(self):
        iocs = {
            "ipv4": ["1.1.1.1"],
            "domains": ["evil.com"],
            "hash_md5": ["abc123"],
            "metadata": {},
        }
        filtered = filter_ioc_types(iocs, "ip,hash")
        self.assertEqual(filtered["ipv4"], ["1.1.1.1"])
        self.assertEqual(filtered["hash_md5"], ["abc123"])
        self.assertEqual(filtered["domains"], [])


if __name__ == "__main__":
    unittest.main()
