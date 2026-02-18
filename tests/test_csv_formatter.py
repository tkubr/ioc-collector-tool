"""
CSV Formatter Test Suite (#3.1)
CSV çıktı format doğrulama testleri.
"""
import unittest
import csv
from io import StringIO
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ioc_collector.formatters.csv_formatter import format_csv


class TestCSVFormatter(unittest.TestCase):
    """CSV formatter testleri"""

    def test_basic_output(self):
        rows = [
            {"type": "ipv4", "value": "8.8.8.8", "confidence": "High", "source": "test", "note": "Test IP"},
        ]
        result = format_csv(rows)
        self.assertIn("type,value,confidence,source,note", result)
        self.assertIn("8.8.8.8", result)

    def test_header_present(self):
        rows = []
        result = format_csv(rows)
        self.assertIn("type,value,confidence,source,note", result)

    def test_multiple_rows(self):
        rows = [
            {"type": "ipv4", "value": "1.1.1.1", "confidence": "High", "source": "test", "note": "IP1"},
            {"type": "domain", "value": "evil.com", "confidence": "Medium", "source": "test", "note": "Domain1"},
        ]
        result = format_csv(rows)
        reader = csv.DictReader(StringIO(result))
        parsed_rows = list(reader)
        self.assertEqual(len(parsed_rows), 2)
        self.assertEqual(parsed_rows[0]["value"], "1.1.1.1")
        self.assertEqual(parsed_rows[1]["value"], "evil.com")

    def test_empty_rows(self):
        result = format_csv([])
        lines = result.strip().split("\n")
        self.assertEqual(len(lines), 1)  # Sadece header

    def test_csv_parseable(self):
        """Üretilen CSV standart parser ile okunabilmeli"""
        rows = [
            {"type": "url", "value": "http://evil.com/path?a=1&b=2", "confidence": "High", "source": "test", "note": "URL with params"},
        ]
        result = format_csv(rows)
        reader = csv.DictReader(StringIO(result))
        parsed = list(reader)
        self.assertEqual(parsed[0]["value"], "http://evil.com/path?a=1&b=2")


if __name__ == "__main__":
    unittest.main()
