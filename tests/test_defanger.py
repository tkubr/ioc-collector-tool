"""
Defanger/Refanger Test Suite (#3.1)
Defang ve refang dönüşüm testleri.
"""
import unittest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ioc_collector.utils.defanger import refang, defang


class TestRefang(unittest.TestCase):
    """Refang (etkisizleştirilmiş → normal) testleri"""

    def test_refang_hxxp(self):
        self.assertEqual(refang("hxxp://evil.com"), "http://evil.com")

    def test_refang_hxxps(self):
        self.assertEqual(refang("hxxps://evil.com"), "https://evil.com")

    def test_refang_bracket_dot(self):
        self.assertEqual(refang("evil[.]com"), "evil.com")

    def test_refang_paren_dot(self):
        self.assertEqual(refang("evil(.)com"), "evil.com")

    def test_refang_bracket_at(self):
        self.assertEqual(refang("user[@]evil.com"), "user@evil.com")

    def test_refang_at_text(self):
        self.assertEqual(refang("user[at]evil.com"), "user@evil.com")

    def test_refang_dot_text(self):
        self.assertEqual(refang("evil[dot]com"), "evil.com")

    def test_refang_complex(self):
        """Birden fazla defang pattern'ı aynı anda"""
        text = "hxxps://evil[.]com/path"
        expected = "https://evil.com/path"
        self.assertEqual(refang(text), expected)

    def test_refang_email(self):
        text = "attacker[@]evil[.]com"
        expected = "attacker@evil.com"
        self.assertEqual(refang(text), expected)

    def test_refang_no_change(self):
        """Zaten normal olan text değişmemeli"""
        text = "https://example.com"
        self.assertEqual(refang(text), text)


class TestDefang(unittest.TestCase):
    """Defang (normal → etkisizleştirilmiş) testleri"""

    def test_defang_http(self):
        result = defang("http://evil.com")
        self.assertIn("hxxp", result)

    def test_defang_https(self):
        result = defang("https://evil.com")
        self.assertIn("hxxps", result)

    def test_defang_ip(self):
        result = defang("192.168.1.1")
        self.assertIn("[.]", result)

    def test_defang_email(self):
        result = defang("user@evil.com")
        self.assertIn("[@]", result)

    def test_defang_domain(self):
        result = defang("evil.com")
        self.assertIn("[.]", result)


class TestRoundTrip(unittest.TestCase):
    """Refang → Defang → Refang round trip testleri"""

    def test_ip_roundtrip(self):
        original = "8.8.8.8"
        defanged = defang(original)
        self.assertNotEqual(defanged, original)
        refanged = refang(defanged)
        self.assertEqual(refanged, original)

    def test_domain_roundtrip(self):
        original = "evil.com"
        defanged = defang(original)
        self.assertNotEqual(defanged, original)
        refanged = refang(defanged)
        self.assertEqual(refanged, original)


if __name__ == "__main__":
    unittest.main()
