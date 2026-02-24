"""
IOC Regex Extractor Test Suite (#3.1)
Her IOC tipi için pozitif ve negatif test case'ler.
"""
import unittest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ioc_collector.extractors.regex_extractor import (
    extract_iocs, validate_ipv4, validate_ipv6, validate_domain, extract_hashes
)


class TestIPv4Extraction(unittest.TestCase):
    """IPv4 çıkarma ve doğrulama testleri (#1.1)"""

    def test_valid_public_ip(self):
        text = "Saldırgan IP: 8.8.8.8"
        result = extract_iocs(text)
        self.assertIn("8.8.8.8", result["ipv4"])

    def test_invalid_ip_999(self):
        """999.999.999.999 gibi geçersiz IP'ler yakalanmamalı (#1.1)"""
        text = "Invalid: 999.999.999.999"
        result = extract_iocs(text)
        self.assertNotIn("999.999.999.999", result["ipv4"])

    def test_invalid_ip_256(self):
        text = "Invalid: 256.1.1.1"
        result = extract_iocs(text)
        self.assertNotIn("256.1.1.1", result["ipv4"])

    def test_multiple_ips(self):
        text = "IPs: 1.1.1.1, 8.8.8.8, 9.9.9.9"
        result = extract_iocs(text)
        self.assertEqual(len(result["ipv4"]), 3)

    def test_private_ip_still_detected(self):
        """Private IP'ler de tespit edilmeli (filtreleme opsiyonel)"""
        text = "Private: 192.168.1.1"
        result = extract_iocs(text)
        self.assertIn("192.168.1.1", result["ipv4"])

    def test_validate_ipv4_valid(self):
        self.assertTrue(validate_ipv4("1.2.3.4"))
        self.assertTrue(validate_ipv4("255.255.255.255"))
        self.assertTrue(validate_ipv4("0.0.0.0"))

    def test_validate_ipv4_invalid(self):
        self.assertFalse(validate_ipv4("999.999.999.999"))
        self.assertFalse(validate_ipv4("256.0.0.1"))
        self.assertFalse(validate_ipv4("abc.def.ghi.jkl"))


class TestIPv6Extraction(unittest.TestCase):
    """IPv6 çıkarma testleri (#6.1)"""

    def test_full_ipv6(self):
        text = "IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        result = extract_iocs(text)
        self.assertIn("2001:0db8:85a3:0000:0000:8a2e:0370:7334", result["ipv6"])

    def test_validate_ipv6(self):
        self.assertTrue(validate_ipv6("2001:db8::1"))
        self.assertTrue(validate_ipv6("::1"))
        self.assertFalse(validate_ipv6("not-an-ipv6"))


class TestDomainExtraction(unittest.TestCase):
    """Domain çıkarma ve false positive testleri (#1.3)"""

    def test_valid_domain(self):
        text = "Malicious domain: evil.com"
        result = extract_iocs(text)
        self.assertIn("evil.com", result["domains"])

    def test_valid_subdomain(self):
        text = "C2 server: c2.malware.example.org"
        result = extract_iocs(text)
        self.assertIn("c2.malware.example.org", [d for d in result["domains"] if "malware" in d] or result["domains"])

    def test_file_extension_not_domain(self):
        """file.exe domain olarak yakalanmamalı (#1.3)"""
        text = "Dosya adı: malware_payload.exe"
        result = extract_iocs(text)
        for d in result["domains"]:
            self.assertFalse(d.endswith(".exe"), f"file.exe domain olarak yakalandı: {d}")

    def test_version_number_not_domain(self):
        """Python.3 gibi versiyon numaraları domain olmamalı (#1.3)"""
        text = "Python.3 is the latest version"
        result = extract_iocs(text)
        # "Python.3" gibi, TLD'si geçersiz olan string domain olmamalı
        for d in result["domains"]:
            self.assertNotEqual(d, "python.3")

    def test_reserved_domain_filtered(self):
        text = "Test: example.com"
        result = extract_iocs(text)
        self.assertNotIn("example.com", result["domains"])


class TestURLExtraction(unittest.TestCase):
    """URL çıkarma testleri"""

    def test_http_url(self):
        text = "Payload: http://evil.com/malware.exe"
        result = extract_iocs(text)
        self.assertIn("http://evil.com/malware.exe", result["urls"])

    def test_https_url(self):
        text = "C2: https://c2server.com/beacon"
        result = extract_iocs(text)
        self.assertIn("https://c2server.com/beacon", result["urls"])

    def test_defanged_url_refang(self):
        text = "URL: hxxp://evil[.]com/payload.exe"
        result = extract_iocs(text, do_refang=True)
        self.assertTrue(any("evil.com" in u for u in result["urls"]))


class TestEmailExtraction(unittest.TestCase):
    """Email çıkarma testleri"""

    def test_normal_email(self):
        text = "Contact: attacker@evil.com"
        result = extract_iocs(text)
        self.assertIn("attacker@evil.com", result["emails"])

    def test_defanged_email(self):
        text = "Email: attacker[@]evil[.]com"
        result = extract_iocs(text, do_refang=True)
        self.assertIn("attacker@evil.com", result["emails"])


class TestHashExtraction(unittest.TestCase):
    """Hash çıkarma ve çakışma testleri (#1.2)"""

    def test_md5(self):
        text = "MD5: d41d8cd98f00b204e9800998ecf8427e"
        result = extract_iocs(text)
        self.assertIn("d41d8cd98f00b204e9800998ecf8427e", result["hash_md5"])

    def test_sha256(self):
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        text = f"SHA256: {sha256}"
        result = extract_iocs(text)
        self.assertIn(sha256, result["hash_sha256"])

    def test_hash_collision_prevention(self):
        """SHA256 hash'i MD5 veya SHA1 olarak yakalanmamalı (#1.2)"""
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        text = f"Only one hash: {sha256}"
        result = extract_iocs(text)
        self.assertIn(sha256, result["hash_sha256"])
        # SHA256'nın alt-stringleri MD5/SHA1'de olmamalı
        self.assertEqual(len(result["hash_md5"]), 0,
                         f"SHA256'nın parçası MD5 olarak yakalandı: {result['hash_md5']}")
        self.assertEqual(len(result["hash_sha1"]), 0,
                         f"SHA256'nın parçası SHA1 olarak yakalandı: {result['hash_sha1']}")


class TestCVEExtraction(unittest.TestCase):
    """CVE çıkarma testleri"""

    def test_standard_cve(self):
        text = "Vulnerability: CVE-2024-12345"
        result = extract_iocs(text)
        self.assertIn("CVE-2024-12345", result["cves"])

    def test_case_insensitive_cve(self):
        text = "cve-2023-9999"
        result = extract_iocs(text)
        self.assertTrue(len(result["cves"]) > 0)


class TestMITREExtraction(unittest.TestCase):
    """MITRE ATT&CK çıkarma testleri (#1.4)"""

    def test_valid_technique(self):
        text = "Technique: T1071.001"
        result = extract_iocs(text)
        self.assertIn("T1071.001", result["mitre_techniques"])

    def test_lowercase_t_not_matched(self):
        """Küçük 't' ile başlayan pattern yakalanmamalı (#1.4)"""
        text = "Serial: t1000"
        result = extract_iocs(text)
        self.assertNotIn("t1000", result["mitre_techniques"])

    def test_tactics_id(self):
        """S ile başlayan software ID'leri de yakalanmalı"""
        text = "Software: S0001"
        result = extract_iocs(text)
        self.assertIn("S0001", result["mitre_techniques"])


class TestDeduplication(unittest.TestCase):
    """Deduplication testleri (#5.3)"""

    def test_unique_removes_duplicates(self):
        text = "8.8.8.8 and again 8.8.8.8 and once more 8.8.8.8"
        result = extract_iocs(text, unique=True)
        self.assertEqual(result["ipv4"].count("8.8.8.8"), 1)

    def test_unique_false_keeps_duplicates(self):
        text = "8.8.8.8 and again 8.8.8.8"
        result = extract_iocs(text, unique=False)
        self.assertEqual(len(result["ipv4"]), 2)


class TestRefang(unittest.TestCase):
    """Refang testleri"""

    def test_refang_ip(self):
        text = "IP: 8[.]8[.]8[.]8"
        result = extract_iocs(text, do_refang=True)
        self.assertIn("8.8.8.8", result["ipv4"])

    def test_refang_url(self):
        text = "hxxps://evil[.]com/payload"
        result = extract_iocs(text, do_refang=True)
        self.assertTrue(any("evil.com" in u for u in result["urls"]))


class TestEdgeCases(unittest.TestCase):
    """Edge case testleri"""

    def test_empty_text(self):
        result = extract_iocs("")
        self.assertEqual(len(result["ipv4"]), 0)

    def test_no_iocs(self):
        text = "This is a normal text with no indicators."
        result = extract_iocs(text)
        self.assertEqual(len(result["ipv4"]), 0)
        self.assertEqual(len(result["urls"]), 0)

    def test_metadata_present(self):
        result = extract_iocs("test")
        self.assertIn("metadata", result)
        self.assertIn("extracted_at", result["metadata"])


if __name__ == "__main__":
    unittest.main()
