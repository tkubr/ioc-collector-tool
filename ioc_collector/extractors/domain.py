"""
Domain Extractor — Domain adı çıkarma.
"""
from typing import Set
from .base import BaseExtractor

VALID_TLDS = {
    "com", "org", "net", "edu", "gov", "mil", "int",
    "io", "co", "us", "uk", "de", "fr", "ru", "cn", "jp",
    "br", "in", "au", "ca", "it", "es", "nl", "se", "no",
    "fi", "dk", "pl", "cz", "at", "ch", "be", "pt", "tr",
    "kr", "tw", "hk", "sg", "my", "th", "vn", "id", "ph",
    "za", "ng", "ke", "eg", "ma", "ar", "mx", "cl", "pe",
    "info", "biz", "name", "pro", "mobi", "tel", "asia",
    "xyz", "online", "site", "store", "tech", "app",
    "dev", "page", "blog", "cloud", "ai", "ml", "cc",
    "me", "tv", "ly", "to", "la", "pw", "ws", "tk",
}

BAD_SUFFIXES = (
    ".exe", ".dll", ".zip", ".rar", ".7z", ".msi", ".ps1",
    ".bat", ".cmd", ".scr", ".tmp", ".log", ".txt", ".cfg",
    ".sys", ".ini", ".bak", ".old", ".doc", ".pdf", ".png",
)

RESERVED = {"localhost", "example.com", "example.org", "example.net", "test.com", "invalid", "local"}


class DomainExtractor(BaseExtractor):
    """Domain adı extractor'ı"""

    def __init__(self):
        super().__init__()
        self.pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        self.ioc_type = "domain"

    def extract(self, text: str) -> Set[str]:
        matches = self._find_matches(text)
        return {d.lower() for d in matches if self.validate(d)}

    def validate(self, ioc: str) -> bool:
        d = ioc.lower().strip()
        if d.endswith(BAD_SUFFIXES):
            return False
        if "." not in d:
            return False
        if d in RESERVED:
            return False
        tld = d.rsplit(".", 1)[-1]
        return tld in VALID_TLDS
