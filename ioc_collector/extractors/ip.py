"""
IP Extractor — IPv4 ve IPv6 adres çıkarma.
"""
import ipaddress
from typing import Set
import re
from .base import BaseExtractor


class IPv4Extractor(BaseExtractor):
    """IPv4 adresi extractor'ı"""

    def __init__(self):
        super().__init__()
        self.pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        self.ioc_type = "ipv4"

    def extract(self, text: str) -> Set[str]:
        matches = self._find_matches(text)
        return {ip for ip in matches if self.validate(ip)}

    def validate(self, ioc: str) -> bool:
        try:
            ipaddress.IPv4Address(ioc)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False


class IPv6Extractor(BaseExtractor):
    """IPv6 adresi extractor'ı"""

    def __init__(self):
        super().__init__()
        self.pattern = (
            r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
            r'|\b(?:[0-9a-fA-F]{1,4}:){1,7}:'
            r'|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b'
            r'|\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b'
        )
        self.ioc_type = "ipv6"

    def extract(self, text: str) -> Set[str]:
        matches = self._find_matches(text)
        return {ip for ip in matches if self.validate(ip)}

    def validate(self, ioc: str) -> bool:
        try:
            ipaddress.IPv6Address(ioc)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False
