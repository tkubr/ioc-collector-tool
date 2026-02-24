"""
Base Extractor — Tüm extractor'lar için temel sınıf.
"""
from abc import ABC, abstractmethod
from typing import Set, List
import re


class BaseExtractor(ABC):
    """Tüm IOC extractor'lar için abstract base sınıf"""

    def __init__(self):
        self.pattern: str = ""
        self.ioc_type: str = ""

    @abstractmethod
    def extract(self, text: str) -> Set[str]:
        """Metinden IOC'leri çıkarır"""
        pass

    @abstractmethod
    def validate(self, ioc: str) -> bool:
        """IOC'nin geçerli olup olmadığını kontrol eder"""
        pass

    def _find_matches(self, text: str) -> List[str]:
        """Regex ile eşleşmeleri bulur"""
        return re.findall(self.pattern, text, re.IGNORECASE)
