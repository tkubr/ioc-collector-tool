"""
Email Extractor — Email adresi çıkarma.
"""
from typing import Set
from .base import BaseExtractor


class EmailExtractor(BaseExtractor):
    """Email adresi extractor'ı (defanged dahil)"""

    def __init__(self):
        super().__init__()
        self.pattern = r'\b[a-zA-Z0-9._%+-]+(?:@|\[@\]|\[at\])[a-zA-Z0-9.-]+(?:\.|\[\.\]|\[dot\])[a-zA-Z]{2,}\b'
        self.ioc_type = "email"

    def extract(self, text: str) -> Set[str]:
        matches = self._find_matches(text)
        return {e for e in matches if self.validate(e)}

    def validate(self, ioc: str) -> bool:
        # Basit format kontrolü
        return "@" in ioc or "[@]" in ioc or "[at]" in ioc
