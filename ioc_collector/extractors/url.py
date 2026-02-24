"""
URL Extractor — URL çıkarma.
"""
from typing import Set
from .base import BaseExtractor


class URLExtractor(BaseExtractor):
    """URL extractor'ı (hxxp dahil)"""

    def __init__(self):
        super().__init__()
        self.pattern = r'(?:https?|hxxps?|ftp)://(?:[\w\-]+(?:\.[\w\-]+)+)(?::\d+)?(?:/[^\s]*)?'
        self.ioc_type = "url"

    def extract(self, text: str) -> Set[str]:
        matches = self._find_matches(text)
        return {u for u in matches if self.validate(u)}

    def validate(self, ioc: str) -> bool:
        return ioc.startswith(("http://", "https://", "hxxp://", "hxxps://", "ftp://"))
