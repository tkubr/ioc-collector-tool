
from typing import Set
from .base import BaseExtractor


class CVEExtractor(BaseExtractor):
    """CVE ID extractor'ı"""

    def __init__(self):
        super().__init__()
        self.pattern = r'\bCVE-\d{4}-\d{4,7}\b'
        self.ioc_type = "cve"

    def extract(self, text: str) -> Set[str]:
        matches = self._find_matches(text)
        return {cve.upper() for cve in matches if self.validate(cve)}

    def validate(self, ioc: str) -> bool:
        parts = ioc.upper().split("-")
        if len(parts) != 3:
            return False
        if parts[0] != "CVE":
            return False
        return parts[1].isdigit() and parts[2].isdigit()
