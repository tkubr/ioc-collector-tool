"""
Hash Extractor — MD5, SHA1, SHA256, SHA512 hash çıkarma.
"""
import re
from typing import Set, Dict
from .base import BaseExtractor


class HashExtractor(BaseExtractor):
    """Hash extractor'ı — çakışma önlemeli"""

    def __init__(self):
        super().__init__()
        self.patterns: Dict[str, str] = {
            'sha512': r'(?<![a-fA-F0-9])[a-fA-F0-9]{128}(?![a-fA-F0-9])',
            'sha256': r'(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])',
            'sha1': r'(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])',
            'md5': r'(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])',
        }
        self.ioc_type = "hash"

    def extract(self, text: str) -> Dict[str, Set[str]]:
        """Hash'leri çıkarır"""
        results = {}
        found_positions = set()

        for hash_type, pattern in self.patterns.items():
            matches = set()
            for match in re.finditer(pattern, text):
                value = match.group().lower()
                start, end = match.start(), match.end()

                # Daha önce uzun hash'in parçası olarak bulundu mu?
                is_sub = any(start >= ps and end <= pe for ps, pe in found_positions)
                if not is_sub:
                    matches.add(value)
                    found_positions.add((start, end))

            if matches:
                results[hash_type] = matches

        return results

    def validate(self, ioc: str) -> bool:
        return all(c in '0123456789abcdefABCDEF' for c in ioc)
