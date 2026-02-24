"""
IP Blocklist Feed'leri — Blocklist.de, Emerging Threats, Spamhaus DROP, Cinsscore, Talos.

Tüm feed'ler düz text formatında, her satırda bir IP adresi.
Yorum satırları (#) ve boş satırlar atlanır.
Spamhaus DROP özel olarak CIDR formatındadır (ör: 1.10.16.0/20).
"""

import logging
from typing import Optional, List

from ioc_collector.sources.remote_fetcher import RemoteFetcher

logger = logging.getLogger(__name__)


class IPBlocklistFeed:
    """IP blocklist feed'lerini çeken sınıf."""

    BLOCKLIST_DE_URL = "https://lists.blocklist.de/lists/all.txt"
    EMERGING_THREATS_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    SPAMHAUS_DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
    CINSSCORE_URL = "https://cinsscore.com/list/ci-badguys.txt"
    TALOS_URL = "https://www.talosintelligence.com/documents/ip-blacklist"

    def __init__(self, fetcher: RemoteFetcher):
        self.fetcher = fetcher

    def _parse_ip_list(self, text: str) -> List[str]:
        """Düz text IP listesini parse eder, yorum ve boş satırları atlar."""
        ips = []
        for line in text.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and not stripped.startswith(";"):
                # Spamhaus DROP: "1.10.16.0/20 ; SB..." — sadece IP/CIDR kısmını al
                ip_part = stripped.split(";")[0].strip()
                if ip_part:
                    ips.append(ip_part)
        return ips

    def fetch_blocklist_de(self) -> Optional[str]:
        """
        Blocklist.de — Saldırgan IP adresleri.
        Düz text, her satırda bir IP.
        """
        logger.info("Blocklist.de feed çekiliyor...")
        content = self.fetcher.fetch(self.BLOCKLIST_DE_URL)
        if not content:
            logger.error("Blocklist.de feed verisi alınamadı.")
            return None

        ips = self._parse_ip_list(content)
        logger.info(f"Blocklist.de: {len(ips)} saldırgan IP bulundu.")
        return "\n".join(ips)

    def fetch_emerging_threats(self) -> Optional[str]:
        """
        Emerging Threats — Compromised IP adresleri.
        Düz text, her satırda bir IP.
        """
        logger.info("Emerging Threats feed çekiliyor...")
        content = self.fetcher.fetch(self.EMERGING_THREATS_URL)
        if not content:
            logger.error("Emerging Threats feed verisi alınamadı.")
            return None

        ips = self._parse_ip_list(content)
        logger.info(f"Emerging Threats: {len(ips)} compromised IP bulundu.")
        return "\n".join(ips)

    def fetch_spamhaus_drop(self) -> Optional[str]:
        """
        Spamhaus DROP — Hijack edilmiş IP blokları (CIDR).
        Format: "IP/CIDR ; SBxxx | description"
        CIDR bloklarını döner, extract_iocs() IP'leri çıkarır.
        """
        logger.info("Spamhaus DROP feed çekiliyor...")
        content = self.fetcher.fetch(self.SPAMHAUS_DROP_URL)
        if not content:
            logger.error("Spamhaus DROP feed verisi alınamadı.")
            return None

        ips = self._parse_ip_list(content)
        logger.info(f"Spamhaus DROP: {len(ips)} IP bloğu bulundu.")
        return "\n".join(ips)

    def fetch_cinsscore(self) -> Optional[str]:
        """
        Cinsscore — Kötü amaçlı IP adresleri.
        Düz text, her satırda bir IP.
        """
        logger.info("Cinsscore feed çekiliyor...")
        content = self.fetcher.fetch(self.CINSSCORE_URL)
        if not content:
            logger.error("Cinsscore feed verisi alınamadı.")
            return None

        ips = self._parse_ip_list(content)
        logger.info(f"Cinsscore: {len(ips)} kötü amaçlı IP bulundu.")
        return "\n".join(ips)

    def fetch_talos(self) -> Optional[str]:
        """
        Talos Intelligence — Bilinen kötü IP adresleri.
        Düz text, her satırda bir IP.
        """
        logger.info("Talos Intelligence feed çekiliyor...")
        content = self.fetcher.fetch(self.TALOS_URL)
        if not content:
            logger.error("Talos Intelligence feed verisi alınamadı.")
            return None

        ips = self._parse_ip_list(content)
        logger.info(f"Talos: {len(ips)} kötü IP bulundu.")
        return "\n".join(ips)

    def fetch_all(self) -> Optional[str]:
        """Tüm IP blocklist feed'lerini çeker ve birleştirir."""
        parts = []
        for name, method in [
            ("Blocklist.de", self.fetch_blocklist_de),
            ("Emerging Threats", self.fetch_emerging_threats),
            ("Spamhaus DROP", self.fetch_spamhaus_drop),
            ("Cinsscore", self.fetch_cinsscore),
            ("Talos", self.fetch_talos),
        ]:
            try:
                result = method()
                if result:
                    parts.append(f"# --- {name} ---\n{result}")
            except Exception as e:
                logger.error(f"{name} feed hatası: {e}")

        if parts:
            return "\n\n".join(parts)
        return None
