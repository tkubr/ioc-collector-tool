"""
Domain/Phishing Feed'leri — OpenPhish, Bambenek C2, PhishTank, CyberCrime Tracker.

OpenPhish: Phishing URL listesi (düz text, her satırda bir URL).
Bambenek C2: C2 domain listesi (düz text, yorum satırları # ile başlar).
PhishTank: Phishing URL listesi (CSV, API key opsiyonel).
CyberCrime Tracker: C2 panel URL listesi (düz text).
"""

import csv
import io
import logging
import os
from typing import Optional, List

from ioc_collector.sources.remote_fetcher import RemoteFetcher

logger = logging.getLogger(__name__)


class PhishingFeed:
    """Phishing ve C2 domain feed'lerini çeken sınıf."""

    OPENPHISH_URL = "https://openphish.com/feed.txt"
    BAMBENEK_C2_URL = "https://osint.bambenekconsulting.com/feeds/c2-dommasterlist.txt"
    PHISHTANK_URL = "https://data.phishtank.com/data/online-valid.csv"
    CYBERCRIME_TRACKER_URL = "https://cybercrime-tracker.net/all.php"

    def __init__(self, fetcher: RemoteFetcher):
        self.fetcher = fetcher

    def _parse_text_list(self, text: str) -> List[str]:
        """Düz text listesini parse eder, yorum ve boş satırları atlar."""
        lines = []
        for line in text.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                lines.append(stripped)
        return lines

    def fetch_openphish(self) -> Optional[str]:
        """
        OpenPhish — Phishing URL listesi.
        Düz text, her satırda bir phishing URL.
        """
        logger.info("OpenPhish feed çekiliyor...")
        content = self.fetcher.fetch(self.OPENPHISH_URL)
        if not content:
            logger.error("OpenPhish feed verisi alınamadı.")
            return None

        urls = self._parse_text_list(content)
        logger.info(f"OpenPhish: {len(urls)} phishing URL bulundu.")
        return "\n".join(urls)

    def fetch_bambenek_c2(self) -> Optional[str]:
        """
        Bambenek C2 — C2 domain master listesi.
        Düz text, CSV-benzeri: domain,ip,info,...
        İlk sütun domain'dir, yorum satırları # ile başlar.
        """
        logger.info("Bambenek C2 feed çekiliyor...")
        content = self.fetcher.fetch(self.BAMBENEK_C2_URL)
        if not content:
            logger.error("Bambenek C2 feed verisi alınamadı.")
            return None

        lines = self._parse_text_list(content)
        # Bambenek formatı: domain,ip,description,...  — ilk sütun domain
        domains = []
        for line in lines:
            parts = line.split(",")
            if parts:
                domain = parts[0].strip()
                if domain:
                    domains.append(domain)

        if domains:
            logger.info(f"Bambenek C2: {len(domains)} C2 domain bulundu.")
            return "\n".join(domains)

        # Parse başarısız olursa raw text dön
        logger.warning("Bambenek C2 parse edilemedi, raw text döndürülüyor.")
        return content

    def fetch_phishtank(self) -> Optional[str]:
        """
        PhishTank — Phishing URL veritabanı.
        CSV formatı: phish_id, url, phish_detail_url, submission_time, verified, ...
        API key varsa PHISHTANK_API_KEY env variable'ından alınır.
        """
        logger.info("PhishTank feed çekiliyor...")
        api_key = os.environ.get("PHISHTANK_API_KEY", "")
        url = self.PHISHTANK_URL
        if api_key:
            url = f"https://data.phishtank.com/data/{api_key}/online-valid.csv"

        content = self.fetcher.fetch(url)
        if not content:
            logger.error("PhishTank feed verisi alınamadı.")
            return None

        urls = []
        try:
            reader = csv.reader(io.StringIO(content))
            header = next(reader, None)  # Başlık satırını atla
            url_idx = 1  # Varsayılan: 2. sütun URL
            if header:
                for i, col in enumerate(header):
                    if col.strip().lower() == "url":
                        url_idx = i
                        break
            for row in reader:
                if len(row) > url_idx:
                    phish_url = row[url_idx].strip()
                    if phish_url:
                        urls.append(phish_url)
        except csv.Error as e:
            logger.error(f"PhishTank CSV parse hatası: {e}")
            return content  # Raw text fallback

        if urls:
            logger.info(f"PhishTank: {len(urls)} phishing URL bulundu.")
            return "\n".join(urls)

        logger.warning("PhishTank parse edilemedi, raw text döndürülüyor.")
        return content

    def fetch_cybercrime_tracker(self) -> Optional[str]:
        """
        CyberCrime Tracker — C2 panel URL listesi.
        Düz text, her satırda bir URL.
        """
        logger.info("CyberCrime Tracker feed çekiliyor...")
        content = self.fetcher.fetch(self.CYBERCRIME_TRACKER_URL)
        if not content:
            logger.error("CyberCrime Tracker feed verisi alınamadı.")
            return None

        urls = self._parse_text_list(content)
        logger.info(f"CyberCrime Tracker: {len(urls)} C2 panel URL bulundu.")
        return "\n".join(urls)

    def fetch_all(self) -> Optional[str]:
        """Tüm phishing feed'lerini çeker ve birleştirir."""
        parts = []
        for name, method in [
            ("OpenPhish", self.fetch_openphish),
            ("Bambenek C2", self.fetch_bambenek_c2),
            ("PhishTank", self.fetch_phishtank),
            ("CyberCrime Tracker", self.fetch_cybercrime_tracker),
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
