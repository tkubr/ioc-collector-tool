"""
abuse.ch Feed Ailesi — URLhaus, MalBazaar, ThreatFox, Feodo Tracker, SSL Blacklist.

Tüm abuse.ch feed'leri ücretsizdir ve API key gerektirmez.
CSV formatındaki feed'lerde yorum satırları (#) atlanır.
"""

import csv
import io
import logging
from typing import Optional, List, Dict

from ioc_collector.sources.remote_fetcher import RemoteFetcher

logger = logging.getLogger(__name__)


class AbuseCHFeed:
    """abuse.ch threat intelligence feed'lerini çeken sınıf."""

    URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    MALBAZAAR_URL = "https://bazaar.abuse.ch/export/csv/recent/"
    THREATFOX_URL = "https://threatfox.abuse.ch/export/csv/recent/"
    FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
    SSLBL_URL = "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"

    def __init__(self, fetcher: RemoteFetcher):
        self.fetcher = fetcher

    def _skip_comments(self, text: str) -> List[str]:
        """Yorum satırlarını (#) ve boş satırları atlar."""
        lines = []
        for line in text.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                lines.append(stripped)
        return lines

    def _parse_csv_content(self, text: str) -> List[List[str]]:
        """CSV içeriğini parse eder, yorum satırlarını atlar."""
        clean_lines = self._skip_comments(text)
        if not clean_lines:
            return []

        clean_text = "\n".join(clean_lines)
        reader = csv.reader(io.StringIO(clean_text))
        rows = []
        for row in reader:
            if row:
                rows.append(row)
        return rows

    def fetch_urlhaus(self) -> Optional[str]:
        """
        URLhaus — Son zamanlarda tespit edilen malicious URL'ler.
        CSV formatında: id, dateadded, url, url_status, threat, tags, urlhaus_link, reporter
        Raw text döner, extract_iocs() URL'leri çıkarır.
        """
        logger.info("abuse.ch URLhaus feed çekiliyor...")
        content = self.fetcher.fetch(self.URLHAUS_URL)
        if not content:
            logger.error("URLhaus feed verisi alınamadı.")
            return None

        # CSV'deki URL sütununu çıkar (index 2)
        rows = self._parse_csv_content(content)
        urls = []
        for row in rows:
            if len(row) > 2:
                url = row[2].strip('"')
                if url.startswith("http"):
                    urls.append(url)

        if urls:
            logger.info(f"URLhaus: {len(urls)} malicious URL bulundu.")
            return "\n".join(urls)

        # Eğer parse başarısız olursa raw text'i dön
        logger.warning("URLhaus CSV parse edilemedi, raw text döndürülüyor.")
        return content

    def fetch_malbazaar(self) -> Optional[str]:
        """
        MalBazaar — Son zamanlarda tespit edilen malware hash'leri.
        CSV: sha256_hash, md5_hash, sha1_hash, ...
        Raw text döner, extract_iocs() hash'leri çıkarır.
        """
        logger.info("abuse.ch MalBazaar feed çekiliyor...")
        content = self.fetcher.fetch(self.MALBAZAAR_URL)
        if not content:
            logger.error("MalBazaar feed verisi alınamadı.")
            return None

        # CSV'deki hash sütunlarını çıkar
        rows = self._parse_csv_content(content)
        hashes = []
        for row in rows:
            if len(row) > 2:
                # sha256 (index 0), md5 (index 1), sha1 (index 2)
                for i in range(min(3, len(row))):
                    h = row[i].strip('"').strip()
                    if h and len(h) in (32, 40, 64):
                        hashes.append(h)

        if hashes:
            logger.info(f"MalBazaar: {len(hashes)} malware hash bulundu.")
            return "\n".join(hashes)

        logger.warning("MalBazaar CSV parse edilemedi, raw text döndürülüyor.")
        return content

    def fetch_threatfox(self) -> Optional[str]:
        """
        ThreatFox — Çeşitli IOC tipleri (IP, Domain, URL, Hash).
        CSV: date, ioc_id, ioc_value, ioc_type, threat_type, ...
        Raw text döner, extract_iocs() tüm IOC'leri çıkarır.
        """
        logger.info("abuse.ch ThreatFox feed çekiliyor...")
        content = self.fetcher.fetch(self.THREATFOX_URL)
        if not content:
            logger.error("ThreatFox feed verisi alınamadı.")
            return None

        # CSV'deki ioc_value sütununu çıkar (index 2)
        rows = self._parse_csv_content(content)
        ioc_values = []
        for row in rows:
            if len(row) > 2:
                ioc_val = row[2].strip('"').strip()
                if ioc_val:
                    ioc_values.append(ioc_val)

        if ioc_values:
            logger.info(f"ThreatFox: {len(ioc_values)} IOC bulundu.")
            return "\n".join(ioc_values)

        logger.warning("ThreatFox CSV parse edilemedi, raw text döndürülüyor.")
        return content

    def fetch_feodo_tracker(self) -> Optional[str]:
        """
        Feodo Tracker — Botnet C2 IP adresleri (düz text).
        Her satır bir IP adresi, yorum satırları # ile başlar.
        """
        logger.info("abuse.ch Feodo Tracker feed çekiliyor...")
        content = self.fetcher.fetch(self.FEODO_URL)
        if not content:
            logger.error("Feodo Tracker feed verisi alınamadı.")
            return None

        lines = self._skip_comments(content)
        logger.info(f"Feodo Tracker: {len(lines)} botnet C2 IP bulundu.")
        return "\n".join(lines)

    def fetch_ssl_blacklist(self) -> Optional[str]:
        """
        SSL Blacklist — Malicious SSL sertifikası kullanan IP'ler.
        CSV: listing_date, ip, port, ...
        """
        logger.info("abuse.ch SSL Blacklist feed çekiliyor...")
        content = self.fetcher.fetch(self.SSLBL_URL)
        if not content:
            logger.error("SSL Blacklist feed verisi alınamadı.")
            return None

        # CSV'deki IP sütununu çıkar (index 1)
        rows = self._parse_csv_content(content)
        ips = []
        for row in rows:
            if len(row) > 1:
                ip = row[1].strip('"').strip()
                if ip:
                    ips.append(ip)

        if ips:
            logger.info(f"SSL Blacklist: {len(ips)} malicious IP bulundu.")
            return "\n".join(ips)

        logger.warning("SSL Blacklist CSV parse edilemedi, raw text döndürülüyor.")
        return content

    def fetch_all(self) -> Optional[str]:
        """Tüm abuse.ch feed'lerini çeker ve birleştirir."""
        parts = []
        for name, method in [
            ("URLhaus", self.fetch_urlhaus),
            ("MalBazaar", self.fetch_malbazaar),
            ("ThreatFox", self.fetch_threatfox),
            ("Feodo Tracker", self.fetch_feodo_tracker),
            ("SSL Blacklist", self.fetch_ssl_blacklist),
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
