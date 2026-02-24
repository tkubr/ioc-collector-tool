
from typing import Dict, Optional, List
from ioc_collector.sources.remote_fetcher import RemoteFetcher
import xml.etree.ElementTree as ET
import logging

logger = logging.getLogger(__name__)


class CERTFeed:
    """CERT feed'lerini çeken sınıf (TR, US, EU, NL, FR, JP)."""

    # RSS feed URL'leri
    NCSC_NL_URL = "https://advisories.ncsc.nl/rss/advisories"
    CERT_FR_URL = "https://www.cert.ssi.gouv.fr/feed/"
    JPCERT_URL = "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf"
    CERT_EU_URL = "https://cert.europa.eu/publications/latest-publications"

    def __init__(self, fetcher: RemoteFetcher):
        self.fetcher = fetcher

    def fetch_tr_usom(self) -> Optional[str]:
        """Fetches the TR-CERT (USOM) malicious URL list."""
        url = "https://www.usom.gov.tr/url-list.txt"
        return self.fetcher.fetch(url)

    def fetch_us_cisa_kev(self) -> Optional[Dict]:
        """Fetches the CISA Known Exploited Vulnerabilities catalog (JSON)."""
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        return self.fetcher.fetch_json(url)

    def _parse_rss(self, xml_text: str) -> List[Dict[str, str]]:
        """RSS/XML feed'i parse eder, title + link + description döner."""
        items = []
        try:
            root = ET.fromstring(xml_text)

            # Standart RSS 2.0 formatı
            for item in root.findall(".//item"):
                entry = {}
                title = item.find("title")
                link = item.find("link")
                description = item.find("description")

                if title is not None and title.text:
                    entry["title"] = title.text.strip()
                if link is not None and link.text:
                    entry["link"] = link.text.strip()
                if description is not None and description.text:
                    entry["description"] = description.text.strip()

                if entry:
                    items.append(entry)

            # RDF formatı (JPCERT gibi)
            if not items:
                # RDF namespace ile denemek
                ns = {
                    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
                    "rss": "http://purl.org/rss/1.0/",
                    "dc": "http://purl.org/dc/elements/1.1/",
                }
                for item in root.findall(".//rss:item", ns):
                    entry = {}
                    title = item.find("rss:title", ns)
                    link = item.find("rss:link", ns)
                    description = item.find("rss:description", ns)

                    if title is not None and title.text:
                        entry["title"] = title.text.strip()
                    if link is not None and link.text:
                        entry["link"] = link.text.strip()
                    if description is not None and description.text:
                        entry["description"] = description.text.strip()

                    if entry:
                        items.append(entry)

        except ET.ParseError as e:
            logger.error(f"RSS parse hatası: {e}")

        return items

    def _items_to_text(self, items: List[Dict[str, str]]) -> str:
        """Parse edilmiş RSS item'larını text formatına çevirir."""
        parts = []
        for item in items:
            line_parts = []
            if "title" in item:
                line_parts.append(item["title"])
            if "link" in item:
                line_parts.append(item["link"])
            if "description" in item:
                line_parts.append(item["description"])
            parts.append(" | ".join(line_parts))
        return "\n".join(parts)

    def fetch_nl_ncsc(self) -> Optional[str]:
        """
        NCSC-NL (Hollanda) — Güvenlik uyarıları RSS feed'i.
        """
        logger.info("NCSC-NL feed çekiliyor...")
        content = self.fetcher.fetch(self.NCSC_NL_URL)
        if not content:
            logger.error("NCSC-NL feed verisi alınamadı.")
            return None

        items = self._parse_rss(content)
        if items:
            logger.info(f"NCSC-NL: {len(items)} güvenlik uyarısı bulundu.")
            return self._items_to_text(items)

        logger.warning("NCSC-NL RSS parse edilemedi, raw text döndürülüyor.")
        return content

    def fetch_fr_cert(self) -> Optional[str]:
        """
        CERT-FR (Fransa) — Güvenlik uyarıları RSS feed'i.
        """
        logger.info("CERT-FR feed çekiliyor...")
        content = self.fetcher.fetch(self.CERT_FR_URL)
        if not content:
            logger.error("CERT-FR feed verisi alınamadı.")
            return None

        items = self._parse_rss(content)
        if items:
            logger.info(f"CERT-FR: {len(items)} güvenlik uyarısı bulundu.")
            return self._items_to_text(items)

        logger.warning("CERT-FR RSS parse edilemedi, raw text döndürülüyor.")
        return content

    def fetch_jp_cert(self) -> Optional[str]:
        """
        JPCERT (Japonya) — Tehdit istihbaratı RSS/RDF feed'i.
        """
        logger.info("JPCERT feed çekiliyor...")
        content = self.fetcher.fetch(self.JPCERT_URL)
        if not content:
            logger.error("JPCERT feed verisi alınamadı.")
            return None

        items = self._parse_rss(content)
        if items:
            logger.info(f"JPCERT: {len(items)} tehdit istihbaratı bulundu.")
            return self._items_to_text(items)

        logger.warning("JPCERT RSS parse edilemedi, raw text döndürülüyor.")
        return content

    def fetch_eu_cert(self) -> Optional[str]:
        """
        CERT-EU (Avrupa) — CTI raporları.
        JSON endpoint'inden başlık ve link bilgisi çıkarır.
        RSS fallback ile de çalışır.
        """
        logger.info("CERT-EU feed çekiliyor...")
        content = self.fetcher.fetch(self.CERT_EU_URL)
        if not content:
            logger.error("CERT-EU feed verisi alınamadı.")
            return None

        # JSON olarak parse et
        try:
            import json
            data = json.loads(content)
            items = []
            if isinstance(data, list):
                for item in data:
                    parts = []
                    if item.get("title"):
                        parts.append(str(item["title"]))
                    if item.get("link") or item.get("url"):
                        parts.append(str(item.get("link") or item.get("url")))
                    if item.get("description") or item.get("summary"):
                        parts.append(str(item.get("description") or item.get("summary")))
                    if parts:
                        items.append(" | ".join(parts))
            elif isinstance(data, dict):
                # Tek obje veya nested format
                for key in ["items", "publications", "results", "data"]:
                    if key in data and isinstance(data[key], list):
                        for item in data[key]:
                            parts = []
                            if isinstance(item, dict):
                                if item.get("title"):
                                    parts.append(str(item["title"]))
                                if item.get("link") or item.get("url"):
                                    parts.append(str(item.get("link") or item.get("url")))
                            if parts:
                                items.append(" | ".join(parts))
                        break

            if items:
                logger.info(f"CERT-EU: {len(items)} CTI raporu bulundu.")
                return "\n".join(items)
        except (json.JSONDecodeError, TypeError):
            pass

        # JSON parse edilemezse RSS dene
        items = self._parse_rss(content)
        if items:
            logger.info(f"CERT-EU (RSS): {len(items)} güvenlik uyarısı bulundu.")
            return self._items_to_text(items)

        # Son çare: raw text dön
        logger.warning("CERT-EU parse edilemedi, raw text döndürülüyor.")
        return content

    def fetch_all(self) -> Optional[str]:
        """Tüm CERT feed'lerini çeker ve birleştirir."""
        import json
        parts = []

        # TR USOM
        try:
            c = self.fetch_tr_usom()
            if c:
                parts.append(f"# --- TR USOM ---\n{c}")
        except Exception as e:
            logger.error(f"TR USOM feed hatası: {e}")

        # US CISA
        try:
            c = self.fetch_us_cisa_kev()
            if c:
                parts.append(f"# --- US CISA KEV ---\n{json.dumps(c)}")
        except Exception as e:
            logger.error(f"US CISA feed hatası: {e}")

        # EU CERT
        try:
            c = self.fetch_eu_cert()
            if c:
                parts.append(f"# --- EU CERT ---\n{c}")
        except Exception as e:
            logger.error(f"EU CERT feed hatası: {e}")

        # NL NCSC
        try:
            c = self.fetch_nl_ncsc()
            if c:
                parts.append(f"# --- NL NCSC ---\n{c}")
        except Exception as e:
            logger.error(f"NL NCSC feed hatası: {e}")

        # FR CERT
        try:
            c = self.fetch_fr_cert()
            if c:
                parts.append(f"# --- FR CERT ---\n{c}")
        except Exception as e:
            logger.error(f"FR CERT feed hatası: {e}")

        # JP CERT
        try:
            c = self.fetch_jp_cert()
            if c:
                parts.append(f"# --- JP CERT ---\n{c}")
        except Exception as e:
            logger.error(f"JP CERT feed hatası: {e}")

        if parts:
            return "\n\n".join(parts)
        return None
