"""
IOC Enrichment — VirusTotal API entegrasyonu.
"""
import logging
import os

logger = logging.getLogger(__name__)

VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"


class VirusTotalEnrichment:
    """VirusTotal API ile IOC zenginleştirme"""

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.environ.get("VT_API_KEY", "")
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }

    def is_configured(self) -> bool:
        """API key'in yapılandırılıp yapılandırılmadığını kontrol eder"""
        return bool(self.api_key)

    def check_ip(self, ip: str) -> dict | None:
        """IP adresini VirusTotal'da sorgular"""
        if not self.is_configured():
            logger.warning("VirusTotal API key yapılandırılmamış. VT_API_KEY env variable'ı set edin.")
            return None
        try:
            import requests
            url = f"{VIRUSTOTAL_API_URL}/ip_addresses/{ip}"
            response = requests.get(url, headers=self.headers, timeout=15)
            response.raise_for_status()
            data = response.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "ip": ip,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "country": attrs.get("country", "N/A"),
                "as_owner": attrs.get("as_owner", "N/A"),
                "reputation": attrs.get("reputation", 0),
            }
        except Exception as e:
            logger.error(f"VT IP sorgusu hatası ({ip}): {e}")
            return None

    def check_hash(self, file_hash: str) -> dict | None:
        """Hash'i VirusTotal'da sorgular"""
        if not self.is_configured():
            logger.warning("VirusTotal API key yapılandırılmamış.")
            return None
        try:
            import requests
            url = f"{VIRUSTOTAL_API_URL}/files/{file_hash}"
            response = requests.get(url, headers=self.headers, timeout=15)
            response.raise_for_status()
            data = response.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "hash": file_hash,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "type_description": attrs.get("type_description", "N/A"),
                "reputation": attrs.get("reputation", 0),
                "names": attrs.get("names", [])[:5],
            }
        except Exception as e:
            logger.error(f"VT hash sorgusu hatası ({file_hash}): {e}")
            return None

    def check_domain(self, domain: str) -> dict | None:
        """Domain'i VirusTotal'da sorgular"""
        if not self.is_configured():
            logger.warning("VirusTotal API key yapılandırılmamış.")
            return None
        try:
            import requests
            url = f"{VIRUSTOTAL_API_URL}/domains/{domain}"
            response = requests.get(url, headers=self.headers, timeout=15)
            response.raise_for_status()
            data = response.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "domain": domain,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": attrs.get("reputation", 0),
                "registrar": attrs.get("registrar", "N/A"),
            }
        except Exception as e:
            logger.error(f"VT domain sorgusu hatası ({domain}): {e}")
            return None

    def enrich_iocs(self, iocs: dict, max_lookups: int = 10) -> dict:
        """Tüm IOC'ları zenginleştirir (rate limit'e dikkat ederek)"""
        enrichment = {}
        lookups = 0

        for ip in iocs.get("ipv4", [])[:max_lookups]:
            if lookups >= max_lookups:
                break
            result = self.check_ip(ip)
            if result:
                enrichment[ip] = result
            lookups += 1

        for domain in iocs.get("domains", [])[:max_lookups - lookups]:
            if lookups >= max_lookups:
                break
            result = self.check_domain(domain)
            if result:
                enrichment[domain] = result
            lookups += 1

        for hash_type in ["hash_sha256", "hash_sha1", "hash_md5"]:
            for h in iocs.get(hash_type, [])[:max_lookups - lookups]:
                if lookups >= max_lookups:
                    break
                result = self.check_hash(h)
                if result:
                    enrichment[h] = result
                lookups += 1

        return enrichment
