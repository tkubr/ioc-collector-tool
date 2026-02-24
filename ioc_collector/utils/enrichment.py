"""
IOC Enrichment — VirusTotal, OTX AlienVault, AbuseIPDB, Shodan, GreyNoise API entegrasyonu.
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


OTX_API_URL = "https://otx.alienvault.com/api/v1"


class OTXEnrichment:
    """AlienVault OTX API ile IOC zenginleştirme"""

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.environ.get("OTX_API_KEY", "")
        self.headers = {
            "X-OTX-API-KEY": self.api_key,
            "Accept": "application/json",
        }

    def is_configured(self) -> bool:
        """API key'in yapılandırılıp yapılandırılmadığını kontrol eder"""
        return bool(self.api_key)

    def check_ip(self, ip: str) -> dict | None:
        """IP adresini OTX'te sorgular"""
        if not self.is_configured():
            logger.warning("OTX API key yapılandırılmamış. OTX_API_KEY env variable'ı set edin.")
            return None
        try:
            import requests
            url = f"{OTX_API_URL}/indicators/IPv4/{ip}/general"
            response = requests.get(url, headers=self.headers, timeout=15)
            response.raise_for_status()
            data = response.json()
            return {
                "ip": ip,
                "pulse_count": data.get("pulse_info", {}).get("count", 0),
                "reputation": data.get("reputation", 0),
                "country": data.get("country_code", "N/A"),
                "asn": data.get("asn", "N/A"),
            }
        except Exception as e:
            logger.error(f"OTX IP sorgusu hatası ({ip}): {e}")
            return None

    def check_domain(self, domain: str) -> dict | None:
        """Domain'i OTX'te sorgular"""
        if not self.is_configured():
            logger.warning("OTX API key yapılandırılmamış.")
            return None
        try:
            import requests
            url = f"{OTX_API_URL}/indicators/domain/{domain}/general"
            response = requests.get(url, headers=self.headers, timeout=15)
            response.raise_for_status()
            data = response.json()
            return {
                "domain": domain,
                "pulse_count": data.get("pulse_info", {}).get("count", 0),
                "alexa": data.get("alexa", "N/A"),
                "whois": data.get("whois", "N/A")[:200] if data.get("whois") else "N/A",
            }
        except Exception as e:
            logger.error(f"OTX domain sorgusu hatası ({domain}): {e}")
            return None

    def check_hash(self, file_hash: str) -> dict | None:
        """Hash'i OTX'te sorgular"""
        if not self.is_configured():
            logger.warning("OTX API key yapılandırılmamış.")
            return None
        try:
            import requests
            url = f"{OTX_API_URL}/indicators/file/{file_hash}/general"
            response = requests.get(url, headers=self.headers, timeout=15)
            response.raise_for_status()
            data = response.json()
            return {
                "hash": file_hash,
                "pulse_count": data.get("pulse_info", {}).get("count", 0),
            }
        except Exception as e:
            logger.error(f"OTX hash sorgusu hatası ({file_hash}): {e}")
            return None

    def enrich_iocs(self, iocs: dict, max_lookups: int = 10) -> dict:
        """Tüm IOC'ları OTX ile zenginleştirir"""
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


# ─── AbuseIPDB ────────────────────────────────────────────────

ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2"


class AbuseIPDBEnrichment:
    """AbuseIPDB API ile IP reputation kontrolü"""

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.environ.get("ABUSEIPDB_API_KEY", "")
        self.headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def check_ip(self, ip: str) -> dict | None:
        """IP adresini AbuseIPDB'de sorgular"""
        if not self.is_configured():
            logger.warning("ABUSEIPDB_API_KEY env variable set edilmemiş.")
            return None
        try:
            import requests
            url = f"{ABUSEIPDB_API_URL}/check"
            params = {"ipAddress": ip, "maxAgeInDays": 90}
            response = requests.get(url, headers=self.headers, params=params, timeout=15)
            response.raise_for_status()
            data = response.json().get("data", {})
            return {
                "ip": ip,
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country_code": data.get("countryCode", "N/A"),
                "isp": data.get("isp", "N/A"),
                "usage_type": data.get("usageType", "N/A"),
                "is_public": data.get("isPublic", True),
            }
        except Exception as e:
            logger.error(f"AbuseIPDB sorgu hatası ({ip}): {e}")
            return None

    def enrich_iocs(self, iocs: dict, max_lookups: int = 10) -> dict:
        """IP IOC'larını AbuseIPDB ile zenginleştirir (sadece IP destekler)"""
        enrichment = {}
        lookups = 0
        for ip in iocs.get("ipv4", [])[:max_lookups]:
            if lookups >= max_lookups:
                break
            result = self.check_ip(ip)
            if result:
                enrichment[ip] = result
            lookups += 1
        return enrichment


# ─── Shodan ───────────────────────────────────────────────────

SHODAN_API_URL = "https://api.shodan.io"


class ShodanEnrichment:
    """Shodan API ile IP/port bilgisi"""

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.environ.get("SHODAN_API_KEY", "")

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def check_ip(self, ip: str) -> dict | None:
        """IP adresini Shodan'da sorgular"""
        if not self.is_configured():
            logger.warning("SHODAN_API_KEY env variable set edilmemiş.")
            return None
        try:
            import requests
            url = f"{SHODAN_API_URL}/shodan/host/{ip}"
            params = {"key": self.api_key}
            response = requests.get(url, params=params, timeout=15)
            response.raise_for_status()
            data = response.json()
            return {
                "ip": ip,
                "ports": data.get("ports", []),
                "os": data.get("os", "N/A"),
                "country_code": data.get("country_code", "N/A"),
                "org": data.get("org", "N/A"),
                "isp": data.get("isp", "N/A"),
                "vulns": data.get("vulns", []),
            }
        except Exception as e:
            logger.error(f"Shodan sorgu hatası ({ip}): {e}")
            return None

    def enrich_iocs(self, iocs: dict, max_lookups: int = 10) -> dict:
        """IP IOC'larını Shodan ile zenginleştirir (sadece IP destekler)"""
        enrichment = {}
        lookups = 0
        for ip in iocs.get("ipv4", [])[:max_lookups]:
            if lookups >= max_lookups:
                break
            result = self.check_ip(ip)
            if result:
                enrichment[ip] = result
            lookups += 1
        return enrichment


# ─── GreyNoise ────────────────────────────────────────────────

GREYNOISE_API_URL = "https://api.greynoise.io/v3/community"


class GreyNoiseEnrichment:
    """GreyNoise Community API ile IP noise/riot kontrolü"""

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.environ.get("GREYNOISE_API_KEY", "")
        self.headers = {
            "key": self.api_key,
            "Accept": "application/json",
        }

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def check_ip(self, ip: str) -> dict | None:
        """IP adresini GreyNoise Community API'de sorgular"""
        if not self.is_configured():
            logger.warning("GREYNOISE_API_KEY env variable set edilmemiş.")
            return None
        try:
            import requests
            url = f"{GREYNOISE_API_URL}/{ip}"
            response = requests.get(url, headers=self.headers, timeout=15)
            response.raise_for_status()
            data = response.json()
            return {
                "ip": ip,
                "noise": data.get("noise", False),
                "riot": data.get("riot", False),
                "classification": data.get("classification", "unknown"),
                "name": data.get("name", "N/A"),
                "link": data.get("link", ""),
            }
        except Exception as e:
            logger.error(f"GreyNoise sorgu hatası ({ip}): {e}")
            return None

    def enrich_iocs(self, iocs: dict, max_lookups: int = 10) -> dict:
        """IP IOC'larını GreyNoise ile zenginleştirir (sadece IP destekler)"""
        enrichment = {}
        lookups = 0
        for ip in iocs.get("ipv4", [])[:max_lookups]:
            if lookups >= max_lookups:
                break
            result = self.check_ip(ip)
            if result:
                enrichment[ip] = result
            lookups += 1
        return enrichment
