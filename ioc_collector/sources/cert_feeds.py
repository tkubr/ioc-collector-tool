
from typing import Dict, Optional
from ioc_collector.sources.remote_fetcher import RemoteFetcher

class CERTFeed:
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
