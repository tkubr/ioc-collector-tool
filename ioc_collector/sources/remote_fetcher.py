
import requests
import logging
import time
import os
from typing import Optional, Dict
from urllib.parse import urlparse

try:
    import requests_cache
    HAS_CACHE = True
except ImportError:
    HAS_CACHE = False

class RemoteFetcher:
    def __init__(self, proxy: Optional[str] = None, verify_ssl: bool = True, user_agent: str = "IOC-Collector/1.2"):
        self.verify_ssl = verify_ssl
        self.headers = {"User-Agent": user_agent}
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        
        if not verify_ssl:
            requests.packages.urllib3.disable_warnings()
            
        if HAS_CACHE:
            cache_dir = os.path.expanduser("~/.ioc-collector/cache")
            requests_cache.install_cache(cache_dir, expire_after=3600) # 1 hour default

    def fetch(self, url: str, retries: int = 3, backoff_factor: float = 0.5) -> Optional[str]:

        """Fetches URL content."""
        for i in range(retries):
            try:
                logging.info(f"Fetching {url} (Attempt {i+1}/{retries})")
                response = requests.get(
                    url, 
                    headers=self.headers, 
                    proxies=self.proxies, 
                    verify=self.verify_ssl, 
                    timeout=30
                )
                response.raise_for_status()
                return response.text
            except requests.exceptions.RequestException as e:
                logging.warning(f"Error fetching {url}: {e}")
                if i < retries - 1:
                    sleep_time = backoff_factor * (2 ** i)
                    time.sleep(sleep_time)
                else:
                    logging.error(f"Failed to fetch {url} after {retries} attempts.")
                    return None
        return None

    def fetch_json(self, url: str) -> Optional[Dict]:
        """Fetches and parses JSON content from a URL."""
        content = self.fetch(url)
        if content:
            try:
                return requests.json.loads(content) # Using requests internal json or standard json
            except Exception as e:
                 # fallback if needed, but response.json() is better if we had the response object
                 # Since fetch returns text, we use json.loads
                 import json
                 try:
                     return json.loads(content)
                 except json.JSONDecodeError as e:
                     logging.error(f"Failed to parse JSON from {url}: {e}")
        return None
