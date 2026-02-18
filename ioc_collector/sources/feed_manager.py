import os
import yaml
import logging
from typing import Dict, List, Optional

# Default configuration path
CONFIG_DIR = os.path.expanduser("~/.ioc-collector")
FEEDS_FILE = os.path.join(CONFIG_DIR, "feeds.yaml")

DEFAULT_FEEDS = {
    "TR": {
        "name": "USOM Malicious URL List",
        "url": "https://www.usom.gov.tr/url-list.txt",
        "format": "text",
        "type": "cert"
    },
    "US": {
        "name": "CISA Known Exploited Vulnerabilities",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "format": "json",
        "type": "cert"
    },
    "maltrail": {
        "name": "Maltrail Malware List",
        "url": "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/malware.json",
        "format": "text",
        "type": "github"
    }
}

class FeedManager:
    def __init__(self, config_path: str = FEEDS_FILE):
        self.config_path = config_path
        self._ensure_config_exists()
        self.feeds = self._load_feeds()

    def _ensure_config_exists(self):
        """Creates default configuration."""
        if not os.path.exists(os.path.dirname(self.config_path)):
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        
        if not os.path.exists(self.config_path):
            self._create_default_config()

    def _load_feeds(self) -> Dict:
        """Loads feeds from config."""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logging.error(f"Error loading feeds config: {e}")
            return DEFAULT_FEEDS

    def _create_default_config(self):
        """Creates default configuration file."""
        try:
            with open(self.config_path, 'w') as f:
                yaml.dump(DEFAULT_FEEDS, f, default_flow_style=False)
            logging.info(f"Created default feeds config at {self.config_path}")
        except Exception as e:
            logging.error(f"Error creating default config: {e}")

    def get_feed(self, name: str) -> Optional[Dict]:
        """Retrieves a specific feed by name."""
        return self.feeds.get(name)

    def list_feeds(self) -> Dict:
        """Lists all available feeds."""
        return self.feeds

    def add_feed(self, name: str, url: str, format_type: str = "text", feed_type: str = "custom"):
        """Adds a new feed."""
        if name in self.feeds:
             logging.warning(f"Feed '{name}' already exists. Overwriting.")
        
        self.feeds[name] = {
            "name": name,
            "url": url,
            "format": format_type,
            "type": feed_type
        }
        self._save_feeds()

    def _save_feeds(self):
        """Saves current feeds to configuration file."""
        try:
            with open(self.config_path, 'w') as f:
                yaml.dump(self.feeds, f, default_flow_style=False)
            logging.info(f"Saved feeds to {self.config_path}")
        except Exception as e:
            logging.error(f"Error saving feeds config: {e}")
