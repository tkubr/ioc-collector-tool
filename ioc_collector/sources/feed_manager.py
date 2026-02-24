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
    },
    "urlhaus": {
        "name": "abuse.ch URLhaus",
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "format": "csv",
        "type": "abuse_ch"
    },
    "malbazaar": {
        "name": "abuse.ch MalBazaar",
        "url": "https://bazaar.abuse.ch/export/csv/recent/",
        "format": "csv",
        "type": "abuse_ch"
    },
    "threatfox": {
        "name": "abuse.ch ThreatFox",
        "url": "https://threatfox.abuse.ch/export/csv/recent/",
        "format": "csv",
        "type": "abuse_ch"
    },
    "feodo": {
        "name": "abuse.ch Feodo Tracker",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "format": "text",
        "type": "abuse_ch"
    },
    "sslbl": {
        "name": "abuse.ch SSL Blacklist",
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
        "format": "csv",
        "type": "abuse_ch"
    },
    "blocklist_de": {
        "name": "Blocklist.de",
        "url": "https://lists.blocklist.de/lists/all.txt",
        "format": "text",
        "type": "ip_blocklist"
    },
    "emerging_threats": {
        "name": "Emerging Threats",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "format": "text",
        "type": "ip_blocklist"
    },
    "spamhaus": {
        "name": "Spamhaus DROP",
        "url": "https://www.spamhaus.org/drop/drop.txt",
        "format": "text",
        "type": "ip_blocklist"
    },
    "cinsscore": {
        "name": "Cinsscore",
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "format": "text",
        "type": "ip_blocklist"
    },
    "talos": {
        "name": "Talos Intelligence",
        "url": "https://www.talosintelligence.com/documents/ip-blacklist",
        "format": "text",
        "type": "ip_blocklist"
    },
    "openphish": {
        "name": "OpenPhish",
        "url": "https://openphish.com/feed.txt",
        "format": "text",
        "type": "phishing"
    },
    "bambenek_c2": {
        "name": "Bambenek C2",
        "url": "https://osint.bambenekconsulting.com/feeds/c2-dommasterlist.txt",
        "format": "text",
        "type": "phishing"
    },
    "NL": {
        "name": "NCSC-NL Security Advisories",
        "url": "https://advisories.ncsc.nl/rss/advisories",
        "format": "rss",
        "type": "cert"
    },
    "FR": {
        "name": "CERT-FR Security Advisories",
        "url": "https://www.cert.ssi.gouv.fr/feed/",
        "format": "rss",
        "type": "cert"
    },
    "JP": {
        "name": "JPCERT Threat Intelligence",
        "url": "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf",
        "format": "rss",
        "type": "cert"
    },
    "EU": {
        "name": "CERT-EU CTI Reports",
        "url": "https://cert.europa.eu/publications/latest-publications",
        "format": "json",
        "type": "cert"
    },
    "phishtank": {
        "name": "PhishTank",
        "url": "https://data.phishtank.com/data/online-valid.csv",
        "format": "csv",
        "type": "phishing"
    },
    "cybercrime_tracker": {
        "name": "CyberCrime Tracker",
        "url": "https://cybercrime-tracker.net/all.php",
        "format": "text",
        "type": "phishing"
    },
    "misp_warninglists": {
        "name": "MISP Warning Lists",
        "url": "https://github.com/MISP/misp-warninglists",
        "format": "json",
        "type": "github"
    },
    "firehol": {
        "name": "Firehol IP Lists",
        "url": "https://github.com/firehol/blocklist-ipsets",
        "format": "text",
        "type": "github"
    },
    "yaraify": {
        "name": "YARAify",
        "url": "https://github.com/abuse-ch/yaraify",
        "format": "text",
        "type": "github"
    },
    "threathunter": {
        "name": "ThreatHunter Playbook",
        "url": "https://github.com/OTRF/ThreatHunter-Playbook",
        "format": "text",
        "type": "github"
    },
    "eset_apt": {
        "name": "ESET APT IOCs",
        "url": "https://github.com/eset/malware-ioc",
        "format": "text",
        "type": "github"
    },
    "malpedia": {
        "name": "Malpedia",
        "url": "https://github.com/malpedia/malpedia",
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
