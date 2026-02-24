
from typing import Optional, Dict, List
from ioc_collector.sources.remote_fetcher import RemoteFetcher
import logging

logger = logging.getLogger(__name__)


# Preset GitHub IOC repo tanımları
GITHUB_PRESETS = {
    "maltrail": {
        "repo": "stamparm/maltrail",
        "branch": "master",
        "path": "trails/static/malware/malware.txt",
        "description": "Maltrail malware IOC listesi",
    },
    "misp_warninglists": {
        "repo": "MISP/misp-warninglists",
        "branch": "main",
        "path": "lists/disposable-email/list.json",
        "description": "MISP false positive filtreleme listeleri",
    },
    "firehol": {
        "repo": "firehol/blocklist-ipsets",
        "branch": "master",
        "path": "firehol_level1.netset",
        "description": "Firehol Level 1 IP blocklist",
    },
    "yaraify": {
        "repo": "abuse-ch/yaraify",
        "branch": "main",
        "path": "README.md",
        "description": "YARAify YARA rule ve hash repository",
    },
    "threathunter": {
        "repo": "OTRF/ThreatHunter-Playbook",
        "branch": "master",
        "path": "README.md",
        "description": "ThreatHunter Playbook ATT&CK TTP bilgisi",
    },
    "eset_apt": {
        "repo": "eset/malware-ioc",
        "branch": "master",
        "path": "README.adoc",
        "description": "ESET APT kampanya IOC'ları",
    },
    "malpedia": {
        "repo": "malpedia/malpedia",
        "branch": "main",
        "path": "README.md",
        "description": "Malpedia malware ailesi bilgisi",
    },
}


class GitHubFeed:
    def __init__(self, fetcher: RemoteFetcher):
        self.fetcher = fetcher

    def fetch_from_repo(self, repo_slug: str, branch: str = "master", path: str = "trails/static/malware/malware.txt") -> Optional[str]:
        """Fetches a file from GitHub."""
        raw_url = f"https://raw.githubusercontent.com/{repo_slug}/{branch}/{path}"
        return self.fetcher.fetch(raw_url)

    def fetch_raw_url(self, url: str) -> Optional[str]:
        """Fetches content from a direct raw URL."""
        return self.fetcher.fetch(url)

    def fetch_preset(self, preset_name: str) -> Optional[str]:
        """Belirli bir preset'ten IOC verisi çeker."""
        if preset_name not in GITHUB_PRESETS:
            logger.error(f"Bilinmeyen GitHub preset: {preset_name}")
            logger.info(f"Mevcut preset'ler: {', '.join(GITHUB_PRESETS.keys())}")
            return None

        preset = GITHUB_PRESETS[preset_name]
        logger.info(f"GitHub preset çekiliyor: {preset_name} ({preset['description']})")
        return self.fetch_from_repo(
            repo_slug=preset["repo"],
            branch=preset["branch"],
            path=preset["path"],
        )

    def fetch_all_presets(self) -> Optional[str]:
        """Tüm GitHub preset'lerinden veri çeker ve birleştirir."""
        parts = []
        for name, preset in GITHUB_PRESETS.items():
            try:
                content = self.fetch_preset(name)
                if content:
                    parts.append(f"# --- {name}: {preset['description']} ---\n{content}")
            except Exception as e:
                logger.error(f"GitHub preset {name} hatası: {e}")

        if parts:
            return "\n\n".join(parts)
        return None

    @staticmethod
    def list_presets() -> List[Dict[str, str]]:
        """Mevcut preset'leri listeler."""
        result = []
        for name, info in GITHUB_PRESETS.items():
            result.append({
                "name": name,
                "repo": info["repo"],
                "description": info["description"],
            })
        return result

