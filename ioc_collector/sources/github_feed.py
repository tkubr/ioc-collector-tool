
from typing import Optional
from ioc_collector.sources.remote_fetcher import RemoteFetcher

class GitHubFeed:
    def __init__(self, fetcher: RemoteFetcher):
        self.fetcher = fetcher

    def fetch_from_repo(self, repo_slug: str, branch: str = "master", path: str = "trails/static/malware/malware.txt") -> Optional[str]:

        """Fetches a file from GitHub."""
        # Default path is for maltrail
        
        raw_url = f"https://raw.githubusercontent.com/{repo_slug}/{branch}/{path}"
        return self.fetcher.fetch(raw_url)

    def fetch_raw_url(self, url: str) -> Optional[str]:
        """Fetches content from a direct raw URL."""
        return self.fetcher.fetch(url)
