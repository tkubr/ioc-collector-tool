"""
GitHub Feed Preset Test Suite
GitHub preset sistemi, fetch_preset, list_presets ve CLI argüman testleri.
"""

import unittest
from unittest.mock import MagicMock
from ioc_collector.sources.github_feed import GitHubFeed, GITHUB_PRESETS
from ioc_collector.sources.remote_fetcher import RemoteFetcher


class TestGitHubPresets(unittest.TestCase):
    def test_presets_dict_has_all_entries(self):
        expected = ["maltrail", "misp_warninglists", "firehol", "yaraify",
                     "threathunter", "eset_apt", "malpedia"]
        for name in expected:
            self.assertIn(name, GITHUB_PRESETS)
            self.assertIn("repo", GITHUB_PRESETS[name])
            self.assertIn("branch", GITHUB_PRESETS[name])
            self.assertIn("path", GITHUB_PRESETS[name])
            self.assertIn("description", GITHUB_PRESETS[name])

    def test_list_presets(self):
        presets = GitHubFeed.list_presets()
        self.assertIsInstance(presets, list)
        self.assertEqual(len(presets), len(GITHUB_PRESETS))
        names = [p["name"] for p in presets]
        self.assertIn("maltrail", names)
        self.assertIn("firehol", names)


class TestFetchPreset(unittest.TestCase):
    def setUp(self):
        self.fetcher = MagicMock(spec=RemoteFetcher)
        self.feed = GitHubFeed(self.fetcher)

    def test_fetch_known_preset(self):
        self.fetcher.fetch.return_value = "1.2.3.4\n5.6.7.8\n"
        result = self.feed.fetch_preset("firehol")
        self.assertIsNotNone(result)
        self.assertIn("1.2.3.4", result)
        # URL doğru oluşturulmalı
        call_url = self.fetcher.fetch.call_args[0][0]
        self.assertIn("firehol/blocklist-ipsets", call_url)
        self.assertIn("firehol_level1.netset", call_url)

    def test_fetch_unknown_preset_returns_none(self):
        result = self.feed.fetch_preset("nonexistent")
        self.assertIsNone(result)

    def test_fetch_maltrail_preset(self):
        self.fetcher.fetch.return_value = "evil-domain.com\nbad-host.net\n"
        result = self.feed.fetch_preset("maltrail")
        self.assertIsNotNone(result)
        call_url = self.fetcher.fetch.call_args[0][0]
        self.assertIn("stamparm/maltrail", call_url)

    def test_fetch_misp_preset(self):
        self.fetcher.fetch.return_value = '{"list": ["disposable@example.com"]}'
        result = self.feed.fetch_preset("misp_warninglists")
        self.assertIsNotNone(result)
        call_url = self.fetcher.fetch.call_args[0][0]
        self.assertIn("MISP/misp-warninglists", call_url)


class TestFetchAllPresets(unittest.TestCase):
    def setUp(self):
        self.fetcher = MagicMock(spec=RemoteFetcher)
        self.feed = GitHubFeed(self.fetcher)

    def test_fetch_all_presets(self):
        self.fetcher.fetch.return_value = "mock data"
        result = self.feed.fetch_all_presets()
        self.assertIsNotNone(result)
        self.assertEqual(self.fetcher.fetch.call_count, len(GITHUB_PRESETS))

    def test_fetch_all_returns_none_when_all_fail(self):
        self.fetcher.fetch.return_value = None
        result = self.feed.fetch_all_presets()
        self.assertIsNone(result)


class TestCLIGitHubPresetArg(unittest.TestCase):
    def test_github_preset_argument(self):
        from ioc_collector.cli import create_parser
        parser = create_parser()
        args = parser.parse_args(["--github-feed-preset", "firehol"])
        self.assertEqual(args.github_feed_preset, "firehol")

    def test_github_preset_all(self):
        from ioc_collector.cli import create_parser
        parser = create_parser()
        args = parser.parse_args(["--github-feed-preset", "all"])
        self.assertEqual(args.github_feed_preset, "all")


if __name__ == "__main__":
    unittest.main()
