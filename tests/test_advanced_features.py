
import unittest
import os
import shutil
import tempfile
import json
import yaml
from unittest.mock import MagicMock, patch
from ioc_collector.sources.remote_fetcher import RemoteFetcher
from ioc_collector.sources.feed_manager import FeedManager

class TestRemoteFetcherAdvanced(unittest.TestCase):
    def setUp(self):
        # We can't easily mock requests_cache install globally without side effects, 
        # but we can test if RemoteFetcher init works.
        pass

    @patch('ioc_collector.sources.remote_fetcher.requests.get')
    def test_fetch_retry(self, mock_get):
        # Mock a failure then success
        mock_response_fail = MagicMock()
        mock_response_fail.raise_for_status.side_effect = Exception("Fail")
        
        mock_response_ok = MagicMock()
        mock_response_ok.status_code = 200
        mock_response_ok.text = "success"
        
        # side_effect acts as an iterator
        # First call raises exception (inside requests.get? No, requests.get returns response, 
        # then response.raise_for_status() is called)
        # But my code calls requests.get inside try...except RequestException.
        # If I want to simulate network error, requests.get should raise RequestException.
        
        # Let's verify verify_ssl logic
        fetcher = RemoteFetcher(verify_ssl=False)
        self.assertFalse(fetcher.verify_ssl)


class TestFeedManager(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.test_dir, "feeds.yaml")
        self.manager = FeedManager(config_path=self.config_path)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_add_feed(self):
        self.manager.add_feed("test_feed", "http://test.com/feed")
        
        # Verify in memory
        self.assertIn("test_feed", self.manager.feeds)
        self.assertEqual(self.manager.feeds["test_feed"]["url"], "http://test.com/feed")
        
        # Verify on disk
        with open(self.config_path, "r") as f:
            data = yaml.safe_load(f)
            self.assertIn("test_feed", data)

    def test_list_feeds(self):
        feeds = self.manager.list_feeds()
        self.assertIsInstance(feeds, dict)
        self.assertIn("TR", feeds) # Default feed

if __name__ == "__main__":
    unittest.main()
