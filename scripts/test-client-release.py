#!/usr/bin/env python3
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("client_release", ROOT / "scripts/client-release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseInventoryTest(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT / "config/client-releases.json").read_text())

    def test_published_and_development_are_separate(self):
        release.validate(self.data)
        major, minor, patch = release.version(self.data["published"]["android"]["version"])
        self.data["development"]["android"]["version"] = f"{major}.{minor}.{patch + 1}"
        self.data["development"]["android"]["version_code"] = self.data["published"]["android"]["version_code"]
        with self.assertRaises(ValueError):
            release.validate(self.data)

    def test_current_source_can_be_published_without_inventing_a_future_version(self):
        published = self.data["published"]["android"]
        self.data["development"]["android"] = {"version": published["version"], "version_code": published["version_code"]}
        release.validate(self.data)
        self.data["development"]["android"]["version_code"] += 1
        with self.assertRaises(ValueError):
            release.validate(self.data)

    def test_redirected_or_incomplete_inventory_is_rejected(self):
        original = copy.deepcopy(self.data)
        self.data["published"]["android"]["artifacts"][0]["url"] = "https://other.invalid/app.apk"
        with self.assertRaises(ValueError):
            release.validate(self.data)
        original["published"]["android"]["artifacts"].pop()
        with self.assertRaises(ValueError):
            release.validate(original)

    def test_withdrawn_platform_and_stable_channel_are_valid(self):
        del self.data["published"]["android"]
        self.data["published"]["windows"]["channel"] = "stable"
        release.validate(self.data)
        self.data["published"]["windows"]["features"] = {"packet_capture": "false"}
        with self.assertRaises(ValueError):
            release.validate(self.data)

    def test_remote_asset_replacement_is_detected(self):
        expected = self.data["published"]["windows"]
        actual = {"draft": False, "tag_name": expected["tag"], "html_url": expected["release_url"], "assets": [
            {"name": a["name"], "state": "uploaded", "size": a["size"], "digest": "sha256:" + a["sha256"], "browser_download_url": a["url"]}
            for a in expected["artifacts"]] + [
            {"name": "source", "state": "uploaded", "browser_download_url": expected["source_url"]},
            {"name": "checksums", "state": "uploaded", "browser_download_url": expected["checksums_url"]}]}
        release.compare_published(expected, actual)
        actual["assets"][0]["digest"] = "sha256:" + "0" * 64
        with self.assertRaises(ValueError):
            release.compare_published(expected, actual)


if __name__ == "__main__":
    unittest.main()
