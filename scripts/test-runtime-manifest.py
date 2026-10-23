#!/usr/bin/env python3
"""Verify pinned-download failure behavior without network access."""
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('runtime_manifest', Path(__file__).with_name('runtime-manifest.py'))
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class Response(io.BytesIO):
    url = 'https://release-assets.githubusercontent.com/verified-asset'


class RuntimePins(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'core.zip'
        self.artifact = {'filename': 'core.zip', 'url': 'https://github.com/official/core.zip',
                         'sha256': hashlib.sha256(b'expected release').hexdigest()}

    def test_manifest_has_immutable_platform_pins(self):
        data = runtime.manifest()
        self.assertIn('windows-amd64', data['sing_box']['artifacts'])
        self.assertIn('linux-arm64', data['sing_box']['artifacts'])

    def test_verified_cache_never_fetches_again(self):
        self.path.write_bytes(b'expected release')
        with patch.object(runtime.urllib.request, 'urlopen', side_effect=AssertionError('network')):
            runtime.download(self.artifact, self.path)

    def test_tampered_download_does_not_replace_previous_file(self):
        self.path.write_bytes(b'previous release')
        with patch.object(runtime.urllib.request, 'urlopen', return_value=Response(b'tampered')):
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                runtime.download(self.artifact, self.path)
        self.assertEqual(self.path.read_bytes(), b'previous release')
        self.assertEqual(list(self.path.parent.glob('*.part')), [])

    def test_verified_download_replaces_as_one_file(self):
        self.path.write_bytes(b'previous release')
        with patch.object(runtime.urllib.request, 'urlopen', return_value=Response(b'expected release')):
            runtime.download(self.artifact, self.path)
        self.assertEqual(self.path.read_bytes(), b'expected release')

    def test_insecure_redirect_cannot_replace_cache(self):
        response = Response(b'expected release'); response.url = 'http://mirror.invalid/core.zip'
        with patch.object(runtime.urllib.request, 'urlopen', return_value=response):
            with self.assertRaisesRegex(ValueError, 'insecure'):
                runtime.download(self.artifact, self.path)
        self.assertFalse(self.path.exists())


if __name__ == '__main__':
    unittest.main()
