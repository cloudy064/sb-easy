import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import time
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('packager', Path(__file__).resolve().parents[1] / 'scripts/package-plugins.py')
packager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packager)


class PluginPackageTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sb-plugin-package-')
        self.repo = Path(self.temp.name)
        self.output = self.repo / 'release'
        self.now = int(time.time())
        for plugin, names in packager.LAYOUTS.items():
            manifest = json.dumps(dict(id=plugin, version='1.1.0', build=2, api_version=1)).encode()
            path = self.repo / f'windows/extensions/{plugin}/extension.json'
            path.parent.mkdir(parents=True)
            path.write_bytes(manifest)
            if plugin == 'capture':
                path = self.repo / 'build/sb-easy-capture-1.1.0-windows-x64.zip'
                path.parent.mkdir(parents=True, exist_ok=True)
                with zipfile.ZipFile(path, 'w') as archive:
                    for name in names:
                        archive.writestr('payload/' + name, manifest if name == 'extension.json' else b'test artifact')
                    archive.writestr('ui/view.js', '// test')
                    archive.writestr('ui/view.css', '/* test */')
            else:
                for name in names:
                    if name == 'extension.json':
                        continue
                    path = self.repo / ('build/windows-release' if name.startswith('licenses/') else f'build/windows-release/extensions/{plugin}') / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b'test artifact')
                for name in ('view.js', 'view.css'):
                    path = self.repo / f'windows/ui/dist-{plugin}' / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b'/* test UI */')

    def tearDown(self):
        self.temp.cleanup()

    def build(self, url='https://releases.example.invalid/plugins'):
        return packager.build(self.repo, self.output, url, 12, self.now, self.now + 86400)

    def test_signed_metadata_matches_actual_archives_and_native_layout(self):
        payload = self.build()
        self.assertEqual(len(payload['releases']), 3)
        for release in payload['releases']:
            artifact = (self.output / release['url'].rsplit('/', 1)[1]).read_bytes()
            self.assertEqual(len(artifact), release['bytes'])
            self.assertEqual(hashlib.sha256(artifact).hexdigest(), release['sha256'])
            self.assertEqual(artifact[:8], b'SBECP001')
            offset, files = 8, []
            while offset < len(artifact):
                length, = struct.unpack_from('<I', artifact, offset)
                offset += 4
                files.append(artifact[offset:offset + length])
                offset += length
            self.assertEqual(offset, len(artifact))
            self.assertEqual(len(files), len(packager.LAYOUTS[release['id']]) + 2)
            manifest = json.loads(files[0])
            self.assertEqual((manifest['id'], manifest['version'], manifest['build']), (release['id'], release['version'], release['build']))
        self.assertFalse((self.repo / 'windows/service/store_catalog.h').exists())

    def test_transport_and_stale_capture_manifest_are_rejected(self):
        for url in ('http://example.test/plugins', 'https://user:secret@example.test/plugins', 'https://example.test/plugins?key=secret', 'https://example.test/plugins#hash'):
            with self.assertRaises(ValueError):
                self.build(url)
        path = self.repo / 'windows/extensions/capture/extension.json'
        manifest = json.loads(path.read_text())
        manifest['build'] = 3
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'manifest is stale'):
            self.build()


if __name__ == '__main__':
    unittest.main()
