import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('app_catalog_publish', ROOT / 'updates/android/publish.py')
catalog = importlib.util.module_from_spec(spec); spec.loader.exec_module(catalog)


class AppCatalogTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='sb-app-catalog-test-'); cls.folder = Path(cls.temp.name)
        cls.private = cls.folder / 'ephemeral.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', str(cls.private)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        der = catalog.common.openssl(['pkey', '-in', str(cls.private), '-pubout', '-outform', 'DER'])
        cls.keys_data = json.dumps({'format': catalog.FORMAT + '.keys', 'version': 1, 'keys': {'test-only': base64.b64encode(der).decode()}}).encode()
        cls.keys = catalog.trust_keys(cls.keys_data); cls.now = int(time.time())
        cls.payload = {'sequence': 7, 'issued_at': cls.now - 60, 'expires_at': cls.now + 3600,
                       'releases': [{'version': '1.4.0', 'build': 29, 'min_os': 24, 'abis': ['arm64-v8a'], 'package': 'io.sbeasy.android',
                                     'signer_sha256': 'a' * 64, 'url': 'https://download.example.invalid/app.apk', 'sha256': 'b' * 64, 'bytes': 1234,
                                     'core_version': '1.14.3', 'source_revision': 'c' * 40, 'provenance_sha256': 'd' * 64}],
                       'revocations': [{'build': 1, 'reason': '旧构建撤销'}]}
        cls.raw = json.dumps(cls.payload, ensure_ascii=False, indent=2).encode()
        cls.signed = catalog.sign(cls.raw, cls.private, 'test-only', cls.keys, cls.now)
        cls.fixtures = ROOT / 'build/app-catalog-fixtures'; cls.fixtures.mkdir(parents=True, exist_ok=True)
        (cls.fixtures / 'catalog.json').write_bytes(cls.signed); (cls.fixtures / 'keys.json').write_bytes(cls.keys_data)
        (cls.fixtures / 'test-info.json').write_text(json.dumps({'now': cls.now, 'sequence': 7, 'payload_sha256': hashlib.sha256(cls.raw).hexdigest()}))

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def test_exact_bytes_and_domain_separation(self):
        value, digest = catalog.verify(self.signed, self.keys, self.now)
        self.assertEqual(value, self.payload); self.assertEqual(digest, hashlib.sha256(self.raw).hexdigest())
        for prefix, salt, mgf, name in [(b'', 32, 'sha256', 'no-domain.json'), (catalog.PREFIX, 20, 'sha256', 'wrong-salt.json'), (catalog.PREFIX, 32, 'sha1', 'wrong-mgf.json')]:
            signature = catalog.common.openssl(['dgst', '-sha256', '-sign', str(self.private), '-sigopt', 'rsa_padding_mode:pss', '-sigopt', f'rsa_pss_saltlen:{salt}', '-sigopt', f'rsa_mgf1_md:{mgf}'], prefix + self.raw)
            envelope = json.loads(self.signed); envelope['signature'] = base64.b64encode(signature).decode()
            encoded = json.dumps(envelope).encode(); (self.fixtures / name).write_bytes(encoded)
            with self.assertRaises(ValueError): catalog.verify(encoded, self.keys, self.now)
        envelope = json.loads(self.signed); envelope['payload'] = base64.b64encode(json.dumps(self.payload).encode()).decode()
        with self.assertRaises(ValueError): catalog.verify(json.dumps(envelope).encode(), self.keys, self.now)
        with self.assertRaises(ValueError): catalog.verify(self.signed, {}, self.now)

    def test_expiry_duplicate_json_and_separate_trust_config(self):
        with self.assertRaises(ValueError): catalog.verify(self.signed, self.keys, self.payload['expires_at'])
        catalog.verify(self.signed, self.keys, self.payload['expires_at'], False)
        for malformed in [self.signed[:-1] + b',"version":1}', self.signed + b'{}', b' ' * (1024 * 1024 + 1)]:
            with self.assertRaises(ValueError): catalog.verify(malformed, self.keys, self.now)
        wrong_keys = json.loads(self.keys_data); wrong_keys['format'] = 'sb-easy.plugin-catalog.keys'
        with self.assertRaises(ValueError): catalog.trust_keys(json.dumps(wrong_keys).encode())

    def test_unsigned_metadata_and_conflicting_builds_are_rejected(self):
        for field, value in [('package', 'evil.app'), ('url', 'http://example.test/app.apk'), ('url', 'https://@example.test/app.apk'), ('url', 'https://example.test/app.apk#'),
                             ('abis', ['x86', 'x86']), ('abis', ['mips']), ('build', True), ('min_os', 23), ('source_revision', 'abc'), ('provenance_sha256', '0' * 63), ('extra', True)]:
            altered = json.loads(self.raw); altered['releases'][0][field] = value
            with self.assertRaises(ValueError, msg=field): catalog.validate_payload(altered, self.now)
        altered = json.loads(self.raw); second = dict(altered['releases'][0]); second['abis'] = ['x86_64']; second['core_version'] = '1.14.2'; altered['releases'].append(second)
        with self.assertRaises(ValueError): catalog.validate_payload(altered, self.now)


if __name__ == '__main__': unittest.main()
