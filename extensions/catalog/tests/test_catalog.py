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
spec = importlib.util.spec_from_file_location('catalog_publish', Path(__file__).resolve().parents[1] / 'publish.py')
catalog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(catalog)


class CatalogTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='sb-catalog-signing-test-')
        cls.folder = Path(cls.temp.name)
        cls.private = cls.folder / 'test-only.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', str(cls.private)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        public = catalog.openssl(['pkey', '-in', str(cls.private), '-pubout', '-outform', 'DER'])
        cls.keys_data = json.dumps({'format': 'sb-easy.plugin-catalog.keys', 'version': 1, 'keys': {'test-only': base64.b64encode(public).decode()}}).encode()
        cls.keys = catalog.trust_keys(cls.keys_data)
        cls.now = int(time.time())
        artifact = b'NON-EXECUTABLE PLUGIN CATALOG TEST ARTIFACT\n'
        cls.artifact = cls.folder / 'plugin-test.bin'; cls.artifact.write_bytes(artifact)
        cls.payload = {'sequence': 42, 'issued_at': cls.now - 60, 'expires_at': cls.now + 86400,
                       'releases': [{'id': 'http-debug', 'platform': 'android', 'version': '1.0.1', 'build': 2,
                                     'abi': 'x86_64', 'api': 2, 'min_host': '1.3.4', 'max_host': '2.0.0',
                                     'min_core': '1.14.0', 'max_core': '1.15.0', 'min_os': 24,
                                     'url': 'https://downloads.example.invalid/plugin-test.bin', 'sha256': hashlib.sha256(artifact).hexdigest(),
                                     'bytes': len(artifact), 'package': 'io.sbeasy.httpdebug', 'signer_sha256': '0' * 64,
                                     'permissions': ['internet', 'private-files', 'tls-intercept']}],
                       'revocations': [{'id': 'http-debug', 'platform': 'android', 'build': 1, 'reason': '旧版不再受支持'}]}
        # Deliberately retain whitespace/non-ASCII: consumers must verify the exact bytes.
        cls.raw = json.dumps(cls.payload, ensure_ascii=False, indent=2).encode()
        cls.signed = catalog.sign(cls.raw, cls.private, 'test-only', cls.keys, cls.now, cls.folder)
        fixtures = ROOT / 'build' / 'plugin-catalog-fixtures'; fixtures.mkdir(parents=True, exist_ok=True)
        (fixtures / 'catalog.json').write_bytes(cls.signed)
        (fixtures / 'keys.json').write_bytes(cls.keys_data)
        (fixtures / 'payload.json').write_bytes(cls.raw)
        (fixtures / 'test-info.json').write_text(json.dumps({'now': cls.now, 'sequence': 42, 'payload_sha256': hashlib.sha256(cls.raw).hexdigest()}))
        # No private key or executable is exported to the shared fixture directory.
        cls.fixtures = fixtures

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def test_actual_openssl_round_trip_and_noncanonical_payload(self):
        payload, digest = catalog.verify(self.signed, self.keys, self.now)
        self.assertEqual(payload, self.payload)
        self.assertEqual(digest, hashlib.sha256(self.raw).hexdigest())
        envelope = json.loads(self.signed)
        envelope['payload'] = base64.b64encode(json.dumps(self.payload).encode()).decode()
        with self.assertRaises(ValueError): catalog.verify(json.dumps(envelope).encode(), self.keys, self.now)

    def test_tamper_wrong_key_and_pss_parameters(self):
        original = json.loads(self.signed)
        for name, value in [('algorithm', 'rsa-sha1'), ('key_id', 'remote-injected-key'), ('version', 2), ('signature', base64.b64encode(b'x' * 256).decode())]:
            envelope = dict(original); envelope[name] = value
            with self.assertRaises(ValueError): catalog.verify(json.dumps(envelope).encode(), self.keys, self.now)
        for salt, mgf, name in [(20, 'sha256', 'wrong-salt.json'), (32, 'sha1', 'wrong-mgf.json')]:
            signature = catalog.openssl(['dgst', '-sha256', '-sign', str(self.private), '-sigopt', 'rsa_padding_mode:pss',
                                         '-sigopt', f'rsa_pss_saltlen:{salt}', '-sigopt', f'rsa_mgf1_md:{mgf}'], self.raw)
            envelope = dict(original); envelope['signature'] = base64.b64encode(signature).decode()
            encoded = json.dumps(envelope).encode(); (self.fixtures / name).write_bytes(encoded)
            with self.assertRaises(ValueError): catalog.verify(encoded, self.keys, self.now)

    def test_strict_json_limits_expiry_and_artifact_mismatch(self):
        with self.assertRaises(ValueError): catalog.verify(self.signed, self.keys, self.payload['expires_at'])
        catalog.verify(self.signed, self.keys, self.payload['expires_at'], require_fresh=False)
        duplicate = self.signed[:-1] + b',"version":1}'
        (self.fixtures / 'duplicate-key.json').write_bytes(duplicate)
        for malformed in (duplicate, self.signed + b'{}', b' ' * (catalog.MAX_ENVELOPE + 1)):
            with self.assertRaises(ValueError): catalog.verify(malformed, self.keys, self.now)
        self.artifact.write_bytes(b'changed')
        try:
            with self.assertRaises(ValueError): catalog.sign(self.raw, self.private, 'test-only', self.keys, self.now, self.folder)
        finally: self.artifact.write_bytes(b'NON-EXECUTABLE PLUGIN CATALOG TEST ARTIFACT\n')

    def test_release_capability_transport_and_compatibility_validation(self):
        for field, value in [('url', 'http://example.test/plugin.apk'), ('url', 'https://user:secret@example.test/plugin.apk'),
                             ('sha256', '0' * 63), ('permissions', ['internet', 'internet']), ('max_core', '1.14.0'),
                             ('build', True), ('version', '01.0.1'), ('extra', 'unsupported')]:
            payload = json.loads(self.raw); payload['releases'][0][field] = value
            with self.assertRaises((ValueError, TypeError)): catalog.validate_payload(payload, self.now)


if __name__ == '__main__': unittest.main()
