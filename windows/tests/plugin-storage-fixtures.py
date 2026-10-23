#!/usr/bin/env python3
"""Ephemeral signed packages for the native store tests; never production keys."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time

root = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('catalog', root / 'extensions/catalog/publish.py')
catalog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(catalog)
output = Path(sys.argv[1]).resolve()
output.mkdir(parents=True, exist_ok=True)
worker = Path(sys.argv[2]).read_bytes() if len(sys.argv) > 2 else None
now = int(time.time())
with tempfile.TemporaryDirectory(prefix='sbeasy-plugin-tests-') as temporary:
    key = Path(temporary) / 'key.pem'
    subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', str(key)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    der = subprocess.check_output(['openssl', 'pkey', '-in', str(key), '-pubout', '-outform', 'DER'])
    keys = {'format': 'sb-easy.plugin-catalog.keys', 'version': 1, 'keys': {'ephemeral-test': base64.b64encode(der).decode()}}
    (output / 'keys.json').write_text(json.dumps(keys), encoding='utf-8')
    (output / 'plugin_trust_keys.h').write_text('#define SBW_PLUGIN_CATALOG_KEYS ' + json.dumps(json.dumps(keys)) + '\n', encoding='utf-8')
    releases = []
    for build in (2, 3, 4):
        manifest = json.dumps({'id': 'statistics', 'name': 'Test statistics', 'version': f'1.0.{build}', 'build': build, 'api_version': 1}).encode()
        files = [manifest, worker or b'fixture executable bytes ' + bytes([build]), b'vue license', b'tldts license', b'tldts-core license', b'json license', b'// test view', b'/* test CSS */']
        artifact = b'SBECP001' + b''.join(struct.pack('<I', len(f)) + f for f in files)
        (output / f'package-{build}.sbe').write_bytes(artifact)
        releases.append({'id': 'statistics', 'platform': 'windows', 'version': f'1.0.{build}', 'build': build, 'abi': 'x86_64', 'api': 1,
                         'min_host': '0.6.9', 'max_host': '1.0.0', 'min_core': '1.14.0', 'max_core': '1.15.0', 'min_os': 0,
                         'url': f'https://invalid.example/package-{build}.sbe', 'sha256': hashlib.sha256(artifact).hexdigest(), 'bytes': len(artifact),
                         'package': '', 'signer_sha256': '', 'permissions': ['private-files', 'traffic-metadata']})
    equivocation = dict(releases[1], sha256='0' * 64)
    variants = [('catalog-2', 2, [releases[0]], []), ('catalog-3', 3, releases[:2], []),
                ('catalog-4', 4, releases, [{'id': 'statistics', 'platform': 'windows', 'build': 3, 'reason': 'Test revocation'}]),
                ('catalog-5', 5, [releases[0]], []), ('catalog-6', 6, [equivocation], [])]
    for name, sequence, selected, revoked in variants:
        payload = {'sequence': sequence, 'issued_at': now - 30, 'expires_at': now + 30 * 86400, 'releases': selected, 'revocations': revoked}
        raw = json.dumps(payload, separators=(',', ':')).encode()
        envelope = catalog.sign(raw, key, 'ephemeral-test', {'ephemeral-test': subprocess.check_output(['openssl', 'pkey', '-in', str(key), '-pubout'])}, now=now)
        (output / f'{name}.json').write_bytes(envelope)
(output / 'ready').write_text('Only public test material remains.\n', encoding='utf-8')
