#!/usr/bin/env python3
"""Prepare and sign Android app catalogs with external release keys and actual APK checks."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import time
import zipfile
from urllib.parse import urlsplit, unquote

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('plugin_catalog', ROOT / 'extensions/catalog/publish.py')
common = importlib.util.module_from_spec(spec); spec.loader.exec_module(common)
PREFIX = b'sb-easy.app-catalog/v1\n'
FORMAT = 'sb-easy.app-catalog'
ABIS = {'arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64'}
RELEASE_FIELDS = {'version', 'build', 'min_os', 'abis', 'package', 'signer_sha256', 'url', 'sha256', 'bytes', 'core_version', 'source_revision', 'provenance_sha256'}


def validate_payload(value, now=None, require_fresh=True):
    common.keys(value, {'sequence', 'issued_at', 'expires_at', 'releases', 'revocations'})
    common.integer(value['sequence'], 1, 9007199254740991)
    common.integer(value['issued_at'], 1, 4102444800); common.integer(value['expires_at'], 1, 4102444800)
    common.require(0 < value['expires_at'] - value['issued_at'] <= 90 * 86400, 'Invalid catalog validity')
    if require_fresh:
        now = int(time.time()) if now is None else now
        common.require(value['issued_at'] <= now + 300 and value['expires_at'] > now, 'Catalog expired or not yet valid')
    common.require(type(value['releases']) is list and len(value['releases']) <= 128, 'Too many app releases')
    seen = set(); identities = {}
    for release in value['releases']:
        common.keys(release, RELEASE_FIELDS)
        common.version(release['version']); common.version(release['core_version'])
        common.integer(release['build'], 1, 2100000000); common.integer(release['min_os'], 24, 999)
        abis = release['abis']; common.require(type(abis) is list and 1 <= len(abis) <= 4 and all(type(abi) is str for abi in abis), 'Invalid ABIs')
        common.require(len(set(abis)) == len(abis) and set(abis) <= ABIS, 'Duplicate or unsupported ABI')
        common.require(release['package'] == 'io.sbeasy.android', 'Wrong application package')
        for name in ('signer_sha256', 'sha256', 'provenance_sha256'):
            common.require(type(release[name]) is str and common.SHA256.fullmatch(release[name]), 'Invalid SHA-256')
        common.require(type(release['source_revision']) is str and re.fullmatch('[0-9a-f]{40}', release['source_revision']), 'Invalid source revision')
        common.integer(release['bytes'], 1, 160 * 1024 * 1024)
        raw = release['url']; common.require(type(raw) is str and len(raw) <= 4096 and not any(c.isspace() or ord(c) < 32 for c in raw), 'Invalid URL')
        url = urlsplit(raw)
        common.require(url.scheme == 'https' and url.hostname and url.username is None and url.password is None and '#' not in raw, 'HTTPS URL required')
        if url.port is not None: common.integer(url.port, 1, 65535)
        identity = release['build'], frozenset(abis)
        common.require(identity not in seen, 'Duplicate build/ABI'); seen.add(identity)
        details = tuple(release[name] for name in ('version', 'signer_sha256', 'core_version', 'source_revision', 'provenance_sha256', 'min_os'))
        common.require(release['build'] not in identities or identities[release['build']] == details, 'Conflicting build identity')
        identities[release['build']] = details
    common.require(type(value['revocations']) is list and len(value['revocations']) <= 256, 'Too many revocations')
    seen = set()
    for record in value['revocations']:
        common.keys(record, {'build', 'reason'}); common.integer(record['build'], 1, 2100000000)
        reason = record['reason']; common.require(type(reason) is str and 1 <= len(reason) <= 240 and not any(ord(c) < 32 or ord(c) == 127 for c in reason), 'Invalid reason')
        common.require(record['build'] not in seen, 'Duplicate revocation'); seen.add(record['build'])
    return value


def trust_keys(data):
    return common.trust_keys(data, FORMAT + '.keys')


def verify(data, keys, now=None, require_fresh=True):
    return common.verify(data, keys, now, require_fresh, format_name=FORMAT, prefix=PREFIX, validator=validate_payload)


def sign(data, private_key, key_id, keys, now=None, artifact_root=None):
    return common.sign(data, private_key, key_id, keys, now, artifact_root, format_name=FORMAT, prefix=PREFIX, validator=validate_payload)


def file_digest(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def inspect_apk(path, url, build_tools):
    import subprocess
    details = subprocess.check_output([str(build_tools / 'aapt2'), 'dump', 'badging', str(path)], text=True)
    package = re.search(r"^package: name='([^']+)' versionCode='([0-9]+)' versionName='([^']+)'", details, re.M)
    sdk = re.search(r"^(?:sdkVersion|minSdkVersion):'([0-9]+)'", details, re.M)
    common.require(package and sdk, 'APK package/SDK metadata missing')
    signing = subprocess.check_output([str(build_tools / 'apksigner'), 'verify', '--verbose', '--print-certs', str(path)], text=True)
    certificates = re.findall(r'^Signer #[0-9]+ certificate SHA-256 digest: ([0-9a-f]{64})$', signing, re.M)
    common.require(len(certificates) == 1, 'App APK must have one current signer')
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist(); common.require(len(names) == len(set(names)) and len(names) <= 20000, 'Duplicate ZIP entries')
        asset = archive.getinfo('assets/libbox-provenance.json'); common.require(0 < asset.file_size <= 65536, 'Provenance too large')
        raw = archive.read(asset); provenance = common.strict_json(raw, 65536)
        common.keys(provenance, {'format', 'version', 'source_kind', 'core_version', 'source_revision', 'overlay_sha256', 'source_changes_sha256', 'toolchain', 'aar_sha256', 'native_sha256'})
        common.require(provenance['format'] == 'sb-easy.libbox-provenance' and type(provenance['version']) is int and provenance['version'] == 1 and provenance['source_kind'] == 'local-pinned-build', 'Unrecognized libbox provenance')
        common.require(set(provenance['native_sha256']) == ABIS, 'Incomplete native provenance')
        for name in ('aar_sha256', 'overlay_sha256', 'source_changes_sha256'):
            common.require(common.SHA256.fullmatch(provenance[name]), 'Invalid build-input digest')
        common.keys(provenance['toolchain'], {'go', 'gomobile', 'ndk'})
        common.require(all(type(value) is str and 1 <= len(value) <= 256 for value in provenance['toolchain'].values()), 'Invalid toolchain')
        abis = {name.split('/')[1] for name in names if name.startswith('lib/') and name.endswith('.so')}
        common.require(abis and abis <= ABIS, 'Unsupported APK native architecture')
        for abi in abis:
            info = archive.getinfo(f'lib/{abi}/libbox.so'); common.require(0 < info.file_size <= 192 * 1024 * 1024, 'Oversized libbox')
            with archive.open(info) as stream:
                common.require(hashlib.file_digest(stream, 'sha256').hexdigest() == provenance['native_sha256'][abi], 'APK libbox differs from provenance')
    release = {'version': package[3], 'build': int(package[2]), 'min_os': int(sdk[1]), 'abis': sorted(abis), 'package': package[1],
               'signer_sha256': certificates[0], 'url': url, 'sha256': file_digest(path), 'bytes': path.stat().st_size,
               'core_version': provenance['core_version'], 'source_revision': provenance['source_revision'], 'provenance_sha256': hashlib.sha256(raw).hexdigest()}
    now = int(time.time()); validate_payload({'sequence': 1, 'issued_at': now, 'expires_at': now + 60, 'releases': [release], 'revocations': []})
    return release


def main():
    parser = argparse.ArgumentParser(description=__doc__); commands = parser.add_subparsers(dest='command', required=True)
    trust = commands.add_parser('trust'); trust.add_argument('--public-key', type=Path, required=True); trust.add_argument('--key-id', required=True); trust.add_argument('--output', type=Path, required=True)
    inspect = commands.add_parser('release'); inspect.add_argument('--apk', type=Path, required=True); inspect.add_argument('--url', required=True); inspect.add_argument('--build-tools', type=Path, required=True); inspect.add_argument('--output', type=Path, required=True)
    signer = commands.add_parser('sign'); signer.add_argument('--payload', type=Path, required=True); signer.add_argument('--private-key', type=Path, required=True); signer.add_argument('--key-id', required=True); signer.add_argument('--output', type=Path, required=True); signer.add_argument('--artifact-root', type=Path, required=True); signer.add_argument('--build-tools', type=Path, required=True)
    verifier = commands.add_parser('verify'); verifier.add_argument('--catalog', type=Path, required=True)
    for command in (signer, verifier): command.add_argument('--keys', type=Path, required=True); command.add_argument('--now', type=int)
    args = parser.parse_args()
    if args.command == 'trust':
        common.identifier(args.key_id); der = common.openssl(['pkey', '-pubin', '-in', str(args.public_key), '-outform', 'DER'])
        data = json.dumps({'format': FORMAT + '.keys', 'version': 1, 'keys': {args.key_id: base64.b64encode(der).decode()}}, indent=2).encode()
        trust_keys(data); args.output.write_bytes(data + b'\n'); return
    if args.command == 'release':
        args.output.write_text(json.dumps(inspect_apk(args.apk, args.url, args.build_tools), indent=2) + '\n'); return
    keys = trust_keys(args.keys.read_bytes())
    if args.command == 'sign':
        data = args.payload.read_bytes(); payload = validate_payload(common.strict_json(data, common.MAX_PAYLOAD), args.now)
        for release in payload['releases']:
            name = unquote(urlsplit(release['url']).path.rsplit('/', 1)[-1]); common.require(name and '/' not in name and '\\' not in name and name not in ('.', '..'), 'Unsafe artifact name')
            common.require(inspect_apk(args.artifact_root / name, release['url'], args.build_tools) == release, 'Actual APK metadata differs from payload')
        args.output.write_bytes(sign(data, args.private_key, args.key_id, keys, args.now, args.artifact_root) + b'\n')
    else:
        payload, digest = verify(args.catalog.read_bytes(), keys, args.now); print(json.dumps({'sequence': payload['sequence'], 'payload_sha256': digest}))


if __name__ == '__main__':
    try: main()
    except (ValueError, OSError, KeyError, TypeError, zipfile.BadZipFile) as error:
        print(f'App catalog rejected: {error}', file=sys.stderr); sys.exit(2)
