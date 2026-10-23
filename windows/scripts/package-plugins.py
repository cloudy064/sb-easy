"""Build signed-catalog plugin artifacts without rewriting legacy host pins.

Private signing keys remain external. By default this writes a reviewable payload;
--private-key/--key-id/--keys explicitly signs it with the shared publisher tool.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import time
from urllib.parse import urlsplit
import zipfile

ROOT = Path(__file__).resolve().parents[2]
LAYOUTS = {
    'capture': ['extension.json', 'sb-easy-capture.exe', 'capture/WinDivert.dll', 'capture/WinDivert64.sys',
                'licenses/WinDivert.txt', 'licenses/libpcap.txt', 'licenses/vue.txt', 'licenses/sbj-grisu2-MIT.txt'],
    'statistics': ['extension.json', 'sb-easy-statistics.exe', 'licenses/vue.txt', 'licenses/tldts.txt', 'licenses/tldts-core.txt', 'licenses/sbj-grisu2-MIT.txt'],
    'http-debug': ['extension.json', 'sb-easy-http-debug.exe', 'licenses/http-debug.txt', 'licenses/vue.txt'],
}
PERMISSIONS = {'capture': ['private-files', 'packet-capture', 'kernel-driver-broker'],
               'statistics': ['private-files', 'traffic-metadata'],
               'http-debug': ['private-files', 'internet', 'tls-intercept']}


def publisher():
    spec = importlib.util.spec_from_file_location('plugin_catalog', ROOT / 'extensions/catalog/publish.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build(repo, destination, base_url, sequence, now, expires, capture_archive=None):
    helper = publisher()
    address = urlsplit(base_url)
    if address.scheme != 'https' or not address.hostname or address.username or address.password or address.query or address.fragment or '\\' in base_url:
        raise ValueError('Artifact base URL must be credential-free HTTPS without a query or fragment')
    if any(ord(c) < 33 or ord(c) == 127 for c in base_url):
        raise ValueError('Artifact base URL contains whitespace/control characters')
    destination.mkdir(parents=True, exist_ok=True)
    releases = []
    for plugin, names in LAYOUTS.items():
        manifest_data = (repo / f'windows/extensions/{plugin}/extension.json').read_bytes()
        manifest = helper.strict_json(manifest_data, 4096)
        helper.version(manifest.get('version'))
        if manifest.get('id') != plugin or manifest.get('api_version') != 1 or type(manifest.get('build')) is not int or not 2 <= manifest['build'] <= 2100000000:
            raise ValueError(f'{plugin}: expected manifest ID, API 1 and an explicit new build number >= 2')
        paths = ['extension/' + name for name in names] + ['view/view.js', 'view/view.css']
        bundle = bytearray(b'SBECP001')
        archive_path = capture_archive or repo / f'build/sb-easy-capture-{manifest["version"]}-windows-x64.zip'
        archive = zipfile.ZipFile(archive_path) if plugin == 'capture' else None
        try:
            if archive and len(archive.namelist()) != len(set(archive.namelist())):
                raise ValueError('Capture archive has duplicate entries')
            for path in paths:
                folder, relative = path.split('/', 1)
                if archive:
                    data = archive.read(('payload/' if folder == 'extension' else 'ui/') + relative)
                elif folder == 'view':
                    data = (repo / f'windows/ui/dist-{plugin}' / relative).read_bytes()
                elif relative == 'extension.json':
                    data = manifest_data
                elif relative.startswith('licenses/'):
                    data = (repo / 'build/windows-release' / relative).read_bytes()
                else:
                    data = (repo / f'build/windows-release/extensions/{plugin}' / relative).read_bytes()
                if relative == 'extension.json' and data != manifest_data:
                    raise ValueError(f'{plugin}: rebuild the worker archive; its manifest is stale')
                if folder == 'view' and relative == 'view.js' and re.search(rb'\bprocess\.env\b', data):
                    raise ValueError(f'{plugin}: UI still contains Node environment references')
                if not data or len(data) > 160 * 1024 * 1024:
                    raise ValueError(f'{plugin}: invalid file size for {relative}')
                bundle += struct.pack('<I', len(data)) + data
        finally:
            if archive:
                archive.close()
        if len(bundle) > 160 * 1024 * 1024:
            raise ValueError(f'{plugin}: package exceeds the host limit')
        digest = hashlib.sha256(bundle).hexdigest()
        name = f'{plugin}-{manifest["version"]}-{manifest["build"]}-{digest[:16]}.sbe'
        (destination / name).write_bytes(bundle)
        releases.append(dict(id=plugin, platform='windows', version=manifest['version'], build=manifest['build'], abi='x86_64', api=1,
                             min_host='0.7.0', max_host='1.0.0', min_core='1.14.0', max_core='1.15.0', min_os=19041,
                             url=base_url.rstrip('/') + '/' + name, sha256=digest, bytes=len(bundle), package='', signer_sha256='', permissions=PERMISSIONS[plugin]))
    payload = dict(sequence=sequence, issued_at=now, expires_at=expires, releases=releases, revocations=[])
    helper.validate_payload(payload, now=now)
    return payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', required=True)
    parser.add_argument('--sequence', type=int, required=True)
    parser.add_argument('--expires-days', type=int, default=30)
    parser.add_argument('--output', type=Path, default=ROOT / 'build/plugin-release')
    parser.add_argument('--capture-package', type=Path)
    parser.add_argument('--revocations', type=Path, help='Reviewed JSON array; previously issued revocations must remain in publisher history')
    parser.add_argument('--private-key', type=Path)
    parser.add_argument('--key-id')
    parser.add_argument('--keys', type=Path)
    args = parser.parse_args()
    if any((args.private_key, args.key_id, args.keys)) and not all((args.private_key, args.key_id, args.keys)):
        parser.error('Signing requires --private-key, --key-id and --keys together')
    if not 1 <= args.expires_days <= 90:
        parser.error('--expires-days must be 1..90')
    now = int(time.time())
    payload = build(ROOT, args.output, args.base_url, args.sequence, now, now + args.expires_days * 86400, args.capture_package)
    helper = publisher()
    if args.revocations:
        payload['revocations'] = helper.strict_json(args.revocations.read_bytes(), 512 * 1024)
    helper.validate_payload(payload, now=now)
    data = json.dumps(payload, ensure_ascii=False, indent=2).encode('utf-8')
    (args.output / 'catalog-payload.json').write_bytes(data)
    if args.private_key:
        keys = helper.trust_keys(args.keys.read_bytes())
        envelope = helper.sign(data, args.private_key, args.key_id, keys, now=now, artifact_root=args.output)
        (args.output / 'catalog.json').write_bytes(envelope)
    print(args.output / ('catalog.json' if args.private_key else 'catalog-payload.json'))


if __name__ == '__main__':
    main()
