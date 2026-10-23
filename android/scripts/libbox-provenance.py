#!/usr/bin/env python3
"""Record build inputs before compilation, and bind unchanged inputs to the resulting AAR."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[2]
ABIS = {'arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64'}


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')


def git(source, *args):
    return subprocess.check_output(['git', '-C', str(source), *args])


def overlay_digest(source=None):
    overlay = {}
    for path in sorted((ROOT / 'android/libbox-overlay').rglob('*.go')):
        relative = path.relative_to(ROOT / 'android/libbox-overlay')
        if source is not None and digest(path) != digest(source / relative):
            raise ValueError(f'Applied overlay differs from repository: {relative}')
        overlay[str(relative)] = digest(path)
    for name in ('apply-capture-overlay.py', 'build-capture-pcap.sh', 'build-libbox.sh', 'libbox-provenance.py'):
        overlay['scripts/' + name] = digest(ROOT / 'android/scripts' / name)
    overlay['libpcap-1.10.6.tar.xz'] = digest(ROOT / 'android/third_party/libpcap-1.10.6.tar.xz')
    return hashlib.sha256(encoded(overlay)).hexdigest()


def inputs(source):
    manifest = json.loads((ROOT / 'config/runtime-versions.json').read_text())
    revision = git(source, 'rev-parse', 'HEAD').decode().strip()
    if revision != manifest['sing_box']['source_revision']:
        raise ValueError('Source revision differs from pinned runtime manifest')
    overlay = overlay_digest(source)
    changes = hashlib.sha256(git(source, 'diff', '--binary', 'HEAD'))
    for raw in sorted(git(source, 'ls-files', '--others', '--exclude-standard', '-z').split(b'\0')):
        if not raw:
            continue
        name = raw.decode('utf-8')
        if name.startswith(('experimental/sbcapture/pcap-build/', 'experimental/sbcapture/pcap-source/')) or name == 'libbox.aar':
            continue
        path = source / name
        if path.is_file():
            changes.update(raw + b'\0' + bytes.fromhex(digest(path)))
    return {'format': 'sb-easy.libbox-provenance', 'version': 1, 'source_kind': 'local-pinned-build',
            'core_version': manifest['sing_box']['version'], 'source_revision': revision,
            'overlay_sha256': overlay, 'source_changes_sha256': changes.hexdigest(),
            'toolchain': {'go': subprocess.check_output(['go', 'version']).decode().strip(),
                          'gomobile': manifest['android']['gomobile_version'], 'ndk': manifest['android']['ndk_version']}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('prepare', 'finish', 'verify'))
    parser.add_argument('--source', type=Path)
    parser.add_argument('--stamp', type=Path)
    parser.add_argument('--aar', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'prepare':
        args.output.write_bytes(encoded(inputs(args.source)) + b'\n')
        return
    if args.command == 'finish':
        value = json.loads(args.stamp.read_bytes())
        if value != inputs(args.source):
            raise ValueError('Source or overlay changed during libbox compilation')
        if digest(args.aar) != digest(args.source / 'libbox.aar'):
            raise ValueError('Output AAR differs from the local build result')
        value['aar_sha256'] = digest(args.aar)
        with zipfile.ZipFile(args.aar) as archive:
            value['native_sha256'] = {abi: hashlib.sha256(archive.read(f'jni/{abi}/libbox.so')).hexdigest() for abi in sorted(ABIS)}
        args.output.write_bytes(encoded(value) + b'\n')
        return
    value = json.loads(args.output.read_bytes())
    manifest = json.loads((ROOT / 'config/runtime-versions.json').read_bytes())
    if value['format'] != 'sb-easy.libbox-provenance' or value['version'] != 1 or value['source_kind'] != 'local-pinned-build':
        raise ValueError('Invalid local build provenance')
    if value['core_version'] != manifest['sing_box']['version'] or value['source_revision'] != manifest['sing_box']['source_revision']:
        raise ValueError('Provenance does not match the pinned runtime manifest; rebuild libbox')
    if value['overlay_sha256'] != overlay_digest() or any(value['toolchain'][name] != manifest['android'][name + '_version'] for name in ('gomobile', 'ndk')):
        raise ValueError('Overlay or toolchain pins changed; rebuild libbox')
    if value['aar_sha256'] != digest(args.aar):
        raise ValueError('AAR hash differs from recorded local build; rebuild libbox')
    with zipfile.ZipFile(args.aar) as archive:
        actual = {abi: hashlib.sha256(archive.read(f'jni/{abi}/libbox.so')).hexdigest() for abi in sorted(ABIS)}
    if actual != value['native_sha256']:
        raise ValueError('AAR native libraries differ from local build provenance')


if __name__ == '__main__':
    main()
