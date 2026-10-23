#!/usr/bin/env python3
"""Build pinned Apple libbox and vendor libyaml. Requires macOS with Xcode."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
APPLE = ROOT / 'apple'
BUILD = APPLE / '.build'
VENDOR = APPLE / 'Vendor'
YAML_URL = 'https://github.com/yaml/libyaml/releases/download/0.2.5/yaml-0.2.5.tar.gz'
YAML_HASH = 'c642ae9b75fee120b2d96c712538bd2cf283228d2337df2cf2988e3c02678ef4'

def run(args, **kwargs):
    subprocess.run(args, check=True, **kwargs)

def safe_extract(data, target):
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for member in archive.getmembers():
            path = Path(member.name)
            if path.is_absolute() or '..' in path.parts or member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
                raise RuntimeError('Unsafe dependency archive member')
        archive.extractall(target)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--platform', help='gomobile target list, e.g. ios,iossimulator,tvos,tvossimulator,macos')
    parser.add_argument('--yaml-only', action='store_true', help='vendor and verify portable parser dependency without Xcode')
    args = parser.parse_args()
    BUILD.mkdir(exist_ok=True); VENDOR.mkdir(exist_ok=True)
    manifest = json.loads((ROOT / 'config/runtime-versions.json').read_text())
    core = manifest['sing_box']; mobile = manifest['android']['gomobile_version']
    if not all(part.isdigit() for part in core['version'].split('.')): raise RuntimeError('Invalid core version')
    (BUILD / 'Runtime.xcconfig').write_text('SB_CORE_VERSION = ' + core['version'] + '\n')
    archive = BUILD / 'yaml-0.2.5.tar.gz'
    if not archive.exists():
        with urllib.request.urlopen(YAML_URL, timeout=60) as response:
            data = response.read(4 * 1024 * 1024)
        archive.write_bytes(data)
    data = archive.read_bytes()
    if hashlib.sha256(data).hexdigest() != YAML_HASH:
        raise RuntimeError('libyaml checksum mismatch')
    unpacked = BUILD / 'yaml-0.2.5'
    if unpacked.exists(): shutil.rmtree(unpacked)
    safe_extract(data, BUILD)
    if (VENDOR / 'libyaml').exists(): shutil.rmtree(VENDOR / 'libyaml')
    shutil.copytree(unpacked, VENDOR / 'libyaml')
    if args.yaml_only: return
    if platform.system() != 'Darwin':
        raise SystemExit('Apple frameworks require macOS and Xcode; portable checks: cmake -S apple -B build/apple-contract')
    run(['xcrun', '--find', 'clang'])
    checkout = BUILD / 'sing-box'
    if not checkout.exists(): run(['git', 'init', str(checkout)])
    if subprocess.run(['git','-C',str(checkout),'remote','get-url','origin'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        run(['git','-C',str(checkout),'remote','add','origin',core['source_url']])
    origin = subprocess.check_output(['git','-C',str(checkout),'remote','get-url','origin'], text=True).strip()
    if origin != core['source_url']: raise RuntimeError('Unexpected source remote')
    run(['git','-C',str(checkout),'fetch','--depth','1','origin',core['source_revision']])
    run(['git','-C',str(checkout),'checkout','--detach','--force','FETCH_HEAD'])
    revision = subprocess.check_output(['git','-C',str(checkout),'rev-parse','HEAD'], text=True).strip()
    if revision != core['source_revision']: raise RuntimeError('Core revision mismatch')
    # Only generated build trees are changed; the repository's Go core is untouched.
    for source in (APPLE / 'libbox-overlay').rglob('*.go'):
        output = checkout / source.relative_to(APPLE / 'libbox-overlay')
        output.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(source, output)
    environment = dict(os.environ)
    environment['GOMODCACHE'] = subprocess.check_output(['go','env','GOMODCACHE'], text=True).strip()
    environment['GOPATH'] = str(BUILD / 'go')
    environment['GOBIN'] = str(BUILD / 'go/bin')
    run(['go','install',f'github.com/sagernet/gomobile/cmd/gomobile@{mobile}'], env=environment)
    run(['go','install',f'github.com/sagernet/gomobile/cmd/gobind@{mobile}'], env=environment)
    run(['go','test','-ldflags=-checklinkname=0','./experimental/libbox','-run','TestApple','-count=1'], cwd=checkout, env=environment)
    command = ['go','run','./cmd/internal/build_libbox','-target','apple']
    if args.platform: command += ['-platform',args.platform]
    run(command, cwd=checkout, env=environment)
    framework = VENDOR / 'Libbox.xcframework'
    if framework.exists(): shutil.rmtree(framework)
    shutil.copytree(checkout / 'Libbox.xcframework', framework)
    (VENDOR / 'runtime-build.json').write_text(json.dumps({'version':core['version'],'revision':revision,'gomobile':mobile,'overlay_sha256':{str(p.relative_to(APPLE)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((APPLE/'libbox-overlay').rglob('*.go'))}},indent=2)+'\n')
    # Corresponding source for redistributors of the GPLv3 libbox binary.
    with tarfile.open(VENDOR / 'libbox-corresponding-source.tar.gz', 'w:gz') as source_archive:
        for path in sorted(checkout.rglob('*')):
            rel = path.relative_to(checkout)
            if '.git' in rel.parts or 'Libbox.xcframework' in rel.parts: continue
            if path.is_file(): source_archive.add(path, arcname=Path('sing-box')/rel)
        source_archive.add(Path(__file__), arcname='sb-easy/build-deps.py')
        source_archive.add(ROOT/'config/runtime-versions.json',arcname='sb-easy/runtime-versions.json')
    print(f'Built libbox {core["version"]} ({revision}); corresponding source is in apple/Vendor.')
if __name__ == '__main__': main()
