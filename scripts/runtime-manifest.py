#!/usr/bin/env python3
"""Read the checked-in runtime pins and verify downloads before use.

Only maintainers changing this repository's manifest can authorize a new core.
A checksum fetched alongside an untrusted update is never used as a trust root.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def manifest():
    data = json.loads((ROOT / 'config/runtime-versions.json').read_text())
    core = data['sing_box']
    if data['schema_version'] != 1 or not re.fullmatch(r'\d+\.\d+\.\d+', core['version']):
        raise ValueError('Unsupported runtime manifest')
    if not re.fullmatch(r'[a-f0-9]{40}', core['source_revision']):
        raise ValueError('Core revision must pin a full Git commit')
    for platform, artifact in core['artifacts'].items():
        suffix = '.zip' if platform.startswith('windows-') else '.tar.gz'
        filename = f"sing-box-{core['version']}-{platform}{suffix}"
        url = f"https://github.com/SagerNet/sing-box/releases/download/v{core['version']}/{filename}"
        if artifact['filename'] != filename or artifact['url'] != url or not re.fullmatch(r'[a-f0-9]{64}', artifact['sha256']):
            raise ValueError(f'Invalid immutable artifact pin: {platform}')
    return data


def digest(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def download(artifact, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_file() and digest(destination) == artifact['sha256']:
        return
    fd, name = tempfile.mkstemp(prefix=destination.name + '.', suffix='.part', dir=destination.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'wb') as output, urllib.request.urlopen(artifact['url'], timeout=60) as response:
            if not response.url.startswith('https://'):
                raise ValueError('Refusing an insecure download redirect')
            size = 0
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                if size > 512 * 1024 * 1024:
                    raise ValueError('Core archive exceeds the size limit')
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        if digest(temporary) != artifact['sha256']:
            raise ValueError('Core archive does not match the checked-in SHA-256 pin')
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('check')
    get = sub.add_parser('get'); get.add_argument('key')
    for command in ['verify', 'download']:
        item = sub.add_parser(command); item.add_argument('platform'); item.add_argument('path', type=Path)
    args = parser.parse_args()
    data = manifest()
    if args.command == 'get':
        value = data
        for key in args.key.split('.'):
            value = value[key]
        print(value if isinstance(value, (str, int)) else json.dumps(value))
    elif args.command in ['verify', 'download']:
        artifact = data['sing_box']['artifacts'][args.platform]
        if args.command == 'download':
            download(artifact, args.path)
        if digest(args.path) != artifact['sha256']:
            raise ValueError('Core archive does not match the checked-in SHA-256 pin')
        print(f"Verified {artifact['filename']}")
    else:
        print(f"Runtime manifest valid: sing-box {data['sing_box']['version']}")


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError) as error:
        sys.exit(str(error))
