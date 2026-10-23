#!/usr/bin/env python3
"""Configure a Signed-By APT repository using an independently verified public key."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from urllib.parse import urlsplit

KEY_PATH = Path('/usr/share/keyrings/sb-easy-archive-keyring.gpg')
SOURCE_PATH = Path('/etc/apt/sources.list.d/sb-easy.sources')
TRUST_PATH = Path('/var/lib/sb-easy-desktop/repository.json')

def atomic_write(path, content, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    for parent in [path.parent, *path.parent.parents]:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
            # /tmp may be an ancestor of a test staging root, never a destination.
            if parent != Path('/tmp') or not (info.st_mode & stat.S_ISVTX):
                raise ValueError('Destination has an unsafe parent directory')
    if path.is_symlink():
        raise ValueError('Refusing a symbolic link destination')
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + '.', dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)

def checked_url(value):
    parsed = urlsplit(value)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or any(c.isspace() for c in value) or '\\' in value:
        raise ValueError('Repository must be an HTTPS URL without credentials, query or fragment')
    _ = parsed.port
    return value.rstrip('/')

def public_key(path, expected):
    with tempfile.TemporaryDirectory(prefix='sb-easy-repository-key-') as work:
        command = ['gpg', '--homedir', work, '--batch']
        subprocess.run([*command, '--import-options', 'import-minimal', '--import', str(path)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        secret = subprocess.check_output([*command, '--with-colons', '--list-secret-keys'], stderr=subprocess.DEVNULL).decode()
        if any(line.startswith('sec:') for line in secret.splitlines()):
            raise ValueError('Provide a public key export, never a private signing key')
        listing = subprocess.check_output([*command, '--with-colons', '--fingerprint', '--list-keys'], stderr=subprocess.DEVNULL).decode()
        primary = []
        waiting = False
        for line in listing.splitlines():
            fields = line.split(':')
            if fields[0] == 'pub':
                waiting = True
            elif fields[0] == 'fpr' and waiting:
                primary.append(fields[9].upper()); waiting = False
        if primary != [expected]:
            raise ValueError('Public key fingerprint does not match the independently verified fingerprint')
        return subprocess.check_output([*command, '--export-options', 'export-minimal', '--export', expected])

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--suite', default='stable')
    parser.add_argument('--key', type=Path, required=True)
    parser.add_argument('--fingerprint', required=True, help='Full fingerprint obtained through an independent trusted channel')
    parser.add_argument('--architecture', choices=('amd64', 'arm64'), default='amd64')
    parser.add_argument('--root', type=Path, default=Path('/'), help='Staging root for package tests; normal installation uses /')
    args = parser.parse_args()
    if args.root == Path('/') and os.geteuid() != 0:
        raise ValueError('Run repository configuration as an administrator')
    if not args.root.is_absolute() or args.root.is_symlink():
        raise ValueError('Installation root must be an absolute real directory')
    root = args.root.resolve()
    repository = checked_url(args.repository)
    if not re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,48}', args.suite):
        raise ValueError('Invalid repository suite')
    fingerprint = args.fingerprint.replace(' ', '').upper()
    if not re.fullmatch(r'(?:[A-F0-9]{40}|[A-F0-9]{64})', fingerprint):
        raise ValueError('Use the complete signing-key fingerprint')
    key = public_key(args.key, fingerprint)
    if not key:
        raise ValueError('Public key export is empty')
    source = (f'Types: deb\nURIs: {repository}\nSuites: {args.suite}\nComponents: main\n'
              f'Architectures: {args.architecture}\nSigned-By: {KEY_PATH}\n')
    trust = {'schema': 1, 'repository': repository, 'suite': args.suite, 'architecture': args.architecture, 'fingerprint': fingerprint}
    atomic_write(root / KEY_PATH.relative_to('/'), key)
    atomic_write(root / SOURCE_PATH.relative_to('/'), source.encode())
    atomic_write(root / TRUST_PATH.relative_to('/'), (json.dumps(trust, indent=2) + '\n').encode())
    print(f'Configured sb-easy Signed-By repository; verified key {fingerprint}')

if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error))
