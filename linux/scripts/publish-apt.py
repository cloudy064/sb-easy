#!/usr/bin/env python3
"""Build an APT repository and sign Release metadata with an external maintainer key.

This creates local files only; it does not upload or publish them to a server.
"""
import argparse
from datetime import datetime, timedelta, timezone
import email.utils
import gzip
import hashlib
import io
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

PACKAGE = 'sb-easy-desktop'

def control(path):
    with path.open('rb') as source:
        if source.read(8) != b'!<arch>\n':
            raise ValueError(f'Invalid Debian archive: {path.name}')
        while header := source.read(60):
            if len(header) != 60 or header[-2:] != b'`\n':
                raise ValueError('Invalid ar member header')
            name = header[:16].decode('ascii').strip().rstrip('/')
            size = int(header[48:58].strip())
            if size < 0 or size > 512 * 1024 * 1024:
                raise ValueError('Debian archive member exceeds the package limit')
            if name.startswith('control.tar'):
                if size > 1024 * 1024:
                    raise ValueError('Debian control archive is too large')
                with tarfile.open(fileobj=io.BytesIO(source.read(size)), mode='r:*') as archive:
                    members = [entry for entry in archive.getmembers() if entry.name.lstrip('./') == 'control']
                    if len(members) != 1 or not members[0].isfile() or members[0].size > 65536:
                        raise ValueError('Invalid Debian control entry')
                    text = archive.extractfile(members[0]).read().decode()
                    break
            source.seek(size + (size & 1), 1)
        else:
            raise ValueError('Debian control archive is missing')
    fields = {}
    previous = None
    for line in text.strip().splitlines():
        if line.startswith((' ', '\t')) and previous:
            fields[previous] += '\n' + line
        elif ': ' in line:
            previous, value = line.split(': ', 1)
            if previous in fields:
                raise ValueError('Duplicate Debian control field')
            fields[previous] = value
        else:
            raise ValueError('Invalid Debian control data')
    if fields.get('Package') != PACKAGE or not re.fullmatch(r'[0-9][A-Za-z0-9.+:~_-]{0,127}', fields.get('Version', '')) or fields.get('Architecture') not in ('amd64', 'arm64', 'all'):
        raise ValueError('Only supported sb-easy-desktop packages may enter this repository')
    return fields

def sha(path, algorithm='sha256'):
    with path.open('rb') as source:
        return hashlib.file_digest(source, algorithm).hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packages', type=Path, required=True, help='Directory containing retained, reviewed .deb versions')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--suite', default='stable')
    parser.add_argument('--gpg-key', required=True, help='Full fingerprint of the external repository signing key')
    parser.add_argument('--gnupghome', type=Path)
    parser.add_argument('--valid-days', type=int, default=14)
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,48}', args.suite) or not 1 <= args.valid_days <= 30:
        raise ValueError('Invalid suite or metadata lifetime')
    fingerprint = args.gpg_key.replace(' ', '').upper()
    if not re.fullmatch(r'(?:[A-F0-9]{40}|[A-F0-9]{64})', fingerprint):
        raise ValueError('Use a complete external signing-key fingerprint')
    if args.output.is_symlink():
        raise ValueError('Repository output must not be a symbolic link')
    packages = sorted(args.packages.glob('*.deb'))
    if not packages or any(path.is_symlink() for path in packages):
        raise ValueError('Provide regular .deb package files')
    args.output.mkdir(parents=True, exist_ok=True)
    pool = args.output / 'pool/main/s/sb-easy-desktop'; pool.mkdir(parents=True, exist_ok=True)
    records = []; identities = set(); arches = set()
    for package in packages:
        fields = control(package); identity = (fields['Version'], fields['Architecture'])
        if identity in identities:
            raise ValueError('Duplicate package version and architecture')
        identities.add(identity)
        if fields['Architecture'] != 'all': arches.add(fields['Architecture'])
        filename = f"{PACKAGE}_{fields['Version']}_{fields['Architecture']}.deb"
        target = pool / filename
        if target.is_symlink(): raise ValueError('Unsafe repository package destination')
        shutil.copyfile(package, target)
        fields.update(Filename=str(target.relative_to(args.output)), Size=str(target.stat().st_size), SHA256=sha(target), SHA512=sha(target, 'sha512'))
        records.append(fields)
    if not arches: arches.add('amd64')
    dist = args.output / 'dists' / args.suite; outputs = []
    for arch in sorted(arches):
        destination = dist / f'main/binary-{arch}'; destination.mkdir(parents=True, exist_ok=True)
        text = '\n\n'.join('\n'.join(f'{key}: {value}' for key, value in record.items()) for record in records if record['Architecture'] in (arch, 'all')) + '\n\n'
        package_index = destination / 'Packages'; package_index.write_text(text)
        compressed = destination / 'Packages.gz'; compressed.write_bytes(gzip.compress(text.encode(), mtime=0))
        outputs.extend([package_index, compressed])
    now = datetime.now(timezone.utc)
    lines = ['Origin: sb-easy', 'Label: sb-easy', f'Suite: {args.suite}', f'Codename: {args.suite}',
             f'Date: {email.utils.format_datetime(now, usegmt=True)}',
             f'Valid-Until: {email.utils.format_datetime(now + timedelta(days=args.valid_days), usegmt=True)}',
             'Architectures: ' + ' '.join(sorted(arches)), 'Components: main', 'Description: sb-easy native desktop packages', 'SHA256:']
    for file in outputs:
        lines.append(f' {sha(file)} {file.stat().st_size} {file.relative_to(dist)}')
    lines.append('SHA512:')
    for file in outputs:
        lines.append(f' {sha(file, "sha512")} {file.stat().st_size} {file.relative_to(dist)}')
    release = dist / 'Release'; release.write_text('\n'.join(lines) + '\n')
    command = ['gpg', '--batch', '--yes']
    if args.gnupghome: command += ['--homedir', str(args.gnupghome)]
    command += ['--local-user', fingerprint]
    subprocess.run([*command, '--clearsign', '--output', str(dist / 'InRelease'), str(release)], check=True)
    subprocess.run([*command, '--armor', '--detach-sign', '--output', str(dist / 'Release.gpg'), str(release)], check=True)
    print(f'Created signed local repository with {len(records)} package versions; key {fingerprint}')

if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError, tarfile.TarError) as error:
        raise SystemExit(str(error))
