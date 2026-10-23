#!/usr/bin/env python3
"""Install a verified APT package, pin a version, or restore a previously verified package."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time
from urllib.parse import urlsplit

PACKAGE = 'sb-easy-desktop'
SOURCE = Path('/etc/apt/sources.list.d/sb-easy.sources')
KEY = Path('/usr/share/keyrings/sb-easy-archive-keyring.gpg')
STATE = Path('/var/lib/sb-easy-desktop')
CACHE = Path('/var/cache/sb-easy-desktop')
PIN = Path('/etc/apt/preferences.d/sb-easy-desktop-version')
ENV = dict(os.environ, LC_ALL='C')

def run(command, capture=False):
    return subprocess.run(command, check=True, env=ENV, text=True, stdout=subprocess.PIPE if capture else None).stdout

def safe_file(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError(f'Unsafe administrator-owned file: {path}')
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError(f'Unsafe administrator-owned directory: {parent}')

def safe_directory(path):
    path.mkdir(parents=True, exist_ok=True)
    for directory in (path, *path.parents):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError(f'Unsafe administrator-owned directory: {directory}')

def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()

def write_json(path, value):
    safe_directory(path.parent)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + '.', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w') as output:
            json.dump(value, output, indent=2); output.write('\n'); output.flush(); os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)

def repository():
    safe_file(SOURCE); safe_file(KEY); safe_file(STATE / 'repository.json')
    trust = json.loads((STATE / 'repository.json').read_text())
    fields = {}
    for line in SOURCE.read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        if ':' not in line or line[:1].isspace():
            raise ValueError('Unsupported repository source configuration')
        key, value = line.split(':', 1)
        if key in fields:
            raise ValueError('Duplicate repository source field')
        fields[key] = value.strip()
    expected = {'Types': 'deb', 'URIs': trust['repository'], 'Suites': trust['suite'], 'Components': 'main',
                'Architectures': trust['architecture'], 'Signed-By': str(KEY)}
    if fields != expected or urlsplit(trust['repository']).scheme != 'https':
        raise ValueError('Repository configuration no longer matches the verified Signed-By setup')
    with tempfile.TemporaryDirectory(prefix='sb-easy-key-check-') as work:
        listing = run(['gpg', '--homedir', work, '--batch', '--show-keys', '--with-colons', '--fingerprint', str(KEY)], True)
    fingerprints = [line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:')]
    if not fingerprints or fingerprints[0] != trust['fingerprint']:
        raise ValueError('Repository signing key changed; configure and verify it again')
    return trust

def version(value):
    if not re.fullmatch(r'[0-9][A-Za-z0-9.+:~_-]{0,127}', value):
        raise ValueError('Invalid package version')
    return value

def installed():
    result = subprocess.run(['dpkg-query', '--show', '--showformat=${Status}\n${Version}\n', PACKAGE], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    lines = result.stdout.splitlines()
    return lines[1] if result.returncode == 0 and len(lines) >= 2 and lines[0] == 'install ok installed' else None

def apt_options():
    lists = STATE / 'apt/lists'; safe_directory(lists)
    return ['-o', f'Dir::Etc::sourcelist={SOURCE}', '-o', 'Dir::Etc::sourceparts=-', '-o', f'Dir::State::lists={lists}',
            '-o', 'Dir::Cache::pkgcache=', '-o', 'Dir::Cache::srcpkgcache=', '-o', 'Acquire::AllowInsecureRepositories=false',
            '-o', 'Acquire::AllowDowngradeToInsecureRepositories=false', '-o', 'APT::Get::AllowUnauthenticated=false',
            '-o', 'Acquire::https::Timeout=15', '-o', 'Acquire::Retries=0',
            '-o', 'APT::Update::Error-Mode=any']

def inspect_package(path, target):
    metadata = run(['dpkg-deb', '--field', str(path), 'Package', 'Version', 'Architecture'], True)
    fields = dict(line.split(': ', 1) for line in metadata.splitlines() if ': ' in line)
    arch = run(['dpkg', '--print-architecture'], True).strip()
    if fields.get('Package') != PACKAGE or fields.get('Version') != target or fields.get('Architecture') not in (arch, 'all'):
        raise ValueError('Downloaded package identity, version or architecture does not match')

def cached(target):
    directory = CACHE / version(target); receipt = directory / 'verified.json'; package = directory / f'{PACKAGE}.deb'
    if not receipt.exists() and not package.exists():
        return None
    safe_file(receipt); safe_file(package)
    metadata = json.loads(receipt.read_text())
    if metadata.get('schema') != 1 or metadata.get('version') != target or metadata.get('sha256') != digest(package):
        raise ValueError('Previously verified rollback package failed its integrity check')
    inspect_package(package, target)
    return package

def download(target, trust, options):
    safe_directory(CACHE)
    with tempfile.TemporaryDirectory(prefix='download-', dir=CACHE) as work:
        subprocess.run(['apt-get', *options, 'download', f'{PACKAGE}={target}'], cwd=work, check=True, env=ENV)
        files = list(Path(work).glob('*.deb'))
        if len(files) != 1 or files[0].is_symlink():
            raise ValueError('APT did not produce exactly one verified package')
        inspect_package(files[0], target)
        destination = CACHE / target; safe_directory(destination)
        package = destination / f'{PACKAGE}.deb'
        if package.is_symlink():
            raise ValueError('Refusing a symbolic link in the package cache')
        os.replace(files[0], package); package.chmod(0o644)
        write_json(destination / 'verified.json', {'schema': 1, 'version': target, 'sha256': digest(package),
            'repository': trust['repository'], 'fingerprint': trust['fingerprint'], 'verified_at': int(time.time())})
        return package

def install(package, downgrade=False, explicit=False):
    command = ['apt-get', '-o', 'APT::Get::AllowUnauthenticated=false', '--yes', '--no-remove']
    if downgrade:
        command.append('--allow-downgrades')
    if explicit:
        command.append('--allow-change-held-packages')
    run([*command, 'install', str(package)])

def pin(target):
    safe_directory(PIN.parent)
    if PIN.is_symlink():
        raise ValueError('Refusing a symbolic link version pin')
    PIN.write_text(f'Package: {PACKAGE}\nPin: version {target}\nPin-Priority: 1001\n')
    PIN.chmod(0o644); run(['apt-mark', 'hold', PACKAGE])

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument('--check', action='store_true')
    actions.add_argument('--version', type=version)
    actions.add_argument('--rollback', type=version)
    actions.add_argument('--pin', type=version)
    actions.add_argument('--unpin', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('Run package updates as an administrator')
    safe_directory(STATE)
    descriptor = os.open(STATE / 'update.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    lock = os.fdopen(descriptor, 'w')
    safe_file(STATE / 'update.lock')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    if args.unpin:
        if PIN.exists(): safe_file(PIN); PIN.unlink()
        run(['apt-mark', 'unhold', PACKAGE]); print('Version pin removed'); return
    trust = repository(); old = installed(); target = args.rollback or args.pin or args.version
    if PIN.exists() and not (args.rollback or args.pin or args.check):
        raise ValueError('This version is pinned. Use --unpin before a normal update, or choose an explicit --pin/--rollback version.')
    package = cached(target) if args.rollback and target else None
    if package is None:
        options = apt_options(); run(['apt-get', *options, 'update'])
        policy = run(['apt-cache', *options, 'policy', PACKAGE], True)
        candidate = next((line.split(':', 1)[1].strip() for line in policy.splitlines() if line.strip().startswith('Candidate:')), '')
        if not candidate or candidate == '(none)':
            raise ValueError('No signed package is available for this architecture')
        if args.check:
            print(json.dumps({'installed': old, 'candidate': candidate, 'repository': trust['repository']})); return
        target = version(target or candidate)
        if old and subprocess.run(['dpkg', '--compare-versions', target, 'lt', old]).returncode == 0 and not args.rollback:
            raise ValueError('An older version requires an explicit --rollback request')
        package = download(target, trust, options)
    previous = cached(old) if old and old != target else None
    try:
        install(package, downgrade=bool(args.rollback), explicit=bool(args.rollback or args.pin or args.version))
    except subprocess.CalledProcessError:
        if previous:
            install(previous, downgrade=True, explicit=True)
            print(f'Installation failed; restored previously verified {old}')
        raise
    if installed() != target:
        raise ValueError('The package manager did not confirm the requested installed version')
    if args.rollback or args.pin:
        pin(target)
    write_json(STATE / 'last-update.json', {'schema': 1, 'from': old, 'to': target, 'sha256': digest(package), 'at': int(time.time()), 'pinned': bool(args.rollback or args.pin)})
    print(f'Installed verified {PACKAGE} {target}' + (' and pinned this version' if args.rollback or args.pin else ''))

if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error))
