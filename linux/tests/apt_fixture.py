#!/usr/bin/env python3
"""Destructive only inside a fresh, disposable Docker test container; never a host."""
import functools
import http.server
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[2]
if os.geteuid() != 0 or not Path('/.dockerenv').is_file() or os.getenv('SBL_APT_FIXTURE') != 'disposable-container':
    raise SystemExit('Run this fixture only in a fresh disposable Docker container with SBL_APT_FIXTURE=disposable-container')
if subprocess.run(['dpkg-query', '-W', 'sb-easy-desktop'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
    raise SystemExit('Refusing a container with an existing sb-easy-desktop package')

def run(command, success=True, match=None):
    result = subprocess.run([str(item) for item in command], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=100)
    if (result.returncode == 0) != success or (match and match not in result.stdout):
        raise AssertionError(f'Unexpected command result {result.returncode}: {command}\n{result.stdout[-10000:]}')
    return result.stdout

def update(*args, **kw):
    return run([sys.executable, ROOT / 'linux/scripts/update.py', *args], **kw)

def installed(expected):
    assert run(['dpkg-query', '-W', '-f=${Version}', 'sb-easy-desktop']) == expected

class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass

with tempfile.TemporaryDirectory(prefix='sbl-apt-fixture-') as temporary:
    work = Path(temporary); keys = work / 'keys'; keys.mkdir(mode=0o700)
    packages = work / 'packages'; packages.mkdir()
    repository = work / 'repository'
    gpg = ['gpg', '--batch', '--homedir', keys, '--pinentry-mode', 'loopback', '--passphrase', '']
    run([*gpg, '--quick-generate-key', 'sb-easy DISPOSABLE APT TEST <fixture@invalid.example>', 'ed25519', 'sign', '1d'])
    listing = run([*gpg, '--with-colons', '--fingerprint', '--list-keys'])
    fingerprint = next(line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:'))
    public = work / 'fixture-public.asc'
    run([*gpg, '--armor', '--output', public, '--export', fingerprint])
    def package(version, broken=False):
        root = work / ('package-' + version); (root / 'DEBIAN').mkdir(parents=True)
        (root / 'DEBIAN/control').write_text(f'Package: sb-easy-desktop\nVersion: {version}\nArchitecture: all\nMaintainer: Disposable Test <fixture@invalid.example>\nDescription: Harmless package for isolated update acceptance\n')
        (root / 'usr/share/sb-easy-fixture').mkdir(parents=True)
        (root / 'usr/share/sb-easy-fixture/version').write_text(version)
        if broken:
            script = root / 'DEBIAN/postinst'; script.write_text('#!/bin/sh\nexit 23\n'); script.chmod(0o755)
        run(['dpkg-deb', '--build', '--root-owner-group', root, packages / ('fixture-' + version + '.deb')])
    def publish():
        run([sys.executable, ROOT / 'linux/scripts/publish-apt.py', '--packages', packages, '--output', repository, '--gpg-key', fingerprint, '--gnupghome', keys])
    package('0.0.1'); publish()
    cert = work / 'fixture.crt'; secret = work / 'fixture.key'
    run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-keyout', secret, '-out', cert,
         '-subj', '/CN=sb-easy disposable repository test', '-addext', 'subjectAltName=IP:127.0.0.1', '-addext', 'basicConstraints=critical,CA:TRUE'])
    shutil.copyfile(cert, '/usr/local/share/ca-certificates/sb-easy-disposable-fixture.crt')
    run(['update-ca-certificates'])
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(Quiet, directory=repository))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert, secret)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    configure = [sys.executable, ROOT / 'linux/scripts/configure-repository.py', '--repository', f'https://127.0.0.1:{server.server_port}', '--key', public, '--fingerprint', fingerprint]
    try:
        run([*configure[:-1], '0' * 40], success=False, match='fingerprint does not match')
        assert not Path('/etc/apt/sources.list.d/sb-easy.sources').exists()
        run(configure)
        assert 'Signed-By: /usr/share/keyrings/sb-easy-archive-keyring.gpg' in Path('/etc/apt/sources.list.d/sb-easy.sources').read_text()
        update('--version', '0.0.1'); installed('0.0.1')
        package('0.0.2'); publish()
        update('--check', match='"candidate": "0.0.2"')
        update(); installed('0.0.2')
        update('--pin', '0.0.2'); update(success=False, match='version is pinned')
        assert 'sb-easy-desktop' in run(['apt-mark', 'showhold'])
        update('--unpin')
        update('--version', '0.0.1', success=False, match='explicit --rollback')
        metadata = repository / 'dists/stable/InRelease'; original = metadata.read_bytes()
        metadata.write_bytes(original.replace(b'Label: sb-easy', b'Label: tampered'))
        update('--check', success=False); metadata.write_bytes(original)
        source = Path('/etc/apt/sources.list.d/sb-easy.sources'); original_source = source.read_text()
        source.write_text(original_source.replace('Signed-By:', 'Trusted: yes\nSigned-By:'))
        update('--check', success=False, match='no longer matches'); source.write_text(original_source)
        package('0.0.3', broken=True); publish()
        payload = repository / 'pool/main/s/sb-easy-desktop/sb-easy-desktop_0.0.3_all.deb'
        original_payload = payload.read_bytes(); payload.write_bytes(original_payload + b'tamper')
        update('--version', '0.0.3', success=False); installed('0.0.2')
        payload.write_bytes(original_payload)
        update('--version', '0.0.3', success=False, match='restored previously verified 0.0.2'); installed('0.0.2')
        server.shutdown(); server.server_close(); thread.join(timeout=5)
        update('--rollback', '0.0.1'); installed('0.0.1')
        assert 'sb-easy-desktop' in run(['apt-mark', 'showhold'])
        rollback = Path('/var/cache/sb-easy-desktop/0.0.2/sb-easy-desktop.deb')
        rollback.write_bytes(rollback.read_bytes() + b'cache-tamper')
        update('--rollback', '0.0.2', success=False, match='integrity check'); installed('0.0.1')
        receipt = json.loads(Path('/var/lib/sb-easy-desktop/last-update.json').read_text())
        assert receipt['from'] == '0.0.2' and receipt['to'] == '0.0.1' and receipt['pinned']
        print('APT acceptance passed: Signed-By trust, wrong fingerprint, signed metadata tamper, unsafe source, payload tamper, upgrade, downgrade refusal, pin/unpin, failed-install restoration, offline rollback, cache integrity.')
    finally:
        server.shutdown(); server.server_close()
