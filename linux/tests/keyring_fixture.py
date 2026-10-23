#!/usr/bin/env python3
"""Create an isolated, password-protected Secret Service on a private bus."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
try:
    with tempfile.TemporaryDirectory(prefix='sb-linux-keyring-') as work:
        env = dict(os.environ, XDG_RUNTIME_DIR=work, XDG_DATA_HOME=str(Path(work) / 'data'), XDG_CONFIG_HOME=str(Path(work) / 'config'))
        for directory in ('data', 'config', 'control'):
            (Path(work) / directory).mkdir(mode=0o700)
        daemon = subprocess.Popen(['gnome-keyring-daemon', '--foreground', '--unlock', '--components=secrets', '--control-directory', str(Path(work) / 'control')], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        daemon.stdin.write(b'fixture-keyring-password\n')
        daemon.stdin.close()
        try:
            # Wait for this isolated daemon before libsecret can auto-activate a
            # second daemon with the bus launcher's unrelated XDG environment.
            for attempt in range(100):
                if daemon.poll() is not None:
                    raise RuntimeError(daemon.stderr.read().decode())
                owner = subprocess.run(['gdbus', 'call', '--session', '--dest', 'org.freedesktop.DBus',
                    '--object-path', '/org/freedesktop/DBus', '--method', 'org.freedesktop.DBus.NameHasOwner',
                    'org.freedesktop.secrets'], text=True, stdout=subprocess.PIPE, check=True, env=env)
                if 'true' in owner.stdout:
                    break
                time.sleep(.05)
            else:
                raise RuntimeError('Isolated Secret Service did not acquire its bus name')
            subprocess.run([sys.argv[1], str(Path(work) / 'vault')], check=True, timeout=20, env=env)
            keyrings = list((Path(work) / 'data/keyrings').glob('*.keyring'))
            assert keyrings and all(b'fixture-keyring-password' not in file.read_bytes() for file in keyrings)
        finally:
            daemon.terminate()
            daemon.wait(timeout=5)
except Exception:
    raise
