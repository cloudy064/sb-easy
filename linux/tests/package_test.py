#!/usr/bin/env python3
"""Validate installation and removal only in the disposable package-test image."""
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import xml.etree.ElementTree as ET
assert os.getenv('SBL_PACKAGE_FIXTURE') == 'disposable-build' and os.geteuid() == 0
assert Path('/src/build/linux-desktop/CPackConfig.cmake').is_file()
assert not Path('/run/systemd/system').exists(), 'Refusing a running system instance'

def run(command, **kw):
    return subprocess.run(command, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, **kw).stdout
assert run(['dpkg-query', '-W', '-f=${Status}', 'sb-easy-desktop']) == 'install ok installed'
for path, executable in {
    '/usr/bin/sb-easy-desktop': True,
    '/usr/libexec/sb-easy-tunnel': True,
    '/usr/libexec/sb-easy-desktop/configure-repository.py': True,
    '/usr/libexec/sb-easy-desktop/update.py': True,
    '/usr/share/dbus-1/system-services/io.sbeasy.Desktop.Tunnel.service': False,
    '/usr/share/dbus-1/system.d/io.sbeasy.Desktop.Tunnel.conf': False,
    '/usr/share/polkit-1/actions/io.sbeasy.Desktop.policy': False,
    '/usr/lib/systemd/system/sb-easy-tunnel.service': False,
    '/usr/share/doc/sb-easy-desktop/core-provenance.json': False,
}.items():
    info = Path(path).stat()
    assert info.st_uid == 0 and not info.st_mode & 0o022 and stat.S_ISREG(info.st_mode), path
    assert bool(info.st_mode & 0o111) == executable, path
ET.parse('/usr/share/dbus-1/system.d/io.sbeasy.Desktop.Tunnel.conf')
ET.parse('/usr/share/polkit-1/actions/io.sbeasy.Desktop.policy')
run(['systemd-analyze', 'verify', '/usr/lib/systemd/system/sb-easy-tunnel.service'])
assert not Path('/usr/share/keyrings/sb-easy-archive-keyring.gpg').exists(), 'Package must not invent a repository trust root'
result = subprocess.run(['/usr/bin/sb-easy-desktop'], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
assert result.returncode == 2 and 'normal user' in result.stderr
result = subprocess.run(['/usr/libexec/sb-easy-tunnel', '--session-test', '/tmp'], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
assert result.returncode == 2 and 'never run as root' in result.stderr
with tempfile.TemporaryDirectory(prefix='sbl-installed-package-') as work:
    root = Path(work); root.chmod(0o700); os.chown(root, 1000, 1000)
    data = root / 'data'; data.mkdir(mode=0o700); os.chown(data, 1000, 1000)
    env = dict(os.environ, XDG_DATA_HOME=str(data)); env.pop('XDG_RUNTIME_DIR', None)
    run(['/usr/bin/sb-easy-desktop', '--recover-proxy'], env=env, user=1000, group=1000, extra_groups=[])
    marker = data / 'sb-easy-desktop/keep-user-data'; marker.write_text('retained'); os.chown(marker, 1000, 1000)
    run(['apt-get', '--yes', 'remove', 'sb-easy-desktop'])
    assert marker.read_text() == 'retained'
    assert not Path('/usr/bin/sb-easy-desktop').exists()
    assert not Path('/usr/libexec/sb-easy-tunnel').exists()
print('Installed DEB acceptance passed: dependency resolution, root-owned executable/config paths, D-Bus/Polkit XML, systemd unit validation, production CLI loading and privilege guards, uninstall preserving user data.')
