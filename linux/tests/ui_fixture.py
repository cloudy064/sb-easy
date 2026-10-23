#!/usr/bin/env python3
"""Exercise native GTK actions, real proxy traffic and an actual Xvfb render."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from loopback_fixture import proxy, destination, close
try:
    screenshot = Path(sys.argv[2]).resolve()
    screenshot.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='sb-linux-gtk-') as work:
        os.chmod(work, 0o700)
        env = dict(os.environ, GSETTINGS_BACKEND='memory', XDG_RUNTIME_DIR=work, NO_AT_BRIDGE='1')
        subprocess.run([sys.argv[1], '--self-test', work, str(proxy.server_port), str(destination.server_port), str(screenshot)], check=True, timeout=40, env=env)
        assert screenshot.is_file() and screenshot.stat().st_size > 10000, 'GTK screenshot missing'
        assert not (Path(work) / 'runtime/runtime.json').exists(), 'Runtime credentials survived shutdown'
finally:
    close()
