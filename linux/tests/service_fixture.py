#!/usr/bin/env python3
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from loopback_fixture import proxy, destination, close
try:
    with tempfile.TemporaryDirectory(prefix='sb-linux-bus-') as work:
        os.chmod(work, 0o700)
        service = subprocess.Popen([sys.argv[1], '--session-test', work])
        try:
            subprocess.run([sys.argv[2], str(proxy.server_port), str(destination.server_port)], check=True, timeout=40)
        finally:
            service.terminate()
            service.wait(timeout=15)
finally:
    close()
