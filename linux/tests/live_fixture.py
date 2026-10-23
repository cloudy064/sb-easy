#!/usr/bin/env python3
"""Real embedded runtime acceptance, entirely loopback and ephemeral ports."""
import subprocess
import sys
from loopback_fixture import proxy, destination, close
try:
    subprocess.run([sys.argv[1], str(proxy.server_port), str(destination.server_port)], check=True, timeout=45)
finally:
    close()
