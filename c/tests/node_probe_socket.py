"""Exercise the platform worker with the same framed protocol as the panel."""
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time


def probe(path, kind, server):
    node = {"tag": "example", "type": kind, "server": server, "server_port": 443,
            "protocol_config": {"password": "fixture"}}
    data = json.dumps(node).encode()
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(4)
        stream.connect(str(path))
        stream.sendall(struct.pack("!I", len(data)) + data)
        return struct.unpack("!i", stream.recv(4, socket.MSG_WAITALL))[0]


def check(directory, binary, available):
    path = directory / "probe.sock"
    env = dict(os.environ, SINGBOX_BIN=str(binary))
    worker = subprocess.Popen([sys.argv[1], str(path)], env=env)
    try:
        for _ in range(200):
            if path.is_socket() or worker.poll() is not None:
                break
            time.sleep(0.01)
        assert path.is_socket() and path.stat().st_mode & 0o077 == 0
        latency = probe(path, "trojan", "working.example")
        if available:
            assert latency >= 0
            assert probe(path, "trojan", "t.example.com") == -1
            assert probe(path, "unknown", "working.example") == -2
        else:
            assert latency == -2
    finally:
        worker.terminate()
        worker.wait(timeout=5)


if __name__ == "__main__":
    fixture = Path(__file__).resolve().parent / "fixtures" / "probe-sing-box.py"
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for name, binary in (("installed", fixture), ("missing", root / "absent")):
            directory = root / name
            directory.mkdir()
            check(directory, binary, binary == fixture)
