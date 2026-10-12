import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request

with tempfile.TemporaryDirectory() as directory:
    process = subprocess.Popen([sys.argv[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    def call(method, params=None):
        body = json.dumps(dict(method=method, params=params or {})).encode()
        process.stdin.write(struct.pack('<I', len(body))+body); process.stdin.flush()
        header = process.stdout.read(4)
        assert len(header) == 4, 'Worker exited before responding'
        length, = struct.unpack('<I', header); assert 0 < length < 2*1024*1024
        answer = json.loads(process.stdout.read(length)); assert answer['ok'], answer
        return answer['result']
    try:
        state = call('start', dict(directory=directory, proxy_port=27990, web_port=27991, upstream_port=27992))
        deadline = time.monotonic()+30
        while state['phase'] == 'starting' and time.monotonic() < deadline:
            time.sleep(.2); state = call('snapshot')
        assert state['phase'] == 'running', state['error']
        assert len(bytes.fromhex(call('certificate')['der'])) > 500
        assert b'<!doctype html' in urllib.request.urlopen(state['url']).read().lower()
        assert call('stop')['phase'] == 'stopped'
        print('Packaged worker: framed IPC, startup, web UI, public CA export and stop passed.')
    finally:
        process.stdin.close()
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired: process.kill(); process.wait()
