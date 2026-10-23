#!/usr/bin/env python3
"""Real kernel TUN acceptance in an explicitly disposable, network-none container."""
import http.server
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import threading
import time
if os.geteuid() != 0 or not Path('/.dockerenv').is_file() or os.getenv('SBL_TUN_FIXTURE') != 'disposable-container':
    raise SystemExit('Use a fresh Docker --network none container, NET_ADMIN and /dev/net/tun only')

def command(*args, **kw):
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, **kw).stdout

links = json.loads(command('ip', '-j', 'link', 'show'))
assert [entry['ifname'] for entry in links] == ['lo'], 'Refusing a container with external network interfaces'
command('ip', 'link', 'add', 'fixture0', 'type', 'dummy')
command('ip', 'addr', 'add', '192.0.2.1/24', 'dev', 'fixture0')
command('ip', '-6', 'addr', 'add', 'fd42::1/64', 'dev', 'fixture0')
command('ip', 'link', 'set', 'fixture0', 'up')
command('ip', 'route', 'add', 'default', 'via', '192.0.2.254', 'dev', 'fixture0')
command('ip', '-6', 'route', 'add', 'default', 'via', 'fd42::fe', 'dev', 'fixture0')
seen = []
class Destination(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'kernel TUN fixture response'
        self.send_response(200); self.send_header('Content-Length', str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def log_message(self, *_): pass
class Proxy(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_CONNECT(self):
        if self.path not in (f'203.0.113.7:{destination.server_port}', f'[2001:db8::7]:{destination.server_port}'):
            self.send_error(403); return
        seen.append(self.path)
        with socket.create_connection(('127.0.0.1', destination.server_port), timeout=3) as remote:
            self.send_response(200); self.end_headers(); self.wfile.flush()
            while True:
                streams, _, _ = select.select([self.connection, remote], [], [], 5)
                if not streams: return
                for stream in streams:
                    data = stream.recv(65536)
                    if not data: return
                    (remote if stream is self.connection else self.connection).sendall(data)
    def log_message(self, *_): pass

destination = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Destination)
proxy = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
for server in (destination, proxy):
    threading.Thread(target=server.serve_forever, daemon=True).start()
process = None
try:
    command('ip', 'rule', 'add', 'pref', '12045', 'lookup', 'main')
    conflict = command(sys.argv[1], str(proxy.server_port), 'conflict')
    assert '12045:' in command('ip', 'rule', 'show')
    assert 'sbeasy0' not in command('ip', '-j', 'link', 'show')
    command('ip', 'rule', 'del', 'pref', '12045', 'lookup', 'main')
    command('ip', 'route', 'add', 'blackhole', '203.0.113.8/32', 'table', '42041')
    command(sys.argv[1], str(proxy.server_port), 'conflict')
    assert 'blackhole 203.0.113.8' in command('ip', 'route', 'show', 'table', '42041')
    assert 'sbeasy0' not in command('ip', '-j', 'link', 'show')
    command('ip', 'route', 'del', 'blackhole', '203.0.113.8/32', 'table', '42041')
    before4 = command('ip', 'rule', 'show'); before6 = command('ip', '-6', 'rule', 'show')
    process = subprocess.Popen([sys.argv[1], str(proxy.server_port), 'traffic'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError('TUN core exited before startup: ' + process.stderr.read())
        readable, _, _ = select.select([process.stdout], [], [], .5)
        if readable and process.stdout.readline().strip() == 'TUN_READY': break
    else: raise AssertionError('TUN core did not become ready')
    assert 'sbeasy0' in command('ip', 'link', 'show')
    for host in ('203.0.113.7', '[2001:db8::7]'):
        response = command('curl', '--noproxy', '*', '-fsS', '--max-time', '8', f'http://{host}:{destination.server_port}/', user=1000, group=1000, extra_groups=[])
        assert response == 'kernel TUN fixture response'
    assert len(seen) == 2, seen
    process.communicate('\n', timeout=15)
    assert process.returncode == 0
    assert 'sbeasy0' not in command('ip', '-j', 'link', 'show')
    assert command('ip', 'rule', 'show') == before4
    assert command('ip', '-6', 'rule', 'show') == before6
    print('Real kernel TUN acceptance passed: conflicting rule and route table preserved, UID 1000 IPv4/IPv6 HTTP through proxy, interface and policy rules cleaned.')
finally:
    if process and process.poll() is None:
        process.kill(); process.wait(timeout=5)
    proxy.shutdown(); destination.shutdown()
