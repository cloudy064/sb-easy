#!/usr/bin/env python3
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from loopback_fixture import proxy, destination, close
state = {'bad': False, 'statuses': 0, 'telemetry': 0, 'enrollments': 0}
class Center(http.server.BaseHTTPRequestHandler):
    def reply(self, code, payload, etag=None):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Content-Type', 'application/json')
        if etag:
            self.send_header('ETag', etag)
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        if self.path == '/fixture/bad':
            state['bad'] = True
            self.reply(200, {})
        elif self.path == '/api/agent/config':
            assert self.headers.get('Authorization') == 'Bearer fixture-token'
            etag = '"bad"' if state['bad'] else '"good"'
            if self.headers.get('If-None-Match') == etag:
                self.send_response(304); self.send_header('ETag', etag); self.end_headers(); return
            nodes = [{'type': 'http', 'tag': 'managed-node', 'server': '127.0.0.1', 'server_port': proxy.server_port},
                     {'type': 'selector', 'tag': 'managed-default', 'outbounds': ['managed-node']},
                     {'type': 'direct', 'tag': 'managed-direct'}]
            dns = {'servers': [{'type': 'https', 'tag': 'fixture-dns', 'server': '1.1.1.1',
                                'detour': 'managed-direct' if state['bad'] else 'managed-default'}], 'final': 'fixture-dns'}
            self.reply(200, {'outbounds': nodes, 'route': {'final': 'managed-default'}, 'dns': dns}, etag)
        elif self.path == '/api/agent/commands':
            self.reply(200, [])
        else:
            self.reply(404, {})
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
        if self.path == '/api/devices/enroll':
            assert body['code'] == 'fixture-code-0123456789abcdef0123456789abcdef'
            state['enrollments'] += 1
            self.reply(200, {'server': f'http://127.0.0.1:{self.server.server_port}', 'host_id': 'fixture-device', 'host_name': 'Managed fixture', 'agent_token': 'fixture-token'})
        elif self.path == '/api/agent/status':
            assert self.headers.get('Authorization') == 'Bearer fixture-token'
            assert not body.get('capabilities'), 'Desktop must not advertise a server ingress capability'
            state['statuses'] += 1
            self.reply(200, {})
        elif self.path == '/api/agent/telemetry':
            state['telemetry'] += 1
            self.reply(200, {})
        else:
            self.reply(200, {})
    def log_message(self, *_):
        pass
center = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Center)
threading.Thread(target=center.serve_forever, daemon=True).start()
try:
    with tempfile.TemporaryDirectory(prefix='sb-linux-controller-') as work:
        env = dict(os.environ, GSETTINGS_BACKEND='memory')
        subprocess.run([sys.argv[1], work, str(proxy.server_port), str(destination.server_port), str(center.server_port)], check=True, timeout=45, env=env)
        assert state['enrollments'] == 2 and state['statuses'] >= 3 and state['telemetry'] >= 1, state
finally:
    center.shutdown()
    close()
