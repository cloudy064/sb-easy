#!/usr/bin/env python3
"""Native client HTTP protocol test, isolated from the installed service."""
import http.server
import json
import subprocess
import sys
import threading

config = {'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'final': 'direct'}}
state = dict(base_version=100, patch_version=0, base=config, config=config, patch={}, agent_settings={}, etag='"fixture"', agent_settings_initialized=False)
uploads = 0

class Center(http.server.BaseHTTPRequestHandler):
    def reply(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def do_GET(self):
        if self.path == '/fixture/change':
            state['base_version'] += 1
            self.reply(200, {})
        elif self.path == '/fixture/invalid-proxy':
            state['patch_version'] += 1
            state['agent_settings']['linux_preferences']['system_proxy'] = 'invalid'
            self.reply(200, {})
        elif self.path == '/api/agent/config-state':
            assert self.headers.get('Authorization') == 'Bearer fixture-token'
            self.reply(200, state)
        else:
            self.reply(404, {})
    def do_PUT(self):
        global uploads
        assert self.path == '/api/agent/config-state'
        assert self.headers.get('Authorization') == 'Bearer fixture-token'
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        if any(body[k] != state[k] for k in ('base_version', 'patch_version')):
            self.reply(409, {'error': 'conflict'})
            return
        uploads += 1
        state.update(patch=body['patch'], agent_settings=body['agent_settings'], patch_version=100+uploads, agent_settings_initialized=True)
        self.reply(200, state)
    def log_message(self, *_):
        pass

center = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Center)
threading.Thread(target=center.serve_forever, daemon=True).start()
try:
    subprocess.run([sys.argv[1], f'http://127.0.0.1:{center.server_port}'], check=True, timeout=30)
    assert uploads == 2, uploads
finally:
    center.shutdown()
