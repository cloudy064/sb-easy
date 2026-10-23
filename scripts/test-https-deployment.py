#!/usr/bin/env python3
"""Isolated HTTPS/login/WebSocket check. Never changes host trust or live services."""
import argparse
import base64
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


class ClashFixture(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        assert self.headers.get('Authorization') == 'Bearer isolated-clash-secret' or parse_qs(urlsplit(self.path).query).get('token') == ['isolated-clash-secret']
        if self.headers.get('Upgrade', '').lower() == 'websocket':
            key = self.headers['Sec-WebSocket-Key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
            self.send_response(101)
            self.send_header('Upgrade', 'websocket')
            self.send_header('Connection', 'Upgrade')
            self.send_header('Sec-WebSocket-Accept', base64.b64encode(hashlib.sha1(key.encode()).digest()).decode())
            self.end_headers()
            data = b'{"up":12,"down":34}'
            self.wfile.write(bytes([0x81, len(data)]) + data)
            self.wfile.flush()
            time.sleep(1)
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', type=Path, default=ROOT / 'build/c-product-audit/sb-easy-c-server')
    args = parser.parse_args()
    children = []
    upstream = ThreadingHTTPServer(('127.0.0.1', 0), ClashFixture)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    with tempfile.TemporaryDirectory(prefix='sbeasy-https-') as name:
        tmp = Path(name)
        try:
            envfile = tmp / 'generated.env'
            configure = ['python3', str(ROOT / 'scripts/configure-https.py'), '--domain', 'panel.example.test', '--output', str(envfile)]
            subprocess.run(configure, check=True, capture_output=True)
            assert envfile.stat().st_mode & 0o777 == 0o600
            original = envfile.read_bytes()
            assert subprocess.run(configure, capture_output=True).returncode != 0
            assert envfile.read_bytes() == original
            assert subprocess.run(configure[:3] + ['https://bad.test/path', '--output', str(tmp / 'invalid.env')], capture_output=True).returncode != 0
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-keyout', str(tmp / 'key.pem'), '-out', str(tmp / 'cert.pem'), '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost'], check=True, capture_output=True)
            backend, tls_port, http_port = port(), port(), port()
            base = f'https://127.0.0.1:{tls_port}'
            env = {**os.environ, 'JWT_SECRET': secrets.token_hex(32), 'ADMIN_PASSWORD': 'https-fixture-password', 'WG_ENABLED': 'false', 'SINGBOX_MANAGED': 'false', 'SUBSCRIPTION_AUTO_REFRESH': 'false', 'SINGBOX_API_URL': f'http://127.0.0.1:{upstream.server_port}', 'SINGBOX_API_SECRET': 'isolated-clash-secret', 'STATIC_DIR': str(ROOT / 'frontend/dist'), 'LOG_LEVEL': 'warn'}
            log = open(tmp / 'services.log', 'wb')
            children.append(subprocess.Popen([str(args.server.resolve()), str(tmp / 'test.db'), str(ROOT / 'migrations'), '127.0.0.1', str(backend), base], env=env, stdout=log, stderr=log))
            # Use the production site directives and add only this fixture's cert/ports.
            site = (ROOT / 'deploy/Caddyfile').read_text().replace('admin off', f'admin off\n\thttp_port {http_port}\n\thttps_port {tls_port}')
            site = site.replace('{$PANEL_DOMAIN} {', f'127.0.0.1:{tls_port} {{\n\ttls {tmp}/cert.pem {tmp}/key.pem')
            site = site.replace('{$PANEL_UPSTREAM:127.0.0.1:51821}', f'127.0.0.1:{backend}')
            config = tmp / 'Caddyfile'; config.write_text(site)
            children.append(subprocess.Popen(['caddy', 'run', '--config', str(config), '--adapter', 'caddyfile'], env={**env, 'XDG_DATA_HOME': str(tmp / 'data'), 'XDG_CONFIG_HOME': str(tmp / 'config')}, stdout=log, stderr=log))
            context = ssl.create_default_context(cafile=str(tmp / 'cert.pem'))

            def request(method, path, body=None, token=None):
                connection = http.client.HTTPSConnection('127.0.0.1', tls_port, context=context, timeout=5)
                headers = {'Content-Type': 'application/json'}
                if token:
                    headers['Authorization'] = 'Bearer ' + token
                connection.request(method, path, json.dumps(body) if body is not None else None, headers)
                response = connection.getresponse()
                result = response.status, dict(response.getheaders()), response.read()
                connection.close()
                return result

            for _ in range(100):
                try:
                    if request('GET', '/api/health')[0] == 200:
                        break
                except (OSError, http.client.HTTPException):
                    pass
                time.sleep(.05)
            else:
                raise AssertionError('Services failed to start: ' + (tmp / 'services.log').read_text())
            status, headers, body = request('POST', '/api/auth/login', {'username': 'admin', 'password': 'https-fixture-password'})
            assert status == 200, body
            assert 'Secure' in headers['Set-Cookie'] and 'HttpOnly' in headers['Set-Cookie']
            assert headers['Strict-Transport-Security'] == 'max-age=31536000'
            assert headers['Cache-Control'] == 'no-store'
            token = json.loads(body)['token']
            assert request('GET', '/api/auth/session', token=token)[0] == 200
            assert request('GET', '/api/auth/session')[0] == 401
            redirect = http.client.HTTPConnection('127.0.0.1', http_port, timeout=5)
            redirect.request('GET', '/api/health', headers={'Host': f'127.0.0.1:{http_port}'})
            response = redirect.getresponse()
            # Caddy's internal https_port override retains the public HTTPS port.
            assert response.status == 308 and response.getheader('Location') == 'https://127.0.0.1/api/health', (response.status, response.getheader('Location'))
            redirect.close()
            with context.wrap_socket(socket.create_connection(('127.0.0.1', tls_port), timeout=5), server_hostname='127.0.0.1') as ws:
                ws.sendall((f'GET /api/sing-box/ws/traffic?token={token} HTTP/1.1\r\nHost: 127.0.0.1:{tls_port}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n').encode())
                received = b''
                while b'"down":34' not in received:
                    chunk = ws.recv(4096)
                    assert chunk, received
                    received += chunk
                assert received.startswith(b'HTTP/1.1 101'), received
            print('PASS: private setup/no overwrite, verified TLS, HTTP redirect, secure login cookie, auth and proxied WebSocket')
        finally:
            for child in reversed(children):
                child.terminate()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill(); child.wait()
            upstream.shutdown(); upstream.server_close()


if __name__ == '__main__':
    main()
