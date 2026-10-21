"""Offline real-engine check: one port, concurrent HTTP/CONNECT/SOCKS users.

Run: python3 c/tests/proxy_access_e2e.py /path/to/sing-box
Uses temporary files and loopback ephemeral ports; no production config.
"""
import concurrent.futures
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = self.client_address[0].encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def main():
    with tempfile.TemporaryDirectory(prefix='sb-access-e2e-') as tmp:
        root = Path(tmp)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(root/'key'),
                        '-out', str(root/'cert'), '-subj', '/CN=localhost', '-days', '1'], check=True, capture_output=True)
        http = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        https = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(root/'cert', root/'key')
        https.socket = ctx.wrap_socket(https.socket, server_side=True)
        for server in [http, https]:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            control_port = sock.getsockname()[1]
        config = {'log': {'level': 'error'}, 'inbounds': [{'type': 'mixed', 'tag': 'sb-easy-access',
                  'listen': '127.0.0.1', 'listen_port': port,
                  'users': [{'username': u, 'password': 'local-test-key'} for u in ['google', 'node_stable-id']]}],
                  'outbounds': [{'type': 'direct', 'tag': u, 'inet4_bind_address': ip}
                                for u, ip in [('aaa', '127.0.0.2'), ('sb-easy-node-stable-id', '127.0.0.3')]] +
                                [{'type': 'selector', 'tag': 'Google', 'outbounds': ['aaa', 'sb-easy-node-stable-id'], 'default': 'aaa'}],
                  'experimental': {'clash_api': {'external_controller': f'127.0.0.1:{control_port}', 'secret': 'test-only'}},
                  'route': {'rules': [{'inbound': 'sb-easy-access', 'auth_user': u, 'action': 'route', 'outbound': out}
                                      for u, out in [('google', 'Google'), ('node_stable-id', 'sb-easy-node-stable-id')]] + [{'inbound': 'sb-easy-access', 'action': 'reject'}]}}
        path = root/'config.json'
        path.write_text(json.dumps(config))
        os.chmod(path, 0o600)
        subprocess.run([sys.argv[1], 'check', '-c', str(path)], check=True, capture_output=True)
        with (root/'engine.log').open('w') as log:
            engine = subprocess.Popen([sys.argv[1], 'run', '-c', str(path)], stdout=log, stderr=log)
            try:
                for _ in range(100):
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.1):
                            break
                    except OSError:
                        if engine.poll() is not None:
                            raise RuntimeError((root/'engine.log').read_text())
                        time.sleep(.05)
                def request(user, scheme, tls, expected=None):
                    target = f"{'https' if tls else 'http'}://127.0.0.1:{https.server_port if tls else http.server_port}/"
                    r = subprocess.run(['curl', '--noproxy', '', '--max-time', '5', '-ksS',
                        '--proxy', f'{scheme}://127.0.0.1:{port}', '--proxy-user', user+':local-test-key', target], capture_output=True, text=True)
                    assert r.returncode == 0, r.stderr
                    assert r.stdout == (expected or ('127.0.0.2' if user == 'google' else '127.0.0.3')), r.stdout
                jobs = [(u, s, t) for _ in range(3) for u in ['google', 'node_stable-id'] for s in ['http', 'socks5h'] for t in [False, True]]
                with concurrent.futures.ThreadPoolExecutor(4) as pool:
                    list(pool.map(lambda args: request(*args), jobs))
                for credentials in [[], ['--proxy-user', 'google:wrong'], ['--proxy-user', 'unknown:local-test-key']]:
                    r = subprocess.run(['curl', '--noproxy', '', '--max-time', '5', '-sS', '-o', '/dev/null', '-w', '%{http_code}',
                        '--proxy', f'http://127.0.0.1:{port}', *credentials, f'http://127.0.0.1:{http.server_port}/'], capture_output=True, text=True)
                    assert r.stdout == '407', r.stdout
                print('PASS: 24 concurrent HTTP/HTTPS/SOCKS requests use their own exits; missing, wrong and unknown credentials rejected')
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                change = urllib.request.Request(f'http://127.0.0.1:{control_port}/proxies/Google',
                    data=json.dumps({'name': 'sb-easy-node-stable-id'}).encode(), method='PUT',
                    headers={'Authorization': 'Bearer test-only', 'Content-Type': 'application/json'})
                with opener.open(change, timeout=5) as response:
                    assert response.status == 204
                request('google', 'http', True, '127.0.0.3')
                request('node_stable-id', 'http', True, '127.0.0.3')
                print('PASS: group user follows selector change; pinned user keeps its exit')
            finally:
                engine.terminate()
                engine.wait(timeout=10)
                http.shutdown()
                https.shutdown()


if __name__ == '__main__':
    main()
