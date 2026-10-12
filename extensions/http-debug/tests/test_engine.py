"""Real HTTPS -> mitmproxy -> authenticated-loopback-upstream -> TLS fixture.
No internet, no system CA installation and no user traffic are involved.
"""
import base64
from datetime import datetime, timedelta, timezone
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.cookiejar
import json
from pathlib import Path
import select
import socket
import socketserver
import ssl
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from engine import Engine
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0)); return s.getsockname()[1]


class Tunnel(socketserver.StreamRequestHandler):
    def handle(self):
        line = self.rfile.readline().decode()
        headers = {}
        while True:
            header = self.rfile.readline()
            if header in (b'\r\n', b'\n', b''): break
            k, v = header.decode().split(':', 1); headers[k.lower()] = v.strip()
        self.server.headers.append(headers)
        if not line.startswith('CONNECT '): return
        host, target_port = line.split()[1].rsplit(':', 1)
        with socket.create_connection((host, int(target_port)), timeout=5) as upstream:
            self.wfile.write(b'HTTP/1.1 200 Connection established\r\n\r\n'); self.wfile.flush()
            while True:
                readers, _, _ = select.select([self.connection, upstream], [], [], 5)
                if not readers: return
                for source in readers:
                    data = source.recv(65536)
                    if not data: return
                    (upstream if source is self.connection else self.connection).sendall(data)


class Target(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    received = []
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        self.received.append(body)
        response = json.dumps({'received': json.loads(body), 'decrypted': True}).encode()
        self.send_response(200); self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(response))); self.end_headers(); self.wfile.write(response)
    def log_message(self, *args): pass


class EngineTest(unittest.TestCase):
    def test_https_plaintext_edit_replay_and_web_auth(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
            now = datetime.now(timezone.utc)
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                    .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1))
                    .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), False)
                    .add_extension(x509.BasicConstraints(ca=True, path_length=None), True).sign(key, hashes.SHA256()))
            ca = directory/'target.pem'; ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            private = directory/'target.key'; private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            target = ThreadingHTTPServer(('127.0.0.1', 0), Target)
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(ca, private); target.socket = tls.wrap_socket(target.socket, server_side=True)
            upstream = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Tunnel); upstream.daemon_threads = True; upstream.headers = []
            for server in (target, upstream): threading.Thread(target=server.serve_forever, daemon=True).start()
            engine = Engine(); proxy, web = port(), port()
            try:
                engine.start(str(directory/'engine'), proxy, web, upstream.server_address[1])
                deadline = time.monotonic()+15
                while engine.phase == 'starting' and time.monotonic() < deadline: time.sleep(.1)
                self.assertEqual(engine.phase, 'running', engine.error)
                ready = threading.Event()
                def trust_fixture():
                    engine.master.options.update(ssl_verify_upstream_trusted_ca=str(ca)); ready.set()
                engine.loop.call_soon_threadsafe(trust_fixture); self.assertTrue(ready.wait(5))
                # The client trusts only this engine's exported public CA.
                client_ca = directory/'client.pem'; client_ca.write_bytes((directory/'engine/mitmproxy-ca-cert.pem').read_bytes())
                connection = http.client.HTTPSConnection('127.0.0.1', proxy, timeout=10, context=ssl.create_default_context(cafile=str(client_ca)))
                credential = base64.b64encode(f'sbeasy:{engine.password}'.encode()).decode()
                connection.set_tunnel('localhost', target.server_port, {'Proxy-Authorization': f'Basic {credential}'})
                connection.request('POST', '/fixture', body=b'{"prompt":"plaintext-fixture"}', headers={'Content-Type': 'application/json'})
                response = connection.getresponse(); self.assertEqual(response.status, 200); self.assertIn(b'plaintext-fixture', response.read()); connection.close()
                self.assertTrue(upstream.headers)
                self.assertNotIn('proxy-authorization', upstream.headers[0])
                base = f'http://127.0.0.1:{web}'
                with self.assertRaises(urllib.error.HTTPError) as denied: urllib.request.urlopen(base+'/flows.json')
                self.assertIn(denied.exception.code, (401, 403))
                cookies = http.cookiejar.CookieJar(); browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))
                browser.open(engine.snapshot()['url']).read()
                flows = json.load(browser.open(base+'/flows.json')); self.assertEqual(len(flows), 1)
                flow = flows[0]['id']; body_url = base+f'/flows/{flow}/response/content.data'
                self.assertIn(b'plaintext-fixture', browser.open(body_url).read())
                xsrf = 'fixture-csrf-token'
                cookie_header = '; '.join(f'{c.name}={c.value}' for c in cookies) + f'; _mitmproxy_xsrf={xsrf}'
                def mutate(path, data, method):
                    req = urllib.request.Request(base+path, json.dumps(data).encode(), {'Content-Type':'application/json', 'X-XSRFToken':xsrf, 'Cookie': cookie_header}, method=method)
                    return browser.open(req).read()
                mutate(f'/flows/{flow}', {'request': {'content': '{"prompt":"edited-replay"}'}}, 'PUT')
                mutate(f'/flows/{flow}/replay', {}, 'POST')
                deadline = time.monotonic()+10
                while b'{"prompt":"edited-replay"}' not in Target.received and time.monotonic() < deadline: time.sleep(.1)
                self.assertIn(b'{"prompt":"edited-replay"}', Target.received)
                har = json.load(browser.open(base+'/sbeasy.har'))
                self.assertIn('entries', har['log'])
                with self.assertRaises(urllib.error.HTTPError) as denied:
                    mutate('/options', {'scripts': ['forbidden.py']}, 'PUT')
                self.assertEqual(denied.exception.code, 403)
                with self.assertRaises(urllib.error.HTTPError) as denied:
                    mutate('/commands/save.har', {}, 'POST')
                self.assertEqual(denied.exception.code, 403)
                self.assertGreater(len(bytes.fromhex(engine.certificate()['der'])), 500)
            finally:
                engine.stop(); target.shutdown(); target.server_close(); upstream.shutdown(); upstream.server_close()
            self.assertEqual(engine.phase, 'stopped')


if __name__ == '__main__': unittest.main()
