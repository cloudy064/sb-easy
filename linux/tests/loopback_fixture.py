#!/usr/bin/env python3
"""Real embedded runtime acceptance, entirely loopback and ephemeral ports."""
import http.server
import select
import socket
import threading
import time

class Destination(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/slow':
            time.sleep(.45)
        body = b'fixture response' if self.path == '/slow' else b'invalid subscription'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_):
        pass

class Proxy(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_CONNECT(self):
        host, port = self.path.rsplit(':', 1)
        if host != '127.0.0.1' or int(port) != destination.server_port:
            self.send_error(403)
            return
        with socket.create_connection((host, int(port)), timeout=3) as remote:
            self.send_response(200)
            self.end_headers()
            self.wfile.flush()
            while True:
                readable, _, _ = select.select([remote, self.connection], [], [], 5)
                if not readable:
                    return
                for stream in readable:
                    data = stream.recv(65536)
                    if not data:
                        return
                    (self.connection if stream is remote else remote).sendall(data)
    def log_message(self, *_):
        pass

destination = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Destination)
proxy = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
for server in (destination, proxy):
    threading.Thread(target=server.serve_forever, daemon=True).start()

def close():
    proxy.shutdown()
    destination.shutdown()
