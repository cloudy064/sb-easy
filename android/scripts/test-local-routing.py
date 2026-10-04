#!/usr/bin/env python3
"""Exercise the real pinned core with Kotlin-rendered local-routing fixtures.

Generate fixtures with SB_EASY_ROUTING_FIXTURE_DIR=/private/tmp/path and
./gradlew :core:testDebugUnitTest --tests '*LocalRoutingTest' --rerun-tasks.
Run: python3 scripts/test-local-routing.py /path/to/sing-box /private/tmp/path
Only loopback mock exits are used; no service credentials or external traffic.
"""

import json
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request


def read_exact(stream, length):
    value = b""
    while len(value) < length:
        chunk = stream.read(length - len(value))
        if not chunk:
            raise EOFError("unexpected end of socket")
        value += chunk
    return value


class ExitHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(3)
        try:
            if self.server.marker != "direct":
                version, count = read_exact(self.rfile, 2)
                assert version == 5
                read_exact(self.rfile, count)
                self.wfile.write(b"\x05\x00")
                version, command, _, atyp = read_exact(self.rfile, 4)
                assert version == 5 and command == 1
                if atyp == 3:
                    read_exact(self.rfile, read_exact(self.rfile, 1)[0])
                else:
                    read_exact(self.rfile, 4 if atyp == 1 else 16)
                read_exact(self.rfile, 2)
                self.wfile.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            # Ignore the URL-test/DoH background connections; answer our HTTP probes.
            first = self.rfile.readline(4096)
            if not first.startswith(b"GET "):
                return
            while self.rfile.readline(4096).strip():
                pass
            body = self.server.marker.encode()
            self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() +
                             b"\r\nConnection: close\r\n\r\n" + body)
        except (EOFError, OSError, AssertionError):
            pass


class ExitServer(socketserver.ThreadingTCPServer):
    daemon_threads = True

    def __init__(self, marker):
        super().__init__(("127.0.0.1", 0), ExitHandler)
        self.marker = marker
        threading.Thread(target=self.serve_forever, daemon=True).start()


def available_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def probe(port, host, destination_port=80):
    with socket.create_connection(("127.0.0.1", port), timeout=4) as sock:
        sock.settimeout(4)
        stream = sock.makefile("rb")
        sock.sendall(b"\x05\x01\x00")
        assert read_exact(stream, 2) == b"\x05\x00"
        domain = host.encode()
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(domain)]) + domain + struct.pack("!H", destination_port))
        version, status, _, atyp = read_exact(stream, 4)
        assert version == 5 and status == 0, (host, status)
        read_exact(stream, 4 if atyp == 1 else 16)
        read_exact(stream, 2)
        sock.sendall(f"GET /probe HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        result = stream.read().decode()
        assert result.startswith("HTTP/1.1 200 OK"), result
        return result.split("\r\n\r\n", 1)[1]


def main():
    core, fixtures = sys.argv[1], Path(sys.argv[2])
    servers = {name: ExitServer(name) for name in ("Tokyo", "US", "Singapore", "direct")}
    socks_port, api_port = available_port(), available_port()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    process = None
    log_file = None
    with tempfile.TemporaryDirectory(prefix="sb-local-routing-") as temporary:
        directory = Path(temporary)

        def stop():
            nonlocal process, log_file
            if process is not None:
                process.terminate()
                process.wait(timeout=5)
                process = None
                log_file.close()

        def start(name):
            nonlocal process, log_file
            cfg = json.loads((fixtures / name).read_text())
            for outbound in cfg["outbounds"]:
                if outbound["tag"] in servers and outbound["type"] == "socks":
                    outbound["server_port"] = servers[outbound["tag"]].server_address[1]
            cfg["inbounds"] = [{"type": "socks", "tag": "probe-in", "listen": "127.0.0.1", "listen_port": socks_port}]
            cfg["experimental"]["clash_api"] = {"external_controller": f"127.0.0.1:{api_port}"}
            cfg["experimental"]["cache_file"]["path"] = str(directory / "cache.db")
            # Resolve only the direct test destinations locally. Proxy routes still
            # receive real domain destinations, so they must match the generated rules.
            cfg["dns"]["servers"].append({"type": "hosts", "tag": "test-hosts", "predefined": {
                "qq.com": "127.0.0.1", "manage.example.com": "127.0.0.1", "chatgpt.com": "127.0.0.1",
            }})
            cfg["dns"]["rules"].insert(0, {"domain": ["qq.com", "manage.example.com", "chatgpt.com"], "action": "route", "server": "test-hosts"})
            cfg["route"]["default_domain_resolver"] = {"server": "test-hosts"}
            file = directory / "config.json"
            file.write_text(json.dumps(cfg))
            checked = subprocess.run([core, "check", "-c", str(file)], capture_output=True, text=True)
            assert checked.returncode == 0, checked.stderr
            log_file = (directory / "core.log").open("a")
            process = subprocess.Popen([core, "run", "-c", str(file)], stdout=log_file, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise AssertionError((directory / "core.log").read_text())
                try:
                    with opener.open(f"http://127.0.0.1:{api_port}/proxies", timeout=1) as response:
                        json.load(response)
                    # Mirror SbEasyVpnService's synchronous restoration before
                    # reporting ready, including returning to an older choice.
                    for outbound in cfg["outbounds"]:
                        if outbound["type"] == "selector" and outbound["tag"].startswith("sb-easy-local-"):
                            select(outbound["tag"], outbound["default"])
                    return
                except OSError:
                    time.sleep(0.05)
            raise AssertionError("core API startup timed out")

        def select(tag, node):
            path = urllib.parse.quote(tag, safe="")
            request = urllib.request.Request(f"http://127.0.0.1:{api_port}/proxies/{path}",
                data=json.dumps({"name": node}).encode(), method="PUT", headers={"Content-Type": "application/json"})
            with opener.open(request, timeout=2) as response:
                assert response.status == 204

        def expect(host, marker, port=80):
            actual = probe(socks_port, host, port)
            assert actual == marker, f"{host}: expected {marker}, got {actual}"
            print(f"PASS: {host} -> {marker}")

        try:
            start("routing.json")
            expect("api.anthropic.com", "Tokyo")
            expect("claudeusercontent.com", "Tokyo")
            expect("api.openai.com", "US")
            expect("cdn.oaistatic.com", "US")
            expect("work.example.org", "US")
            expect("uncategorized.example.net", "Singapore")
            expect("qq.com", "direct", servers["direct"].server_address[1])
            expect("manage.example.com", "direct", servers["direct"].server_address[1])
            select("sb-easy-local-claude", "Singapore")
            expect("api.anthropic.com", "Singapore")
            expect("api.openai.com", "US")
            expect("uncategorized.example.net", "Singapore")
            select("sb-easy-local-gpt", "direct")
            expect("chatgpt.com", "direct", servers["direct"].server_address[1])
            expect("api.anthropic.com", "Singapore")
            # A saved local policy must beat the previous runtime selection cache.
            stop()
            start("routing-claude-us.json")
            expect("api.anthropic.com", "US")
            expect("api.openai.com", "US")
            expect("uncategorized.example.net", "Singapore")
            stop()
            start("routing.json")
            expect("api.anthropic.com", "Tokyo")
            expect("api.openai.com", "US")
            print("PASS: independent switching, direct routing and saved-policy restart")
        except Exception:
            if process is not None:
                stop()
            if (directory / "core.log").is_file():
                print((directory / "core.log").read_text(), file=sys.stderr)
            raise
        finally:
            stop()
            for server in servers.values():
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    main()
