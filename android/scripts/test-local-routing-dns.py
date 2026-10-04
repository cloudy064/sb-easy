#!/usr/bin/env python3
"""Check real DNS packets with HTTP CONNECT exits that reject literal DNS IPs.

Run after generating LocalRoutingTest fixtures:
  python3 scripts/test-local-routing-dns.py /path/to/sing-box /path/to/fixtures
All traffic stays on loopback. A temporary CA verifies TLS without disabling it.
"""

import ipaddress
import json
from pathlib import Path
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def serve_tls(sock, server, destination):
    with server.context.wrap_socket(sock, server_side=True) as tls:
        with tls.makefile("rwb", buffering=0) as stream:
            first = stream.readline(4096)
            headers = {}
            while True:
                line = stream.readline(4096).strip()
                if not line:
                    break
                key, value = line.decode().split(":", 1)
                headers[key.lower()] = value.strip()
            if first.startswith(b"GET "):
                name = headers["host"]
                server.observations.append((server.marker, name, destination))
                body = server.marker.encode()
                stream.write(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() +
                             b"\r\nConnection: close\r\n\r\n" + body)
                return
            assert first.startswith(b"POST /dns-query ")
            remaining = int(headers["content-length"])
            chunks = []
            while remaining:
                chunk = stream.read(remaining)
                if not chunk:
                    raise EOFError("truncated DNS request")
                chunks.append(chunk)
                remaining -= len(chunk)
            message = b"".join(chunks)
            index, labels = 12, []
            while message[index]:
                length = message[index]
                labels.append(message[index + 1:index + 1 + length].decode())
                index += 1 + length
            index += 1
            qtype, qclass = struct.unpack("!HH", message[index:index + 4])
            index += 4
            name = ".".join(labels)
            server.observations.append((server.marker, name, destination))
            answer = (b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) +
                      ipaddress.ip_address(server.address).packed) if qtype == 1 and qclass == 1 else b""
            response = message[:2] + struct.pack("!HHHHH", 0x8180, 1, int(bool(answer)), 0, 0)
            response += message[12:index] + answer
            stream.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n" +
                         b"Content-Length: " + str(len(response)).encode() +
                         b"\r\nConnection: close\r\n\r\n" + response)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(4)
        try:
            destination = "direct"
            if self.server.marker != "direct":
                header = b""
                while not header.endswith(b"\r\n\r\n") and len(header) < 8192:
                    part = self.request.recv(1)
                    if not part:
                        return
                    header += part
                method, destination, _ = header.split(b"\r\n", 1)[0].decode().split(" ", 2)
                host, _, destination_port = destination.rpartition(":")
                try:
                    ipaddress.ip_address(host)
                    literal = True
                except ValueError:
                    literal = False
                if method != "CONNECT" or literal or destination_port != "443":
                    self.request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
                    return
                self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            serve_tls(self.request, self.server, destination)
        except (OSError, EOFError, ValueError, AssertionError):
            pass


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True

    def __init__(self, marker, address, context, observations):
        super().__init__(("127.0.0.1", 0), Handler)
        self.marker, self.address = marker, address
        self.context, self.observations = context, observations
        threading.Thread(target=self.serve_forever, daemon=True).start()


def query(name, destination_port, qtype=1):
    tid = b"\x12\x34"
    message = tid + struct.pack("!HHHHH", 0x100, 1, 0, 0, 0)
    message += b"".join(bytes([len(label)]) + label.encode() for label in name.split("."))
    message += b"\0" + struct.pack("!HH", qtype, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.sendto(message, ("127.0.0.1", destination_port))
        reply = sock.recv(4096)
    assert reply[:2] == tid
    _, flags, _, answers, _, _ = struct.unpack("!HHHHHH", reply[:12])
    assert flags & 15 == 0, (name, "DNS error", flags & 15)
    if qtype in (1, 28) and answers:
        assert answers == 1, (name, answers)
        return str(ipaddress.ip_address(reply[-4:] if qtype == 1 else reply[-16:]))
    return answers


def main():
    core, fixtures = sys.argv[1], Path(sys.argv[2])
    process = None
    servers = {}
    with tempfile.TemporaryDirectory(prefix="sb-routing-dns-") as temporary:
        directory = Path(temporary)
        cert, key = directory / "cert.pem", directory / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-keyout", str(key), "-out", str(cert), "-subj", "/CN=dns.google",
                        "-addext", "subjectAltName=DNS:dns.google,DNS:dns.alidns.com,IP:127.0.0.1," +
                        "DNS:claude.ai,DNS:*.claude.ai,DNS:chatgpt.com,DNS:*.chatgpt.com," +
                        "DNS:*.anthropic.com,DNS:*.example.org,DNS:*.example.net"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        context.set_alpn_protocols(["http/1.1"])
        observations = []
        addresses = {"Tokyo": "192.0.2.11", "US": "192.0.2.12", "Singapore": "192.0.2.13", "direct": "192.0.2.14"}
        servers = {tag: Server(tag, address, context, observations) for tag, address in addresses.items()}
        dns_port, api_port = port(), port()
        cfg = {
            "inbounds": [{"type": "direct", "tag": "dns-probe", "listen": "127.0.0.1",
                          "listen_port": dns_port, "network": "udp"}],
            "certificate": {"certificate_path": [str(cert)]},
            "experimental": {"clash_api": {"external_controller": f"127.0.0.1:{api_port}"}},
        }
        config = directory / "config.json"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def select(tag, node):
            path = urllib.parse.quote(tag, safe="")
            request = urllib.request.Request(f"http://127.0.0.1:{api_port}/proxies/{path}",
                data=json.dumps({"name": node}).encode(), method="PUT", headers={"Content-Type": "application/json"})
            with opener.open(request, timeout=2) as response:
                assert response.status == 204

        def expect(name, marker):
            assert query(name, dns_port) == addresses[marker], (name, marker)
            assert (marker, name, "direct" if marker == "direct" else "dns.google:443") in observations
            print(f"PASS: DNS {name} -> {marker}")

        tls_context = ssl.create_default_context(cafile=str(cert))
        socks_port = port()

        def browser(name, address, marker):
            with socket.create_connection(("127.0.0.1", socks_port), timeout=4) as sock:
                sock.settimeout(4)
                def exact(length):
                    result = b""
                    while len(result) < length:
                        part = sock.recv(length - len(result))
                        assert part, "SOCKS EOF"
                        result += part
                    return result
                sock.sendall(b"\x05\x01\x00")
                assert exact(2) == b"\x05\x00"
                ip = ipaddress.ip_address(address)
                sock.sendall(b"\x05\x01\x00" + bytes([1 if ip.version == 4 else 4]) + ip.packed + struct.pack("!H", 443))
                reply = exact(4)
                assert reply[1] == 0, reply
                exact(4 if reply[3] == 1 else 16)
                exact(2)
                with tls_context.wrap_socket(sock, server_hostname=name) as tls:
                    tls.sendall(f"GET / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n".encode())
                    response = tls.makefile("rb").read()
                    assert response.startswith(b"HTTP/1.1 200 OK"), response
                    assert response.split(b"\r\n\r\n", 1)[1].decode() == marker, (name, marker)
            assert (marker, name, name + ":443") in observations
            print(f"PASS: browser DNS IP + verified TLS {name} -> CONNECT hostname via {marker}")

        with (directory / "core.log").open("a") as log:
            def stop():
                nonlocal process
                if process is not None:
                    process.terminate()
                    process.wait(timeout=5)
                    process = None

            def start(fixture):
                nonlocal process
                stop()
                rendered = json.loads((fixtures / fixture).read_text())
                rendered["outbounds"] = [outbound for outbound in rendered["outbounds"]
                                        if outbound["type"] != "urltest" and outbound["tag"] != "Proxy"]
                for outbound in rendered["outbounds"]:
                    if outbound["tag"] in servers and outbound["tag"] != "direct":
                        outbound["type"] = "http"
                        outbound["server_port"] = servers[outbound["tag"]].server_address[1]
                for server in rendered["dns"]["servers"]:
                    if server["type"] == "https" and not server.get("detour"):
                        server["server"] = "127.0.0.1"
                        server["server_port"] = servers["direct"].server_address[1]
                rendered["inbounds"] = cfg["inbounds"] + [{"type": "socks", "tag": "browser-probe",
                                                          "listen": "127.0.0.1", "listen_port": socks_port}]
                rendered["certificate"] = cfg["certificate"]
                rendered.setdefault("experimental", {})["clash_api"] = cfg["experimental"]["clash_api"]
                rendered["experimental"].setdefault("cache_file", {})["path"] = str(directory / "cache.db")
                rendered["log"] = {"level": "debug"}
                config.write_text(json.dumps(rendered))
                check = subprocess.run([core, "check", "-c", str(config)], capture_output=True, text=True)
                assert check.returncode == 0, check.stderr
                process = subprocess.Popen([core, "run", "-c", str(config)], stdout=log, stderr=subprocess.STDOUT)
                deadline = time.monotonic() + 5
                while True:
                    assert process.poll() is None, (directory / "core.log").read_text()
                    try:
                        with opener.open(f"http://127.0.0.1:{api_port}/version", timeout=1):
                            break
                    except OSError:
                        assert time.monotonic() < deadline, "core startup timeout"
                        time.sleep(0.05)
                for outbound in rendered["outbounds"]:
                    if outbound["type"] == "selector" and outbound["tag"].startswith("sb-easy-local-"):
                        select(outbound["tag"], outbound["default"])

            try:
                start("routing.json")
                expect("claude.ai", "Tokyo")
                expect("api.anthropic.com", "Tokyo")
                expect("assets-proxy.anthropic.com", "Tokyo")
                expect("chatgpt.com", "US")
                expect("work.example.org", "US")
                expect("other.example.net", "Singapore")
                expect("qq.com", "direct")
                assert query("claude.ai", dns_port, 65) == 0
                select("sb-easy-local-claude", "Singapore")
                expect("after-switch.claude.ai", "Singapore")
                expect("after-switch.chatgpt.com", "US")
                expect("still-default.example.net", "Singapore")
                print("PASS: hostname DoH CONNECT, verified TLS and independent DNS exits")

                start("routing-http.json")
                fake_addresses = {}
                for host, marker in [("claude.ai", "Tokyo"), ("api.anthropic.com", "Tokyo"),
                                     ("chatgpt.com", "US"), ("work.example.org", "US"),
                                     ("other.example.net", "Singapore")]:
                    fake_addresses[host] = query(host, dns_port)
                    assert ipaddress.ip_address(fake_addresses[host]) in ipaddress.ip_network("198.18.0.0/15")
                    browser(host, fake_addresses[host], marker)
                ipv6 = query("ipv6.claude.ai", dns_port, 28)
                assert ipaddress.ip_address(ipv6) in ipaddress.ip_network("fc00::/18")
                browser("ipv6.claude.ai", ipv6, "Tokyo")
                assert query("claude.ai", dns_port, 65) == 0
                assert query("claude.ai", dns_port, 64) == 0
                expect("qq.com", "direct")
                select("sb-easy-local-claude", "Singapore")
                browser("claude.ai", fake_addresses["claude.ai"], "Singapore")
                browser("chatgpt.com", fake_addresses["chatgpt.com"], "US")
                start("routing-http.json")
                browser("claude.ai", fake_addresses["claude.ai"], "Tokyo")
                browser("chatgpt.com", fake_addresses["chatgpt.com"], "US")
                start("routing-http-ipv4.json")
                assert query("ipv6.claude.ai", dns_port, 28) == 0
                browser("claude.ai", fake_addresses["claude.ai"], "Tokyo")
                start("routing.json")
                browser("claude.ai", fake_addresses["claude.ai"], "Tokyo")
                expect("claude.ai", "Tokyo")
                start("routing-direct.json")
                expect("claude.ai", "direct")
                expect("chatgpt.com", "direct")
                expect("other.example.net", "direct")
                print("PASS: FakeIP browser routing, IPv6, no HTTPS hints, saved mapping restart and direct DNS")
            except Exception:
                print((directory / "core.log").read_text()[-6000:], file=sys.stderr)
                raise
            finally:
                stop()
                for server in servers.values():
                    server.shutdown()
                    server.server_close()


if __name__ == "__main__":
    main()
