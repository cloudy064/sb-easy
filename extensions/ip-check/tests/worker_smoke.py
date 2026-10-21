"""Frozen worker + real sing-box against loopback-only HTTP proxy fixtures.

The fixture never forwards requests. It returns an error, or waits for local
cancellation. No user profile, system proxy or running core is read or changed.
"""
import argparse
import json
import os
from pathlib import Path
import queue
import socketserver
import struct
import subprocess
import tempfile
import threading
import time

parser = argparse.ArgumentParser()
parser.add_argument("worker")
parser.add_argument("sing_box")
parser.add_argument("--interface", default="Loopback Pseudo-Interface 1")
args = parser.parse_args()
mode = "reject"
requests = queue.Queue()
closed = threading.Event()


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 16384:
            part = self.request.recv(2048)
            if not part:
                return
            data += part
        requests.put(data.split(b"\r\n", 1)[0])
        if mode == "reject":
            self.request.sendall(b"HTTP/1.1 503 Fixture unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        else:
            try:
                while self.request.recv(2048):
                    pass
            except OSError:
                pass
            finally:
                closed.set()


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True


with tempfile.TemporaryDirectory(prefix="sb-easy-ip-check-acceptance-") as directory, Server(("127.0.0.1", 0), Handler) as server:
    threading.Thread(target=server.serve_forever, daemon=True).start()
    env = dict(os.environ, TEMP=directory, TMP=directory)
    process = subprocess.Popen([str(Path(args.worker).resolve())], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    answers = queue.Queue()

    def reader():
        try:
            while True:
                header = process.stdout.read(4)
                if len(header) != 4:
                    break
                length, = struct.unpack("<I", header)
                assert 0 < length < 768 * 1024
                answers.put(json.loads(process.stdout.read(length)))
        finally:
            answers.put(None)

    threading.Thread(target=reader, daemon=True).start()

    def call(method, params=None, timeout=3):
        body = json.dumps({"method": method, "params": params or {}}).encode()
        process.stdin.write(struct.pack("<I", len(body)) + body)
        process.stdin.flush()
        reply = answers.get(timeout=timeout)
        assert reply and reply["ok"], reply
        return reply["result"]

    params = {"sing_box": str(Path(args.sing_box).resolve()), "interface": args.interface,
              "config": {"outbounds": [{"type": "http", "tag": "fixture",
                  "server": "127.0.0.1", "server_port": server.server_address[1]}]},
              "tags": ["fixture"], "ipv6": False, "bootstrap_dns": "223.5.5.5"}
    try:
        assert call("snapshot", timeout=20)["phase"] == "idle"
        assert call("start", params)["phase"] == "running"
        assert requests.get(timeout=8) == b"CONNECT api.ipify.org:443 HTTP/1.1"
        deadline = time.monotonic() + 8
        while (state := call("snapshot"))["phase"] == "running" and time.monotonic() < deadline:
            time.sleep(.05)
        assert state["phase"] == "failed", state
        assert state["results"][0]["ipv4"]["reason"] == "echo_connection_failed", state
        assert not list(Path(directory).glob("sb-easy-ip-check-*")), "Credentials left after failed probe"

        mode = "wait"
        assert call("start", params)["phase"] == "running"
        assert requests.get(timeout=8) == b"CONNECT api.ipify.org:443 HTTP/1.1"
        assert list(Path(directory).glob("sb-easy-ip-check-*")), "Private runtime config fixture missing"
        begin = time.monotonic()
        assert call("cancel")["cancel_requested"]
        deadline = time.monotonic() + 4
        while (state := call("snapshot"))["phase"] == "running" and time.monotonic() < deadline:
            time.sleep(.05)
        assert state["phase"] == "cancelled", state
        assert time.monotonic() - begin < 4
        assert closed.wait(1), "Private child did not close its fixture connection"
        assert not list(Path(directory).glob("sb-easy-ip-check-*")), "Credentials left after cancellation"

        # EOF is also an implicit cancel, including an in-flight tunnel.
        closed.clear()
        call("start", params)
        assert requests.get(timeout=8) == b"CONNECT api.ipify.org:443 HTTP/1.1"
        process.stdin.close()
        process.wait(timeout=8)
        assert closed.wait(1), "EOF left a private child connected"
        assert not list(Path(directory).glob("sb-easy-ip-check-*")), "EOF left credential files"
        print("PASS: frozen worker IPC, isolated loopback core, no direct fallback, responsive cancellation and EOF cleanup.")
    finally:
        if process.poll() is None:
            if not process.stdin.closed:
                process.stdin.close()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        server.shutdown()
