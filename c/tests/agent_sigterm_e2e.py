#!/usr/bin/env python3
"""SIGTERM must stop the agent cleanly and take the managed sing-box child with it."""
import argparse
import http.server
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
import time

FAKE_SINGBOX = """#!/bin/sh
if [ "$1" = "check" ]; then exit 0; fi
if [ "$1" = "run" ]; then
    echo "$$" > "$3.pid"
    trap 'exit 0' TERM INT
    while :; do sleep 0.05; done
fi
exit 2
"""

CONFIG = {"log": {"level": "error"}, "inbounds": [],
          "outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "direct"}}


class Panel(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, status, body, headers=None):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.startswith("/api/agent/config"):
            self._send(200, CONFIG, {"ETag": '"sigterm-test"'})
        elif self.path.startswith("/api/agent/commands"):
            self._send(200, [])
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        self._send(200, {"ok": True})


def pid_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def run(args, root):
    binary = root / "fake-sing-box"
    binary.write_text(FAKE_SINGBOX)
    binary.chmod(0o700)
    config = root / "sing-box.json"
    pid_file = Path(str(config) + ".pid")
    with http.server.HTTPServer(("127.0.0.1", 0), Panel) as panel:
        threading.Thread(target=panel.serve_forever, daemon=True).start()
        env = {key: os.environ[key] for key in ("PATH", "ASAN_OPTIONS", "UBSAN_OPTIONS") if key in os.environ}
        env.update(HOME=str(root), SB_EASY_SERVER=f"http://127.0.0.1:{panel.server_port}",
                   AGENT_TOKEN="sigterm-test-token", SINGBOX_CONFIG_PATH=str(config),
                   SINGBOX_BIN=str(binary), SINGBOX_MANAGED="true", SINGBOX_VALIDATE_CONFIG="true",
                   AGENT_UI_ENABLED="false", AGENT_INTERVAL="1")
        log = open(root / "agent.log", "w+")
        agent = subprocess.Popen([str(args.agent)], env=env, cwd=root, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 25
            child = 0
            while time.monotonic() < deadline and not child:
                assert agent.poll() is None, f"agent exited early with {agent.returncode}"
                if pid_file.exists():
                    text = pid_file.read_text().strip()
                    child = int(text) if text else 0
                time.sleep(0.1)
            assert child, "managed sing-box never started"
            assert pid_alive(child)
            agent.send_signal(signal.SIGTERM)
            code = agent.wait(timeout=10)
            assert code == 0, f"agent exit status {code}"
            deadline = time.monotonic() + 5
            while pid_alive(child) and time.monotonic() < deadline:
                time.sleep(0.05)
            assert not pid_alive(child), "sing-box child outlived the agent"
            print("PASS: SIGTERM stops the agent with status 0 and the managed sing-box child exits")
        finally:
            if agent.poll() is None:
                agent.kill()
                agent.wait()
            log.seek(0)
            print(log.read()[-3000:])
            log.close()
            panel.shutdown()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent", type=Path, required=True)
    args = parser.parse_args()
    args.agent = args.agent.resolve()
    with tempfile.TemporaryDirectory(prefix="sb-c-sigterm-") as directory:
        run(args, Path(directory))
