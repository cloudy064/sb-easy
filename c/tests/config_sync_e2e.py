#!/usr/bin/env python3
"""Isolated server + two agents: inheritance, upload, restart and conflict recovery."""
import argparse
import http.cookiejar
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Api:
    def __init__(self, url):
        self.url = url
        self.token = None
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(self, path, body=None, method=None, expected=200):
        headers = {"X-SB-Easy-UI": "1"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        if body is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.url + path, data=None if body is None else json.dumps(body).encode(),
                                     headers=headers, method=method)
        try:
            response = self.opener.open(req, timeout=2)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            data = response.read()
            result = json.loads(data) if data else None
            assert response.status == expected, (path, response.status, result)
            return result


class ClashFixture:
    """Retain a wrong cached selection until the real agent calls the API."""
    def __init__(self):
        self.selected = "alternate"
        self.selections = []
        self.reject_next = 1  # Simulate the core API still starting after reload.
        self.lock = threading.Lock()
        fixture = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, status, value):
                body = json.dumps(value).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def authenticated(self):
                if self.headers.get("Authorization") != "Bearer isolated-controller":
                    self.reply(401, {"message": "unauthorized"})
                    return False
                return True

            def do_GET(self):
                if not self.authenticated():
                    return
                if self.path == "/connections":
                    self.reply(200, {"connections": [], "uploadTotal": 0, "downloadTotal": 0})
                elif self.path == "/proxies":
                    with fixture.lock:
                        selected = fixture.selected
                    self.reply(200, {"proxies": {"Choice": {"type": "Selector", "now": selected,
                                                          "all": ["direct", "alternate"]}}})
                else:
                    self.reply(404, {})

            def do_PUT(self):
                if not self.authenticated():
                    return
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                if self.path != "/proxies/Choice" or body.get("name") not in ("direct", "alternate"):
                    self.reply(400, {"message": "invalid selection"})
                    return
                with fixture.lock:
                    if fixture.reject_next:
                        fixture.reject_next -= 1
                        self.reply(503, {"message": "starting"})
                        return
                    fixture.selected = body["name"]
                    fixture.selections.append(body["name"])
                self.reply(200, {})

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def is_selected(self, target):
        with self.lock:
            return self.selected == target and self.selections and self.selections[-1] == target

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def wait(check, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except (OSError, ValueError):
            pass
        time.sleep(.1)
    raise AssertionError("config sync did not converge")


def run(args, root):
    server_api = Api(f"http://127.0.0.1:{port()}")
    common = {k: os.environ[k] for k in ("PATH", "ASAN_OPTIONS", "UBSAN_OPTIONS") if k in os.environ}
    common["HOME"] = str(root)
    server_env = dict(common, BIND_ADDR=server_api.url.removeprefix("http://"),
                      DATABASE_URL="sqlite:" + str(root / "panel.db"), MIGRATIONS_DIR=str(args.repo / "migrations"),
                      JWT_SECRET="isolated-sync-secret", ADMIN_PASSWORD="isolated-sync-password",
                      WG_ENABLED="false", SINGBOX_MANAGED="false", SUBSCRIPTION_AUTO_REFRESH="false",
                      PUBLIC_SERVER=server_api.url, STATIC_DIR=str(root / "static"), LOG_LEVEL="warn")
    processes, logs, controllers = [], [], []

    def start(binary, env, name):
        log = open(root / (name + ".log"), "a")
        logs.append(log)
        process = subprocess.Popen([str(binary)], env=env, cwd=root, stdout=log, stderr=subprocess.STDOUT)
        processes.append(process)
        return process

    def stop(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    def start_server():
        process = start(args.server, server_env, "server")
        wait(lambda: server_api.request("/api/health"))
        server_api.token = server_api.request("/api/auth/login", {"password": "isolated-sync-password"})["token"]
        return process

    def default(level, timestamp=False):
        return {"name": "Default", "mode": "full", "template": {
            "log": {"level": level, "timestamp": timestamp}, "inbounds": [],
            "outbounds": [{"type": "direct", "tag": "direct"}, {"type": "direct", "tag": "alternate"},
                          {"type": "selector", "tag": "Choice", "outbounds": ["direct", "alternate"], "default": "direct"}],
            "route": {"final": "Choice", "rules": []}}}

    def update(path, state, patch, settings=None):
        return server_api.request(path, {"base_version": state["base_version"], "patch_version": state["patch_version"],
                                        "patch": patch, "agent_settings": settings or {}}, "PUT")

    def local_put(ui, state, patch, resolve=None):
        body = {key: state[key] for key in ("base_version", "patch_version", "local_version")}
        body.update(patch=patch, agent_settings=state["agent_settings"])
        if resolve:
            body["resolve"] = resolve
        return ui.request("/api/config-state", body, "PUT")

    def login(ui):
        wait(lambda: ui.request("/health"))
        ui.request("/api/login", {"username": "admin", "password": "isolated-local-password"})

    try:
        server = start_server()
        server_api.request("/api/hosts/profiles/default", default("info"), "PUT")
        agents = []
        for index in range(2):
            controller = ClashFixture()
            controllers.append(controller)
            host = server_api.request("/api/hosts", {"name": f"sync-{index}", "profile_id": "default",
                        "capabilities": {"runs_singbox": True, "is_wg_member": False},
                        "clash_api": controller.url, "clash_secret": "isolated-controller"})
            token = server_api.request(f'/api/hosts/{host["id"]}/token')["agent_token"]
            directory = root / f"agent-{index}"
            directory.mkdir()
            config = directory / "sing-box.json"
            ui = Api(f"http://127.0.0.1:{port()}")
            env = dict(common, SB_EASY_SERVER=server_api.url, AGENT_TOKEN=token,
                       SINGBOX_CONFIG_PATH=str(config), AGENT_UI_BIND=ui.url.removeprefix("http://"),
                       AGENT_UI_PASSWORD="isolated-local-password", SINGBOX_MANAGED="false",
                       SINGBOX_VALIDATE_CONFIG="false", RELOAD_CMD="/bin/true", RESTART_CMD="/bin/true", AGENT_INTERVAL="1")
            process = start(args.agent, env, f"agent-{index}")
            login(ui)
            agents.append({"ui": ui, "env": env, "process": process, "config": config,
                           "path": f'/api/hosts/{host["id"]}/config-state', "controller": controller})

        def applied(agent, level, timestamp):
            if not agent["config"].exists():
                return False
            log = json.loads(agent["config"].read_text())["log"]
            return log["level"] == level and log["timestamp"] == timestamp

        wait(lambda: all(applied(a, "info", False) for a in agents))
        wait(lambda: all(a["controller"].is_selected("direct") for a in agents))
        a, b = agents
        initial = server_api.request(a["path"])
        assert initial["patch"] == {} and initial["agent_settings"] == {}
        changed = update(a["path"], initial, {"log": {"level": "debug"}})
        assert changed["patch_version"] > initial["patch_version"]
        server_api.request("/api/hosts/profiles/default", default("warn", True), "PUT")
        wait(lambda: applied(a, "debug", True) and applied(b, "warn", True))
        server_api.request(a["path"], {"base_version": initial["base_version"], "patch_version": initial["patch_version"],
                                      "patch": {}, "agent_settings": {}}, "PUT", expected=409)
        print("PASS default inheritance, per-device override and stale write rejection")

        ui = a["ui"]
        wait(lambda: ui.request("/api/config-state")["base_version"] == server_api.request(a["path"])["base_version"])
        state = ui.request("/api/config-state")
        local_put(ui, state, {"log": {"level": "error"}})
        wait(lambda: server_api.request(a["path"])["patch"] == {"log": {"level": "error"}} and applied(a, "error", True))
        ui.request("/api/settings", {"expected": {key: state[key] for key in
                   ("base_version", "patch_version", "local_version")}, "local_proxy_egress": True}, "PUT", expected=409)
        assert "_sync_version" in ui.request("/api/settings")
        assert "expected" not in server_api.request(a["path"])["agent_settings"]
        current = server_api.request(a["path"])
        update(a["path"], current, {})
        wait(lambda: applied(a, "warn", True) and not ui.request("/api/config-state")["pending"])
        print("PASS local edits upload and clearing patch restores latest default")

        # A selector's local cached choice must not defeat server-owned policy.
        current = server_api.request(a["path"])
        update(a["path"], current, current["patch"], {"selector_selections": {"Choice": "alternate"}})
        wait(lambda: a["controller"].is_selected("alternate") and b["controller"].is_selected("direct"))
        current = server_api.request(a["path"])
        update(a["path"], current, current["patch"], {})
        wait(lambda: a["controller"].is_selected("direct"))
        ui.request("/api/proxies", {"group": "Choice", "name": "alternate"}, "PUT")
        wait(lambda: server_api.request(a["path"])["agent_settings"].get("selector_selections") == {"Choice": "alternate"})
        current = server_api.request(a["path"])
        update(a["path"], current, current["patch"], {})
        wait(lambda: a["controller"].is_selected("direct") and not ui.request("/api/config-state")["pending"])
        print("PASS selector cache is reconciled, local choice uploads and reset restores inherited choice")

        # Durable outbox while the server is unavailable, including an agent restart.
        stop(server)
        state = ui.request("/api/config-state")
        local_put(ui, state, {"log": {"level": "debug"}})
        assert ui.request("/api/config-state")["pending"]
        stop(a["process"])
        a["process"] = start(args.agent, a["env"], "agent-0")
        login(ui)
        assert ui.request("/api/config-state")["pending"]
        server = start_server()
        wait(lambda: server_api.request(a["path"])["patch"] == {"log": {"level": "debug"}})
        wait(lambda: not ui.request("/api/config-state")["pending"] and applied(a, "debug", True))
        print("PASS offline edit survives agent restart and uploads on reconnect")

        # Concurrent administrator edit must remain intact, with local intent retained.
        stop(server)
        local_put(ui, ui.request("/api/config-state"), {"log": {"level": "error"}})
        stop(a["process"])
        server = start_server()
        update(a["path"], server_api.request(a["path"]), {"log": {"level": "warn"}})
        a["process"] = start(args.agent, a["env"], "agent-0")
        login(ui)
        wait(lambda: ui.request("/api/config-state")["conflict"])
        conflict = ui.request("/api/config-state")
        assert conflict["pending"] and conflict["patch"] == {"log": {"level": "error"}}
        assert server_api.request(a["path"])["patch"] == {"log": {"level": "warn"}}
        local_put(ui, conflict, conflict["server_patch"], "use_server")
        wait(lambda: not ui.request("/api/config-state")["pending"] and applied(a, "warn", True))
        print("PASS concurrent server edit preserves both versions and explicit resolution converges")
    finally:
        for process in reversed(processes):
            stop(process)
        for controller in controllers:
            controller.close()
        for log in logs:
            log.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--agent", type=Path, required=True)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    args.server, args.agent = args.server.resolve(), args.agent.resolve()
    with tempfile.TemporaryDirectory(prefix="sb-config-sync-") as directory:
        try:
            run(args, Path(directory))
        except Exception:
            for log in Path(directory).glob("*.log"):
                print(log.name, log.read_text()[-4000:])
            raise
