#!/usr/bin/env python3
"""Real panel + two polling agents, isolated from the host's proxy and database."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def wait_for(check, processes, seconds=25):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        for process in processes:
            if process.poll() is not None:
                raise AssertionError(f"process exited with {process.returncode}")
        try:
            if check():
                return
        except (OSError, ValueError):
            pass
        time.sleep(0.1)
    raise AssertionError("timed out waiting for control-plane convergence")


def run(args, root):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    token = None

    def request(path, body=None, method=None, headers=None, authenticated=True):
        h = dict(headers or {})
        if authenticated and token:
            h["Authorization"] = "Bearer " + token
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        req = urllib.request.Request(base + path, data=data, headers=h, method=method)
        try:
            response = opener.open(req, timeout=3)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read()
            return response.status, dict(response.headers), json.loads(raw) if raw else None

    def api(path, body=None, method=None):
        status, _, data = request(path, body, method)
        assert status == 200, (path, status, data)
        return data

    env = {key: os.environ[key] for key in ("PATH", "ASAN_OPTIONS", "UBSAN_OPTIONS") if key in os.environ}
    env.update(HOME=str(root), BIND_ADDR=f"127.0.0.1:{port}",
               DATABASE_URL="sqlite:" + str(root / "panel.db"),
               MIGRATIONS_DIR=str(args.repo / "migrations"),
               JWT_SECRET="isolated-e2e-secret", ADMIN_PASSWORD="isolated-e2e-password",
               WG_ENABLED="false", SINGBOX_MANAGED="false", STATIC_DIR=str(root / "static"),
               PUBLIC_SERVER=base, LOG_LEVEL="warn")
    processes, logs = [], []

    def start(binary, process_env, name):
        log = open(root / (name + ".log"), "w+")
        logs.append(log)
        process = subprocess.Popen([str(binary)], env=process_env, cwd=root,
                                   stdout=log, stderr=subprocess.STDOUT)
        processes.append(process)
        return process

    def profile(outbound):
        return {"name": "Shared Claude route", "template": {
            "log": {"level": "error"}, "inbounds": [],
            "experimental": {"clash_api": {"external_controller": "127.0.0.1:1"}},
            "outbounds": [{"type": "direct", "tag": "direct"}] + [
                {"type": "shadowsocks", "tag": tag, "server": "proxy.invalid",
                 "server_port": 443, "method": "aes-128-gcm", "password": "test-password"}
                for tag in ("jp-fixed-a", "jp-fixed-b")],
            "route": {"final": "direct", "rules": [
                {"domain_suffix": ["anthropic.com", "claude.ai", "anyrouter.top"], "outbound": outbound}]}},
            "mode": "full"}

    try:
        start(args.server, env, "panel")
        wait_for(lambda: request("/api/health")[0] == 200, processes)
        token = api("/api/auth/login", {"password": "isolated-e2e-password"})["token"]
        # Exercise the same byte-string identity contract against C and C++.
        for username in ("admin\0other", "\0", " \0 "):
            credentials = {"username": username, "password": "distinct\0password", "role": "admin"}
            created = api("/api/users", credentials)
            assert created["username"] == username
            assert request("/api/users", credentials)[0] == 409
            login = api("/api/auth/login", credentials)
            assert login["username"] == username
            identity_headers = {"Authorization": "Bearer " + login["token"]}
            status, _, session = request("/api/auth/session", headers=identity_headers, authenticated=False)
            assert status == 200 and session["username"] == username
            status, _, _ = request("/api/settings", {"general": {"app_name": "identity test"}}, "PUT",
                                   headers=identity_headers, authenticated=False)
            assert status == 200
            assert any(entry["actor"] == username for entry in api("/api/users/audit"))
            assert any(user["username"] == username for user in api("/api/users"))
            wrong = {"username": username.split("\0", 1)[0], "password": credentials["password"]}
            assert request("/api/auth/login", wrong, authenticated=False)[0] == 401
            api("/api/users/" + created["id"], method="DELETE")
        print("PASS: NUL usernames and passwords preserve distinct identities, sessions and audit actors")
        script = "function buildRules() { return [{domain_suffix:['left\0right'],outbound:'direct'}]; }"
        preview = api("/api/hosts/rule-script/test", {"rule_script": script})
        assert preview["rules"][0]["domain_suffix"] == ["left\0right"]
        body = {"name": "profile\0tail", "mode": "full", "template": {
                    "outbounds": [{"type": "direct", "tag": "direct"}], "route": {}},
                "rule_script": script, "rule_script_enabled": False}
        prof = api("/api/hosts/profiles", body)
        assert prof["name"] == body["name"] and prof["rule_script"] == script
        listed = next(p for p in api("/api/hosts/profiles") if p["id"] == prof["id"])
        assert listed["name"] == body["name"] and listed["rule_script"] == script
        # Updating unrelated profile fields must retain all stored script bytes.
        body.pop("rule_script")
        body["rule_script_enabled"] = True
        body["name"] = "\0renamed"
        prof = api("/api/hosts/profiles/" + prof["id"], body, "PUT")
        assert prof["name"] == body["name"] and prof["rule_script"] == script
        host = api("/api/hosts", {"name": "script identity host", "profile_id": prof["id"],
                    "capabilities": {"runs_singbox": False, "is_wg_member": False}})
        enrollment = api("/api/devices/" + host["id"] + "/enrollment-codes", method="POST")
        redeemed = api("/api/devices/enroll", {"code": enrollment["code"], "device": {}})
        assert redeemed["profile"]["name"] == body["name"]
        config = api("/api/hosts/" + host["id"] + "/config")
        assert any(rule.get("domain_suffix") == ["left\0right"] for rule in config["route"]["rules"])
        api("/api/hosts/" + host["id"], method="DELETE")
        api("/api/hosts/profiles/" + prof["id"], method="DELETE")
        print("PASS: profile name and script bytes survive create, update, list, preview and rendering")
        shared = api("/api/hosts/profiles", profile("jp-fixed-a"))
        agents = []
        for n in range(2):
            with socket.socket() as controller:
                controller.bind(("127.0.0.1", 0))
                controller_port = controller.getsockname()[1]
            host = api("/api/hosts", {"name": f"e2e-agent-{n}", "profile_id": shared["id"],
                       "clash_api": f"http://127.0.0.1:{controller_port}", "clash_secret": "isolated-controller",
                       "capabilities": {"runs_singbox": True, "is_wg_member": False,
                                        "is_wg_hub": False, "is_self": False}})
            enrollment = api(f'/api/devices/{host["id"]}/enrollment-codes', method="POST")
            directory = root / f"agent-{n}"
            directory.mkdir()
            config = directory / "sing-box.json"
            agent_env = {key: env[key] for key in ("PATH", "HOME", "ASAN_OPTIONS", "UBSAN_OPTIONS") if key in env}
            agent_env.update(SB_EASY_SERVER=base, AGENT_ENROLLMENT_CODE=enrollment["code"],
                             SINGBOX_CONFIG_PATH=str(config), AGENT_UI_ENABLED="false",
                             SINGBOX_MANAGED="true" if args.managed else "false",
                             SINGBOX_VALIDATE_CONFIG="true" if args.managed else "false",
                             RELOAD_CMD="/bin/true", RESTART_CMD="/bin/true", AGENT_INTERVAL="1")
            start(args.agent, agent_env, f"agent-{n}")
            agents.append((host["id"], config))

        def converged(tag):
            for _, config in agents:
                if not config.exists():
                    return False
                rules = json.loads(config.read_text())["route"]["rules"]
                if not any(rule.get("outbound") == tag and "anyrouter.top" in rule.get("domain_suffix", [])
                           for rule in rules):
                    return False
            return True

        wait_for(lambda: converged("jp-fixed-a"), processes)
        agent_tokens = [api(f"/api/hosts/{host_id}/token")["agent_token"] for host_id, _ in agents]

        def agent_config(agent_token, etag=None):
            headers = {"Authorization": "Bearer " + agent_token}
            if etag:
                headers["If-None-Match"] = etag
            return request("/api/agent/config", headers=headers, authenticated=False)

        initial = [agent_config(credential) for credential in agent_tokens]
        assert all(item[0] == 200 for item in initial)
        etags = [next(v for k, v in item[1].items() if k.lower() == "etag") for item in initial]
        for credential, etag in zip(agent_tokens, etags):
            assert agent_config(credential, etag)[0] == 304

        api('/api/hosts/profiles/' + shared["id"], profile("jp-fixed-b"), "PUT")
        wait_for(lambda: converged("jp-fixed-b"), processes)
        for credential, etag in zip(agent_tokens, etags):
            assert agent_config(credential, etag)[0] == 200
        print("PASS: two agents enroll, poll a shared profile, converge after one central edit; ETags invalidate")
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for log in logs:
            log.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--agent", type=Path, required=True)
    parser.add_argument("--managed", action="store_true", help="start the real embedded engine (no TUN)")
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    args.server, args.agent = args.server.resolve(), args.agent.resolve()
    with tempfile.TemporaryDirectory(prefix="sb-c-control-plane-") as directory:
        try:
            run(args, Path(directory))
        except Exception:
            for log in Path(directory).glob("*.log"):
                print(log.name, log.read_text()[-5000:])
            raise
