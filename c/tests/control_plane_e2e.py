#!/usr/bin/env python3
"""Real panel + two polling agents, isolated from the host's proxy and database."""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import tempfile
import time
import threading
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
            value = json.loads(raw) if raw and "json" in response.headers.get("Content-Type", "") else raw or None
            return response.status, dict(response.headers), value

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
        # Different byte suffixes must remain distinct throughout CRUD and fingerprints.
        nodes = []
        for suffix in ("one", "two"):
            body = {"tag": "tag\0" + suffix, "node_type": "shadowsocks",
                    "server": "server\0tail", "server_port": 443,
                    "protocol_config": {"method": "aes-256-gcm", "password": "pw\0" + suffix}}
            node = api("/api/proxy/nodes", body)
            assert node["tag"] == body["tag"] and node["server"] == body["server"]
            material = body["server"] + ":443:shadowsocks:" + body["protocol_config"]["password"]
            assert node["fingerprint"] == hashlib.sha256(material.encode()).hexdigest()
            nodes.append(node)
        assert nodes[0]["fingerprint"] != nodes[1]["fingerprint"]
        renamed = api("/api/proxy/nodes/" + nodes[0]["id"], {"tag": "\0renamed"}, "PUT")
        assert renamed["tag"] == "\0renamed" and renamed["server"] == "server\0tail"
        listed = {node["id"]: node for node in api("/api/proxy/nodes")}
        assert listed[nodes[0]["id"]]["tag"] == "\0renamed"
        assert listed[nodes[1]["id"]]["tag"] == "tag\0two"
        invalid = dict(body, tag="invalid", node_type="shadowsocks\0tail")
        assert request("/api/proxy/nodes", invalid)[0] == 400
        for node in nodes:
            api("/api/proxy/nodes/" + node["id"], method="DELETE")
        print("PASS: proxy byte strings preserve CRUD, exact protocol matching and credential fingerprints")
        for name, url, expected_name in (
                (" sub\0tail ", "https://example.invalid/sub\0tail", "sub\0tail"),
                (" \0 ", "https://example.invalid/", "\0"),
                (" ", "https://host\0tail.invalid/path", "host\0tail.invalid")):
            sub = api("/api/subscriptions", {"name": name, "url": url})
            assert sub["name"] == expected_name and sub["url"] == url
            sub = api("/api/subscriptions/" + sub["id"],
                      {"enabled": False, "name": " \0renamed ", "url": url + "\0end"}, "PUT")
            assert sub["name"] == "\0renamed" and sub["url"] == url + "\0end"
            listed = {entry["id"]: entry for entry in api("/api/subscriptions")}
            assert listed[sub["id"]]["url"] == sub["url"]
            api("/api/subscriptions/" + sub["id"], method="DELETE")

        paths = []
        class SubscriptionSource(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                paths.append(self.path)
                if self.path == "/dir%00tail/source":
                    self.send_response(302)
                    self.send_header("Location", "next?q=x")
                    self.end_headers()
                    return
                content = b"trojan://fixture-password@fixture.invalid:443#subscription-byte-test"
                self.send_response(200)
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)

        with http.server.HTTPServer(("127.0.0.1", 0), SubscriptionSource) as source:
            thread = threading.Thread(target=source.serve_forever, daemon=True)
            thread.start()
            try:
                for path in ("/sub\0tail?q=x\0y", "/dir\0tail/source"):
                    sub = api("/api/subscriptions", {"name": "source\0tail",
                        "url": f"http://127.0.0.1:{source.server_port}" + path})
                    fetched = api("/api/subscriptions/" + sub["id"] + "/fetch", {}, "POST")
                    assert fetched["found"] == 1
                    api("/api/subscriptions/" + sub["id"], method="DELETE")
            finally:
                source.shutdown()
                thread.join(timeout=5)
        assert paths == ["/sub%00tail?q=x%00y", "/dir%00tail/source", "/dir%00tail/next?q=x"], paths
        for node in api("/api/proxy/nodes"):
            if node["tag"] == "subscription-byte-test":
                api("/api/proxy/nodes/" + node["id"], method="DELETE")
        print("PASS: subscription byte strings survive CRUD, default names, fetch paths and relative redirects")
        script = "function buildRules(context) { return [{domain_suffix:['left\0right'],outbound:'direct',hostLabel:context.host.name}]; }"
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
        host = api("/api/hosts", {"name": "script\0identity host", "profile_id": prof["id"],
                    "capabilities": {"runs_singbox": False, "is_wg_member": False}})
        enrollment = api("/api/devices/" + host["id"] + "/enrollment-codes", method="POST")
        redeemed = api("/api/devices/enroll", {"code": enrollment["code"], "device": {}})
        assert redeemed["profile"]["name"] == body["name"]
        assert redeemed["host_name"] == "script\0identity host"
        host = api("/api/hosts/" + host["id"], {"name": "\0renamed host"}, "PUT")
        assert host["name"] == "\0renamed host"
        assert next(h for h in api("/api/hosts") if h["id"] == host["id"])["name"] == host["name"]
        config = api("/api/hosts/" + host["id"] + "/config")
        assert any(rule.get("domain_suffix") == ["left\0right"] and rule.get("hostLabel") == host["name"]
                   for rule in config["route"]["rules"])
        invalid_host = {"name": "invalid-profile-reference", "profile_id": "default\0suffix",
                        "capabilities": {"runs_singbox": False, "is_wg_member": False}}
        assert request("/api/hosts", invalid_host)[0] == 500
        assert not any(entry["name"] == invalid_host["name"] for entry in api("/api/hosts"))
        assert request("/api/hosts/" + host["id"], {"profile_id": "default\0suffix"}, "PUT")[0] == 500
        assert next(entry for entry in api("/api/hosts") if entry["id"] == host["id"])["profile_id"] == prof["id"]
        connection_fields = {"wg_address": "10.0.0.2/32\0tail", "wg_endpoint": "\0endpoint:51820",
                             "clash_api": "http://controller\0tail:9090///", "clash_secret": "secret\0tail"}
        reference_host = api("/api/hosts", dict(connection_fields, name="connection-field-check",
            profile_id=prof["id"], capabilities={"runs_singbox": False, "is_wg_member": False}))
        for key in ("wg_address", "wg_endpoint", "clash_api"):
            assert reference_host[key] == connection_fields[key]
        for suffix in ("tail", "updated"):
            connection_fields = {"wg_address": "10.0.0.2/32\0" + suffix,
                "wg_public_key": "public\0" + suffix, "wg_endpoint": "endpoint:51820\0" + suffix,
                "clash_api": "http://controller\0" + suffix + ":9090///", "clash_secret": "secret\0" + suffix}
            reference_host = api("/api/hosts/" + reference_host["id"], connection_fields, "PUT")
            listed = next(entry for entry in api("/api/hosts") if entry["id"] == reference_host["id"])
            for key in ("wg_address", "wg_public_key", "wg_endpoint", "clash_api"):
                assert reference_host[key] == listed[key] == connection_fields[key]
            rendered = api("/api/hosts/" + reference_host["id"] + "/config")
            assert rendered["experimental"]["clash_api"]["external_controller"] == "controller\0" + suffix + ":9090"
            assert rendered["experimental"]["clash_api"]["secret"] == connection_fields["clash_secret"]
        api("/api/hosts/" + reference_host["id"], method="DELETE")
        print("PASS: complete host profile references reject prefix aliases; connection fields survive CRUD/rendering")
        agent_headers = {"Authorization": "Bearer " + api("/api/hosts/" + host["id"] + "/token")["agent_token"]}
        diagnostic = {"reason": "r" * 78 + "\0éend", "app_version": "app\0tail",
                      "core_version": "core\0tail", "logs": ["short\0tail", "l" * 3998 + "\0éend"]}
        status, _, _ = request("/api/agent/diagnostics", diagnostic, headers=agent_headers, authenticated=False)
        assert status == 200
        reports = api("/api/hosts/" + host["id"] + "/diagnostics")
        assert reports[0]["reason"] == "r" * 78 + "\0"
        assert reports[0]["app_version"] == "app\0tail" and reports[0]["core_version"] == "core\0tail"
        assert reports[0]["logs"] == ["short\0tail", "l" * 3998 + "\0"]
        command = api("/api/hosts/" + host["id"] + "/commands", {"command": "reload"})
        status, _, _ = request("/api/agent/commands/" + command["id"] + "/ack",
                              {"status": "done\0suffix", "result": "result\0tail"},
                              headers=agent_headers, authenticated=False)
        assert status == 200
        commands = api("/api/hosts/" + host["id"] + "/commands")
        saved = next(entry for entry in commands if entry["id"] == command["id"])
        assert saved["status"] == "failed" and saved["result"] == "result\0tail"
        print("PASS: diagnostic metadata/logs and command results preserve NUL bytes and UTF-8 limits")
        # Seed only this isolated database; WG_ENABLED=false prevents interface changes.
        peer_name = "host: " + host["name"]
        with sqlite3.connect(root / "panel.db") as db:
            db.execute("insert or replace into app_settings(key,value) values ('wg_server_key',?)",
                       (json.dumps({"private_key": "test-private", "public_key": "test-public"}),))
            db.execute("insert into wireguard_peers(id,name,private_key,public_key,address,host_id) "
                       "values ('name-test',?,'test-peer-private','test-peer-public','10.59.32.44/32',?)",
                       (peer_name, host["id"]))
        updated_peer = api("/api/wireguard/peers/name-test", {"notes": "note\0tail"}, "PUT")
        assert updated_peer["notes"] == "note\0tail"
        peers = api("/api/wireguard/peers")
        assert next(peer for peer in peers if peer["id"] == "name-test")["notes"] == "note\0tail"
        for path, name, suffix in [
                ("/api/wireguard/peers/name-test/config", peer_name, ".conf"),
                ("/api/hosts/" + host["id"] + "/wg-config", host["name"], "-wg.conf")]:
            status, headers, raw = request(path)
            assert status == 200 and host["name"].encode() in raw
            assert b"PrivateKey = test-peer-private" in raw and b"PersistentKeepalive = 25" in raw
            disposition = next(v for k, v in headers.items() if k.lower() == "content-disposition")
            assert disposition == 'attachment; filename="' + name.replace(" ", "_") + suffix + '"'
        with sqlite3.connect(root / "panel.db") as db:
            db.execute("delete from wireguard_peers where id='name-test'")
        api("/api/hosts/" + host["id"], method="DELETE")
        api("/api/hosts/profiles/" + prof["id"], method="DELETE")
        print("PASS: profile name and script bytes survive create, update, list, preview and rendering")
        shared = api("/api/hosts/profiles", profile("jp-fixed-a"))
        agents = []
        for n in range(2):
            with socket.socket() as controller:
                controller.bind(("127.0.0.1", 0))
                controller_port = controller.getsockname()[1]
            host = api("/api/hosts", {"name": f"e2e-agent-{n}\0tail", "profile_id": shared["id"],
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
        for n, (host_id, config_path) in enumerate(agents):
            saved = json.loads((config_path.parent / "device-credential.json").read_text())
            assert saved["host_name"] == f"e2e-agent-{n}\0tail"
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
