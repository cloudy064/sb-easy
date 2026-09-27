#!/usr/bin/env python3
"""Compare C and C++ on independent SQLite snapshots; never open the live DB for writes."""
import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def snapshot(binary, source, root, repo, check_claude_route=False):
    root.mkdir()
    database = root / "panel.db"
    with sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True) as src:
        with sqlite3.connect(database) as dst:
            src.backup(dst)
    with sqlite3.connect(database) as db:
        user_id, username = db.execute("select id,username from users where role='admin' limit 1").fetchone()
        hosts = [r[0] for r in db.execute("select id from hosts order by id")]
    secret = "isolated-database-parity-secret"
    encode = lambda value: base64.urlsafe_b64encode(value).rstrip(b"=")
    header = encode(b'{"alg":"HS256","typ":"JWT"}')
    payload = encode(json.dumps(dict(sub=user_id, username=username, role="admin",
                                    iat=int(time.time()), exp=int(time.time()) + 300)).encode())
    unsigned = header + b"." + payload
    token = (unsigned + b"." + encode(hmac.digest(secret.encode(), unsigned, "sha256"))).decode()
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    env = dict(PATH=os.environ["PATH"], HOME=str(root), BIND_ADDR=f"127.0.0.1:{port}",
               DATABASE_URL="sqlite:" + str(database), JWT_SECRET=secret,
               MIGRATIONS_DIR=str(repo / "migrations"), WG_ENABLED="false",
               SINGBOX_MANAGED="false", SINGBOX_API_URL="http://127.0.0.1:1",
               CONFIG_HASH_SEED="parity", STATIC_DIR=str(root / "static"), LOG_LEVEL="error")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(path, credential=token):
        req = urllib.request.Request(f"http://127.0.0.1:{port}" + path,
                                     headers={"Authorization": "Bearer " + credential})
        try:
            response = opener.open(req, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, response.headers.get("ETag"), response.read()

    with open(root / "server.log", "w") as log:
        process = subprocess.Popen([str(binary)], cwd=root, env=env, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 15
            while True:
                if process.poll() is not None:
                    raise RuntimeError("server exited: " + (root / "server.log").read_text()[-1500:])
                try:
                    if request("/api/health")[0] == 200:
                        break
                except OSError:
                    pass
                if time.monotonic() > deadline:
                    raise TimeoutError("server startup")
                time.sleep(0.1)
            results = {}
            for path in ("/api/hosts/profiles", "/api/proxy/nodes", "/api/settings", "/api/users"):
                results[path] = request(path)
            for host in hosts:
                results[f"/api/hosts/{host}/config"] = request(f"/api/hosts/{host}/config")
                credential = json.loads(request(f"/api/hosts/{host}/token")[2])["agent_token"]
                results[f"agent:{host}"] = request("/api/agent/config", credential)
            if check_claude_route:
                from centralize_claude_route import API, DOMAINS, plan, apply
                api = API.__new__(API)
                api.base, api.opener, api.token = f"http://127.0.0.1:{port}", opener, token
                changes = plan(api, "🇯🇵 日本Z03 | IEPL")
                apply(api, changes, root / "route-rollback.json")
                assert not plan(api, "🇯🇵 日本Z03 | IEPL")
                for host in hosts:
                    status, _, raw = request(f"/api/hosts/{host}/config")
                    assert status == 200
                    config = json.loads(raw)
                    matching = [rule for rule in config["route"]["rules"]
                                if set(rule.get("domain_suffix", [])) == set(DOMAINS)]
                    assert len(matching) == 1
                    outbound = next(node for node in config["outbounds"] if node["tag"] == matching[0]["outbound"])
                    assert outbound["type"] not in ("selector", "urltest", "direct", "block")
                for change in reversed(changes):
                    api.call("/api/hosts/profiles/" + change["id"], change["before"], "PUT")
                assert plan(api, "🇯🇵 日本Z03 | IEPL") == changes
                print(f"PASS: fixed egress apply, all {len(hosts)} rendered host configs, and rollback ({binary.name})")
            with sqlite3.connect(database) as db:
                results["migrations"] = list(db.execute("select * from _sqlx_migrations order by version"))
                results["schema"] = list(db.execute("select name,sql from sqlite_master where sql is not null order by name"))
            return results
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--c-server", type=Path, required=True)
    parser.add_argument("--cpp-server", type=Path, required=True)
    parser.add_argument("--check-claude-route", action="store_true")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix="sb-database-parity-") as directory:
        root = Path(directory)
        old = snapshot(args.cpp_server.resolve(), args.database, root / "cpp", repo, args.check_claude_route)
        new = snapshot(args.c_server.resolve(), args.database, root / "c", repo, args.check_claude_route)
        failures = [key for key in old if old[key] != new[key]]
        for key in failures:
            # Configs contain credentials: report hashes, never raw bodies.
            print("DIFF", key, hashlib.sha256(repr(old[key]).encode()).hexdigest(),
                  hashlib.sha256(repr(new[key]).encode()).hexdigest())
        if failures:
            raise SystemExit(1)
        print(f"PASS: {len(old)} C/C++ comparisons including all host configs, ETags, migrations and schema")
