#!/usr/bin/env python3
"""Real panel, two embedded agents and upstream SS2022 clients on fresh loopback ports."""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import socket
import socketserver
import sqlite3
import struct
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def receive(sock, count):
    data = b""
    while len(data) < count:
        piece = sock.recv(count - len(data))
        if not piece:
            raise EOFError("proxy connection closed")
        data += piece
    return data


def socks_connect(port, destination):
    sock = socket.create_connection(("127.0.0.1", port), timeout=2)
    try:
        sock.sendall(b"\x05\x01\x00")
        assert receive(sock, 2) == b"\x05\x00"
        sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", destination))
        reply = receive(sock, 4)
        if reply[:2] != b"\x05\x00":
            raise OSError("SOCKS destination rejected")
        address_length = {1: 4, 4: 16}.get(reply[3])
        if reply[3] == 3:
            address_length = receive(sock, 1)[0]
        assert address_length is not None
        receive(sock, address_length + 2)
        return sock
    except BaseException:
        sock.close()
        raise


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while data := self.request.recv(65536):
                self.request.sendall(data)
        except OSError:
            pass


class EchoServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    block_on_close = False


def run(args, directory):
    port, self_controller = free_port(), free_port()
    base = f"http://127.0.0.1:{port}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    token, processes, logs, sockets = None, [], [], []

    def request(path, body=None, method=None):
        headers = {"Authorization": "Bearer " + token} if token else {}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(base + path, data, headers, method=method)
        try:
            reply = opener.open(req, timeout=3)
        except urllib.error.HTTPError as error:
            reply = error
        with reply:
            value = json.loads(reply.read())
            assert reply.status == 200, (path.split("?")[0], reply.status, value)
            return value

    def query(sql, values=()):
        with sqlite3.connect(directory / "panel.db", timeout=3) as db:
            return db.execute(sql, values).fetchall()

    def start(binary, env, name, arguments=()):
        log = open(directory / (name + ".log"), "w+")
        logs.append(log)
        process = subprocess.Popen([str(binary), *arguments], cwd=directory, env=env,
                                   stdout=log, stderr=subprocess.STDOUT)
        processes.append(process)
        return process

    def stop(process):
        processes.remove(process)
        process.terminate()
        try:
            process.wait(timeout=12)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            raise AssertionError("process shutdown exceeded 12 seconds")

    def wait(check, description, seconds=25):
        deadline = time.monotonic() + seconds
        last = None
        while time.monotonic() < deadline:
            assert all(process.poll() is None for process in processes), "fixture process exited"
            try:
                if check():
                    return
            except (OSError, EOFError, ValueError) as error:
                last = type(error).__name__
            time.sleep(0.1)
        raise AssertionError(f"timed out: {description} ({last})")

    env = {key: os.environ[key] for key in ("PATH", "ASAN_OPTIONS", "UBSAN_OPTIONS") if key in os.environ}
    env.update(HOME=str(directory), BIND_ADDR=f"127.0.0.1:{port}",
               DATABASE_URL="sqlite:" + str(directory / "panel.db"),
               MIGRATIONS_DIR=str(args.repo / "migrations"),
               JWT_SECRET="isolated-proxy-e2e-secret", ADMIN_PASSWORD="isolated-proxy-e2e-password",
               WG_ENABLED="false", SINGBOX_MANAGED="false", SUBSCRIPTION_AUTO_REFRESH="false",
               STATIC_DIR=str(directory / "static"), PUBLIC_SERVER=base, LOG_LEVEL="warn",
               SELF_SINGBOX_CONFIG_PATH=str(directory / "self.json"), SELF_SINGBOX_INTERVAL="300",
               SINGBOX_API_URL=f"http://127.0.0.1:{self_controller}", SINGBOX_API_SECRET="isolated-self")
    echo = EchoServer(("127.0.0.1", 0), Echo)
    echo_thread = threading.Thread(target=echo.serve_forever, daemon=True)
    echo_thread.start()

    def client(device, host_port, name):
        subscription = request("/api/proxy-self/subscription?token=" +
                               urllib.parse.quote(device["subscription_token"], safe=""))
        outbound = next(item for item in subscription["outbounds"] if item["server_port"] == host_port)
        local = free_port()
        config = {"log": {"level": "error"},
                  "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": local}],
                  "outbounds": [outbound], "route": {"final": outbound["tag"]}}
        path = directory / (name + ".json")
        path.write_text(json.dumps(config))
        path.chmod(0o600)
        start(args.client, env, name, ("run", "-c", str(path)))
        return local

    def connect_ready(local):
        sock = socks_connect(local, echo.server_address[1])
        try:
            sock.sendall(b"ready")
            assert receive(sock, 5) == b"ready"
        except BaseException:
            sock.close()
            raise
        sockets.append(sock)
        return sock

    def new_user(name, hosts, quota=0):
        return request("/api/proxy-users", {"name": name, "enabled": True, "quota_bytes": quota,
                       "expires_at": 0, "max_devices": 4, "host_ids": hosts})

    def new_device(user, name, expiry=0):
        return request(f'/api/proxy-users/{user["id"]}/devices', {"name": name, "expires_at": expiry})

    try:
        # Bootstrap without starting a default core; every later listener is explicitly loopback.
        server = start(args.server, env, "panel-bootstrap")
        wait(lambda: request("/api/health"), "panel health")
        token = request("/api/auth/login", {"password": env["ADMIN_PASSWORD"]})["token"]
        profile = request("/api/hosts/profiles", {"name": "Isolated proxy lease core", "mode": "full",
            "template": {"log": {"level": "error"}, "inbounds": [],
                         "outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "direct"}}})
        request("/api/hosts/self", {"profile_id": profile["id"],
                "clash_api": env["SINGBOX_API_URL"], "clash_secret": env["SINGBOX_API_SECRET"]}, "PUT")
        stop(server)
        env["SINGBOX_MANAGED"] = "true"
        server = start(args.server, env, "panel")
        wait(lambda: request("/api/health"), "managed panel health")

        agents = []
        for n in range(2):
            controller = free_port()
            host = request("/api/hosts", {"name": f"isolated-proxy-{n}", "profile_id": profile["id"],
                "clash_api": f"http://127.0.0.1:{controller}", "clash_secret": "isolated-controller",
                "capabilities": {"runs_singbox": True, "is_wg_member": False, "is_wg_hub": False}})
            enrollment = request(f'/api/devices/{host["id"]}/enrollment-codes', method="POST")
            agent_directory = directory / f"agent-{n}"
            agent_directory.mkdir()
            agent_env = {key: env[key] for key in ("PATH", "HOME", "ASAN_OPTIONS", "UBSAN_OPTIONS") if key in env}
            agent_env.update(SB_EASY_SERVER=base, AGENT_ENROLLMENT_CODE=enrollment["code"],
                SINGBOX_CONFIG_PATH=str(agent_directory / "sing-box.json"), AGENT_UI_ENABLED="false",
                SINGBOX_MANAGED="true", SINGBOX_VALIDATE_CONFIG="true", AGENT_INTERVAL="300")
            process = start(args.agent, agent_env, f"agent-{n}")
            agents.append({"id": host["id"], "env": agent_env, "process": process, "port": free_port()})

        host_ids = [agent["id"] for agent in agents]
        wait(lambda: query("SELECT COUNT(*) FROM proxy_runtime_reports WHERE supported=1")[0][0] == 3,
             "all three real embedded runtimes report support")
        self_port = free_port()
        for host, ingress_port in [(agent["id"], agent["port"]) for agent in agents] + [("self", self_port)]:
            request("/api/proxy-ingress/" + host,
                    {"enabled": True, "server": "127.0.0.1", "listen": "127.0.0.1", "listen_port": ingress_port}, "PUT")

        limited = new_user("Two-node shared quota", host_ids, 8192)
        device = new_device(limited, "Shared credential")
        locals_ = [client(device, agent["port"], f"quota-client-{n}") for n, agent in enumerate(agents)]
        flows = []
        for local in locals_:
            wait(lambda: flows.append(connect_ready(local)) or True, "real SS2022 agent forwarding")
        before = query("SELECT host_id,boot_id,grant_bytes FROM proxy_leases WHERE user_id=?", (limited["id"],))
        assert len(before) == 2 and sum(row[2] for row in before) <= 8192
        barrier = threading.Barrier(2)

        def traffic(sock):
            barrier.wait(timeout=3)
            payload = bytes(range(256)) * 2
            sock.sendall(payload)
            assert receive(sock, len(payload)) == payload
            return len(payload) * 2

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            transferred = sum(executor.map(traffic, flows)) + 20
        wait(lambda: request("/api/proxy-users/" + limited["id"])["reported_bytes"] >= transferred,
             "traffic report while AGENT_INTERVAL is 300 seconds", 16)
        status = request("/api/proxy-users/" + limited["id"])
        assert transferred <= status["reported_bytes"] <= status["allocated_bytes"] <= 8192
        assert all(seq >= 3 for (seq,) in query("SELECT request_seq FROM proxy_lease_sessions WHERE host_id != 'self'"))
        print("PASS: two real SS2022 nodes share a bounded grant and report traffic on the independent 10-second worker", flush=True)

        burst_grant = status["allocated_bytes"]
        barrier = threading.Barrier(2)

        def exhaust(sock):
            barrier.wait(timeout=3)
            sock.settimeout(3)
            sock.sendall(b"quota-burst" * 4096)
            received = 0
            try:
                while piece := sock.recv(65536):
                    received += len(piece)
            except (ConnectionResetError, BrokenPipeError):
                pass
            assert received <= 8192

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            list(executor.map(exhaust, flows))
        wait(lambda: request("/api/proxy-users/" + limited["id"])["reported_bytes"] >= burst_grant,
             "both nodes report exhausted grants", 16)
        status = request("/api/proxy-users/" + limited["id"])
        assert status["reported_bytes"] <= status["allocated_bytes"] <= 8192
        print("PASS: simultaneous traffic beyond the global quota closes both exhausted flows without over-allocation", flush=True)

        # A new boot cannot reclaim any old grant, even if the old process is certainly gone.
        first = agents[0]
        old_boot = next(row[1] for row in before if row[0] == first["id"])
        old_grant = query("SELECT grant_bytes FROM proxy_leases WHERE user_id=? AND host_id=? AND boot_id=?",
                          (limited["id"], first["id"], old_boot))[0][0]
        stop(first["process"])
        first["process"] = start(args.agent, first["env"], "agent-0-restarted")
        wait(lambda: query("SELECT COUNT(*) FROM proxy_leases WHERE user_id=? AND host_id=? AND boot_id!=?",
                           (limited["id"], first["id"], old_boot))[0][0] == 1, "fresh boot obtains a separately reserved lease")
        after = query("SELECT boot_id,grant_bytes FROM proxy_leases WHERE user_id=?", (limited["id"],))
        assert len(after) == 3 and sum(row[1] for row in after) <= 8192
        assert next(row[1] for row in after if row[0] == old_boot) == old_grant
        print("PASS: agent restart changes boot identity and preserves the old boot's reserved quota", flush=True)

        # One node and two credentials isolate device expiry from user lifetime and revocation.
        survivor = agents[1]
        unrestricted = new_user("Independent device lifetime", [survivor["id"]])
        last_exchange = query("SELECT updated_at FROM proxy_lease_sessions WHERE host_id=?", (survivor["id"],))[0][0]
        expiry = max(int(time.time()) + 12, last_exchange + 15)
        temporary = new_device(unrestricted, "Expires independently", expiry)
        permanent = new_device(unrestricted, "Explicitly revoked")
        expiry_local = client(temporary, survivor["port"], "expiry-client")
        revoke_local = client(permanent, survivor["port"], "revoke-client")
        expiring, persistent = [], []
        wait(lambda: expiring.append(connect_ready(expiry_local)) or True, "expiring device establishes existing flow")
        wait(lambda: persistent.append(connect_ready(revoke_local)) or True, "persistent device establishes existing flow")
        expiry_seq = query("SELECT request_seq FROM proxy_lease_sessions WHERE host_id=?", (survivor["id"],))[0][0]

        def closed(sock):
            sock.settimeout(0.15)
            try:
                sock.sendall(b"x")
                data = sock.recv(1)
                return not data
            except socket.timeout:
                return False
            except (OSError, EOFError):
                return True

        wait(lambda: closed(expiring[0]), "engine closes existing flow at independent device expiry", 20)
        assert time.time() <= expiry + 2
        assert query("SELECT request_seq FROM proxy_lease_sessions WHERE host_id=?", (survivor["id"],))[0][0] == expiry_seq
        persistent[0].sendall(b"still-live")
        assert receive(persistent[0], 10) == b"still-live"
        request(f'/api/proxy-users/{unrestricted["id"]}/devices/{permanent["id"]}', method="DELETE")
        wait(lambda: closed(persistent[0]), "next complete policy revokes an existing device flow", 15)
        print("PASS: device expiry closes an existing flow before the next exchange; revocation closes the other flow", flush=True)

        own_user = new_user("Center self worker", ["self"])
        own_device = new_device(own_user, "Center client")
        own_local = client(own_device, self_port, "self-client")
        offline_user = new_user("Offline node deadline", [survivor["id"]])
        offline_device = new_device(offline_user, "Offline client")
        offline_local = client(offline_device, survivor["port"], "offline-client")
        own_flow = []
        offline_flow = []
        wait(lambda: own_flow.append(connect_ready(own_local)) or True, "center self-owned SS2022 listener")
        wait(lambda: offline_flow.append(connect_ready(offline_local)) or True, "remote flow before center shutdown")
        wait(lambda: request("/api/proxy-users/" + own_user["id"])["reported_bytes"] >= 10,
             "center reports traffic while SELF_SINGBOX_INTERVAL is 300 seconds", 15)
        stop(server)
        # A last exchange may commit while HTTP shutdown drains requests. Its
        # deadline is the conservative upper bound even if the reply was lost.
        offline_expiry = query("SELECT expires_at FROM proxy_leases WHERE user_id=?", (offline_user["id"],))[0][0]
        wait(lambda: closed(own_flow[0]), "center shutdown closes self-owned flow", 3)
        assert query("SELECT supported FROM proxy_runtime_reports WHERE host_id='self'")[0][0] == 0
        with socket.socket() as probe:
            probe.settimeout(1)
            assert probe.connect_ex(("127.0.0.1", self_port)) != 0
        print("PASS: center self worker renews independently and orderly shutdown closes its listener and capability", flush=True)
        offline_flow[0].sendall(b"leased")
        assert receive(offline_flow[0], 6) == b"leased"
        wait(lambda: closed(offline_flow[0]), "offline agent closes an existing flow at lease deadline", 65)
        assert time.time() <= offline_expiry + 2
        print("PASS: remote agent keeps only its current authorization while offline, then closes the existing flow at expiry", flush=True)
    except BaseException:
        print("Fixture logs:", directory, flush=True)
        for log in logs:
            log.flush()
            log.seek(0)
            print(Path(log.name).name + ":\n" + "".join(log.readlines()[-12:]), flush=True)
        raise
    finally:
        for sock in sockets:
            sock.close()
        for process in reversed(processes):
            process.terminate()
        for process in reversed(processes):
            try:
                process.wait(timeout=12)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        for log in logs:
            log.close()
        echo.shutdown()
        echo.server_close()
        echo_thread.join(timeout=3)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--agent", type=Path, required=True)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--work-dir", type=Path)
    arguments = parser.parse_args()
    for name in ("server", "agent", "client", "repo"):
        setattr(arguments, name, getattr(arguments, name).resolve())
    if arguments.work_dir:
        arguments.work_dir.mkdir(parents=True, exist_ok=False)
        run(arguments, arguments.work_dir.resolve())
    else:
        with tempfile.TemporaryDirectory(prefix="sb-easy-proxy-runtime-e2e-") as temporary_directory:
            run(arguments, Path(temporary_directory))
