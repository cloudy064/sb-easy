#!/usr/bin/env python3
"""Replace the established sb-easy bridge-network panel, retaining data/container rollback.

Run on the central Docker host after loading and validating the candidate image.
This deliberately checks the known deployment topology before stopping anything.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import urllib.error
import urllib.request


def docker(*args, **kwargs):
    return subprocess.check_output(["docker", *args], text=True, **kwargs).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--root", type=Path, default=Path("/root/workspace/sb-easy"))
    parser.add_argument("--labels-from", type=Path,
                        help="restore Compose ownership from an archived container inspect")
    args = parser.parse_args()
    os.umask(0o077)
    name = "sb-easy"
    old = json.loads(docker("inspect", name))[0]
    image = json.loads(docker("image", "inspect", args.image))[0]
    host = old["HostConfig"]
    assert host["NetworkMode"] == "sb-easy_default", "review the network topology before cutover"
    assert len(old["Mounts"]) == 1 and old["Mounts"][0]["Destination"] == "/app/data"
    data = Path(old["Mounts"][0]["Source"])
    assert data == args.root / "data" and old["Mounts"][0]["Type"] == "bind"
    assert not host["Privileged"] and not host.get("Devices")
    assert not host.get("SecurityOpt") and not host.get("Sysctls")
    assert not host.get("ReadonlyRootfs") and not host.get("Dns") and not host.get("ExtraHosts")
    assert old["Config"]["Cmd"] == ["sb-easy"] and old["Config"]["Entrypoint"] == ["/docker-entrypoint.sh"]
    env = dict(value.split("=", 1) for value in old["Config"]["Env"] if "=" in value)
    label_source = json.loads(args.labels_from.read_text()) if args.labels_from else old
    labels = dict(label_source["Config"].get("Labels") or {})
    if "com.docker.compose.project" in labels:
        compose = json.loads(docker("compose", "--project-directory", str(args.root), "config", "--format", "json"))
        service = compose["services"]["sb-easy"]
        assert service["image"] == args.image, "update the Compose image before cutover"
        assert all(str(value) == env.get(key) for key, value in service["environment"].items()), "Compose env drift"
        labels["com.docker.compose.config-hash"] = docker("compose", "--project-directory", str(args.root),
                                                         "config", "--hash", "sb-easy").split()[-1]
        labels["com.docker.compose.image"] = image["Id"]
        labels.pop("com.docker.compose.replace", None)
    assert env.get("SINGBOX_MANAGED") == "false", "panel cutover does not cover a managed center proxy"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    token = ""

    def request(path, body=None):
        headers = {"Authorization": "Bearer " + token}
        raw = None
        if body is not None:
            raw = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request("http://127.0.0.1:51821" + path, data=raw, headers=headers)
        with opener.open(req, timeout=5) as response:
            return response.read()

    token = json.loads(request("/api/auth/login", {"username": "admin", "password": env["ADMIN_PASSWORD"]}))["token"]
    hosts = json.loads(request("/api/hosts"))
    configs = {item["id"]: request(f"/api/hosts/{item['id']}/config") for item in hosts}
    peers = docker("exec", name, "wg", "show", "wg0", "peers").splitlines() if env.get("WG_ENABLED") == "true" else None
    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup = args.root / "backups" / ("c-cutover-" + stamp)
    backup.mkdir(mode=0o700, parents=True)
    (backup / "container.json").write_text(json.dumps(old))
    (backup / "image.json").write_text(json.dumps(image))
    env_file = backup / "environment"
    env_file.write_text("\n".join(old["Config"]["Env"]) + "\n")
    rollback_name, failed_name = name + "-rollback-" + stamp, name + "-failed-" + stamp
    archive_ready = renamed = candidate_created = False
    started = False
    try:
        docker("update", "--restart=no", name)
        started = True
        docker("stop", "-t", "15", name)
        subprocess.run(["tar", "--numeric-owner", "-czf", str(backup / "data.tar.gz"),
                        "-C", str(args.root), "data"], check=True)
        archive_ready = True
        docker("rename", name, rollback_name)
        renamed = True
        command = ["run", "-d", "--name", name, "--restart", host["RestartPolicy"]["Name"],
                   "--network", host["NetworkMode"], "--env-file", str(env_file),
                   "-v", str(data) + ":/app/data:rw"]
        for cap in host.get("CapAdd") or []:
            command.extend(["--cap-add", cap])
        for key, value in labels.items():
            command.extend(["--label", key + "=" + value])
        for port, bindings in host["PortBindings"].items():
            for binding in bindings:
                prefix = binding["HostIp"] + ":" if binding["HostIp"] else ""
                command.extend(["-p", prefix + binding["HostPort"] + ":" + port])
        command.extend([args.image, "sb-easy"])
        candidate_created = True
        docker(*command)
        deadline = time.monotonic() + 45
        while True:
            try:
                if json.loads(request("/api/health"))["service"] == "sb-easy-c":
                    break
            except (OSError, ValueError):
                pass
            if time.monotonic() > deadline:
                raise TimeoutError("C panel did not become healthy")
            time.sleep(0.5)
        for host_id, before in configs.items():
            assert request(f"/api/hosts/{host_id}/config") == before, f"configuration changed for {host_id}"
        if peers is not None:
            assert sorted(docker("exec", name, "wg", "show", "wg0", "peers").splitlines()) == sorted(peers)
        assert json.loads(request("/api/auth/session"))["role"] == "admin"
        print(f"PASS: C panel healthy; {len(configs)} host configs unchanged; session and WireGuard peers verified")
        print("rollback container:", rollback_name)
        print("backup:", backup)
    except BaseException:
        if started:
            if renamed and candidate_created:
                subprocess.run(["docker", "update", "--restart=no", name], capture_output=True)
                subprocess.run(["docker", "stop", "-t", "5", name], capture_output=True)
                subprocess.run(["docker", "rename", name, failed_name], capture_output=True)
            if archive_ready:
                shutil.move(data, backup / "failed-data")
                subprocess.run(["tar", "-xzf", str(backup / "data.tar.gz"), "-C", str(args.root)], check=True)
            if renamed:
                docker("rename", rollback_name, name)
            docker("update", "--restart=" + host["RestartPolicy"]["Name"], name)
            docker("start", name)
            print("restored previous panel and data", flush=True)
        raise


if __name__ == "__main__":
    main()
