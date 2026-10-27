#!/usr/bin/env python3
"""Read-only local Docker Agent inspection; never print credentials."""

import json
import subprocess
import sys


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          timeout=15).stdout


def main():
    name = sys.argv[1] if len(sys.argv) > 1 else "sb-easy-agent"
    info = json.loads(run("docker", "inspect", name))[0]
    state = info["State"]
    print(f"Container: {info['Name'].lstrip('/')}")
    print(f"Image: {info['Config']['Image']}")
    print(f"State: {state['Status']}; health: "
          f"{state.get('Health', {}).get('Status', 'not configured')}")
    print(f"Network: {info['HostConfig']['NetworkMode']}")
    if not state.get("Running"):
        return 1

    # These paths belong to the container, not the development host.
    run("docker", "exec", name, "test", "-x", "/usr/local/bin/sb-easy")
    print("Executable exists inside container: /usr/local/bin/sb-easy")
    env = dict(item.split("=", 1) for item in info["Config"].get("Env", [])
               if "=" in item)
    path = (env.get("SINGBOX_CONFIG_PATH") or
            env.get("SELF_SINGBOX_CONFIG_PATH") or "data/sing-box.gen.json")
    config = json.loads(run("docker", "exec", name, "cat", "--", path))
    print(f"Container configuration: {path}")
    fields = ("type", "tag", "listen", "listen_port", "interface_name", "auto_route")
    for inbound in config.get("inbounds", []):
        print("Inbound: " + json.dumps({k: inbound[k] for k in fields if k in inbound},
                                       ensure_ascii=False))
    print("Configured inbounds are not proof of listening sockets; host listeners:")
    sockets = run("ss", "-H", "-lnt")
    ports = {str(i["listen_port"]) for i in config.get("inbounds", [])
             if "listen_port" in i}
    for line in sockets.splitlines():
        columns = line.split()
        if len(columns) >= 4 and columns[3].rsplit(":", 1)[-1] in ports:
            print(line)
    print("Host route to 1.1.1.1:")
    print(run("ip", "route", "get", "1.1.1.1").strip())
    print("TUN may proxy requests even with --noproxy '*'. "
          "Equal external IPs alone do not indicate failure.")
    print("This is a state inspection, not an end-to-end connectivity test.")
    return 1 if state.get("Health", {}).get("Status") == "unhealthy" else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (subprocess.SubprocessError, OSError, ValueError, KeyError) as exc:
        # Avoid including subprocess output or config contents in error messages.
        print(f"Runtime inspection failed ({type(exc).__name__}); check Docker "
              "access, container state, configuration path and host tools.", file=sys.stderr)
        sys.exit(1)
