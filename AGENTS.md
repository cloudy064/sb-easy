# Repository and local runtime guidance

- Active server/agent implementation: `c/`. `cpp/` is archived reference code.
- Before diagnosing this machine, read `docs/local-runtime.md` and run
  `python3 scripts/check-local-runtime.py`. The documented snapshot is not a
  substitute for checking the current container and generated configuration.
- The local agent runs in Docker (`sb-easy-agent`), with an embedded sing-box
  engine. Check executable paths inside the container. An absent host
  `/usr/local/bin/sb-easy` does not mean the running executable was deleted.
- Read configured inbounds before assuming a port should exist. The verified
  setup uses mixed HTTP/SOCKS on 7890, plus TUN; it does not require 7891.
- With TUN enabled, `curl --noproxy '*'` can still traverse the proxy. Equal
  external IPs do not prove direct routing or a failed proxy. Check routes and
  connection logs. Do not disable TUN just to diagnose this.
- `dist/`, `build/`, and `tmp/` are local outputs, not the deployed executable.
  Old C++ binaries may require Debian's `libjsoncpp.so.25`; do not symlink
  another ABI version or install libraries to repair an unused artifact.
- Preserve `agent-data/`, `data/`, backups, credentials, and running containers
  during cleanup. Do not print full environment/configuration dumps: they may
  contain tokens and node credentials. Resolve mounts through Docker inspect;
  Docker daemon paths can differ from this workspace's paths.
