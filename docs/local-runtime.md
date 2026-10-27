# Local agent runtime

Verified on 2026-10-26. This describes this development machine, not defaults
for every deployment. Recheck live state before acting:

```sh
python3 scripts/check-local-runtime.py
```

The active container is `sb-easy-agent`, using host networking. At verification
time its image was `sb-easy:access-agent-20261020` and it was healthy. Its
`/usr/local/bin/sb-easy` exists inside the container; the host need not have
that path. The sing-box engine runs inside the agent process.

The generated configuration is `/app/data/sing-box.gen.json` inside the
container. Its inbounds are TUN (`auto_route: true`) and mixed HTTP/SOCKS on
`0.0.0.0:7890`. No 7891 listener is configured. Local clients should use
`http://127.0.0.1:7890` or `socks5h://127.0.0.1:7890` as appropriate.

TUN routing means that omitting an explicit proxy, even with `--noproxy '*'`,
does not establish a direct Internet connection. Both test requests returned
the same IP during verification; logs showed the mixed request using the
selected Shadowsocks node, and the host route used `tun0`. Diagnose the route
and per-connection outbound, rather than comparing external IPs alone.

For an explicit HTTP proxy connectivity check (overriding `NO_PROXY`):

```sh
curl --noproxy '' --proxy http://127.0.0.1:7890 --max-time 15 \
  -o /dev/null -w '%{http_code}\n' https://www.google.com/generate_204
```

Expected response: 204. This checks that URL at that moment; Docker health
alone does not prove that every destination works.

## Builds and cleanup

Use `c/Dockerfile.unified` for current Agent builds. For deployment, use its
runtime image, which supplies runtime libraries. Exported artifacts are not
necessarily portable to arbitrary host distributions. `cpp/` is historical.

On 2026-10-26 the old `dist/agent-static`, static Agent tarball,
`dist/sb-easy-unified-glibc`, and `build/cpp{,-gcc,-clang}` outputs were moved
to a dated directory under `~/.local/share/sb-easy-archives/`. Each archive
contains a `manifest.json` with its original root and relative paths. They can
be restored to those paths if needed. The old unified binary required
`libjsoncpp.so.25`, while this host has `.26`; this was unrelated to the live
container. Do not create an ABI-mismatched library symlink.

Runtime data, backups, Android/Windows releases and other build outputs were
retained. Do not recursively search generated trees to understand source code;
scope searches to `c/`, `scripts/`, `docs/`, or other relevant source directories.
Docker mount sources must be interpreted on the Docker daemon host; they may
not match the path visible to the development shell.
