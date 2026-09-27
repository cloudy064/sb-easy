# C implementation

The C11 control plane and Linux agent replace the C++ implementation. Vue,
Svelte, Android, the SQLite migrations and the official Go sing-box engine
are shared with the existing system. The previous implementation remains in
`cpp/` as a reference and rollback source.

## Build and verify

On Debian/Ubuntu install `cmake gcc git pkg-config python3 libcurl4-openssl-dev
libyaml-dev libsqlite3-dev libssl-dev`. CMake 3.24 or newer is required.

```sh
cmake -S c -B build/c -DCMAKE_BUILD_TYPE=Release -DSB_EASY_WARNINGS_AS_ERRORS=ON
cmake --build build/c --parallel 4
ctest --test-dir build/c --output-on-failure --timeout 180 --parallel 4
```

Programs:

| Binary | Purpose |
| --- | --- |
| `sb-easy-c-server` | Central HTTP service, same arguments and environment as C++ |
| `sb-easy-c-agent` | Polling agent, enrollment, local Svelte UI and `--once` |
| `sb-easy-c-render` | JSON configuration renderer |
| `sb-easy` | Agent entry point for the unified image |

The root Dockerfile installs the server as `sb-easy`, agent as `sb-easy-agent`
and renderer as `sb-easy-c-render`; its existing entrypoint supports
`sb-easy agent`. Build with `docker build -t sb-easy:c-candidate .`.

The control-plane integration test launches a real server and two real agents
on temporary storage and a loopback port. It verifies enrollment, profile
updates reaching both agents and conditional ETag requests. It runs without
WireGuard, TUN or a live proxy; reload is `/bin/true`.

For memory and undefined-behavior checks:

```sh
cmake -S c -B build/c-asan -DCMAKE_BUILD_TYPE=Debug \
  '-DCMAKE_C_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie' \
  -DCMAKE_EXE_LINKER_FLAGS=-no-pie
cmake --build build/c-asan --parallel 4
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
  ctest --test-dir build/c-asan --output-on-failure --timeout 180 --parallel 4
```

## Embedded engine

```sh
docker build -f c/Dockerfile.unified --target runtime -t sb-easy:c-unified .
docker build -f c/Dockerfile.unified --target artifacts \
  --output type=local,dest=dist/sb-easy-c-unified .
```

This builds the pinned sing-box Go C archive, links it into the C agent, and
executes a start/reload/stop smoke test during the image build. The runtime
does not require Go, a C compiler or a separate sing-box executable. The
Svelte UI remains replaceable on disk.

For a native embedded build use `SB_EASY_EMBED_SINGBOX=ON`,
`SB_EASY_SINGBOX_BRIDGE_LIBRARY` and `SB_EASY_SINGBOX_BRIDGE_INCLUDE_DIR`.
The standalone subprocess-supervisor test is replaced with an embedded smoke
test in this configuration.

## Compatibility decisions

- API routing is case-insensitive, so authentication also covers case variants
  of protected API paths. This closes the C++ case-sensitive authentication
  bypass. A noncanonical WebSocket upgrade can return 401 rather than 404.
- Service/renderer version strings identify the C implementation. Agent
  registration and HTTP user-agent strings retain their existing values.
- JSON syntax errors keep the existing response shape and status; detailed
  parser wording can differ from nlohmann. Invalid UTF-8 in server JSON
  responses is rejected with the existing type-error response.
- Passwords, usernames, JWT username claims and audit actors preserve explicit
  byte lengths, including embedded NUL bytes. Agent UI credentials are matched
  against the full JSON strings. Profile names and rule scripts also preserve
  byte lengths through storage, rendering and enrollment. Host and WireGuard
  peer names preserve their bytes through matching, credentials, configuration
  bodies, file writes and download headers. Proxy tags and server strings preserve
  their bytes in CRUD/import/backup, fingerprints and rendered configurations,
  including duplicate tags and QuickJS outbound validation. Agent proxy tests
  and local selector operations also retain full tag bytes. Other model strings still use C
  strings; their NUL compatibility requires further audit before claiming byte-exact
  parity for arbitrary inputs.
- The agent does not serve arbitrary working-directory files on unmatched UI
  requests. It serves only its configured UI directory.

## Rollout

Build and test candidate images before cutover. Keep the current image and
container available, and back up the SQLite database and agent data. Compare
rendered configurations using a database copy before switching the panel.
`scripts/deploy-unified-agent.sh` builds the C unified image, retains the old
agent container and automatically restores it if the health/proxy checks fail.
Use `DOCKERFILE=cpp/Dockerfile.unified` to build the previous implementation.

For the established central bridge-network deployment, load the tested panel
image, update the effective Compose image, then run on the central host:

```sh
python3 c/tools/deploy_center.py --image sb-easy:c-panel-candidate
```

The helper checks the existing topology, saves private container/environment
and stopped-data backups, preserves Compose labels, verifies host configs,
admin session and WireGuard peers, and restores the previous container/data
if verification fails. Its topology checks intentionally require review for
other deployment layouts.

See `PROGRESS.md` for verification results and outstanding release gates.

Central Claude egress planning (credentials through environment only):

```sh
python3 c/tools/centralize_claude_route.py --server http://panel:51821
# Apply only after reviewing the plan; backup is a new private file:
python3 c/tools/centralize_claude_route.py --server http://panel:51821 \
  --apply --backup /private/claude-route-before.json
```

The plan preserves unrelated rules, validates fixed outbound availability and
checks enabled QuickJS scripts retain the rule. It covers all profiles rather
than relying on per-node edits. Offline nodes receive the change when they
reconnect. Existing conflicting local overrides need to be removed during
migration. Roll back using `--rollback /private/claude-route-before.json`.

Verify a private database snapshot (reports hashes, not proxy credentials):

```sh
python3 c/tools/verify_database.py --database /private/snapshot.db \
  --c-server build/c/sb-easy-c-server --cpp-server build/cpp/sb-easy-cpp-server \
  --check-claude-route
```
