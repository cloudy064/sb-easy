# C implementation

The C11 control plane and Linux agent replace the C++ implementation. Vue,
Svelte, Android, the SQLite migrations and the official Go sing-box engine
are shared with the existing system. New server and agent features, fixes and
tests are maintained in `c/`. The old `cpp/` and Rust `backend/` implementations
remain as historical references only, outside primary CI and release builds.

The current service development version is **1.1.0**, read from
[`config/client-releases.json`](../config/client-releases.json). HTTP status,
agent reports and CLI version output share that identity; core identity remains
separate in the runtime manifest. This source version has not been published.

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
| `sb-easy-c-server` | Central HTTP service, preserving the established CLI and environment |
| `sb-easy-c-agent` | Polling agent, enrollment, local Svelte UI and `--once` |
| `sb-easy-c-render` | JSON configuration renderer |
| `sb-easy` | Agent entry point for the unified image |

The root Dockerfile installs the server as `sb-easy`, agent as `sb-easy-agent`
and renderer as `sb-easy-c-render`; its existing entrypoint supports
`sb-easy agent`. Build with `docker build -t sb-easy:c-candidate .`.
Both server and agent in this image embed the engine. The bundled upstream
`sing-box` CLI is retained for diagnostics and configuration checks.
Runtime and client version inventories are installed under `/usr/share/sb-easy/`.

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

The default Dockerfile provides two isolated verification targets:

```sh
docker build --target singbox-bridge-tests .
docker build --target backend-tests .
```

The first runs the Go bridge race tests with actual SS2022 TCP/UDP traffic.
The second runs the C suite and the server/two-agent quota, revocation, restart
and offline-expiry scenarios using the pinned upstream CLI as a client. Neither
target needs host network privileges, a TUN device or production data.

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
  and local selector operations also retain full tag bytes. Subscription names
  and URLs preserve their bytes in storage and backup; fetching encodes complete
  paths/queries and preserves relative redirect bases. A NUL in the URL authority
  returns Bad server address instead of handing a truncated origin to libcurl.
  Diagnostic metadata/logs, command acknowledgement results and WireGuard notes
  retain complete bytes through storage; diagnostic limits still truncate at
  UTF-8 boundaries. Host profile references and connection fields retain full
  bytes in storage; Clash controller/secret values also retain them in generated
  JSON. Invalid profile references cannot alias an existing prefix. Other model strings still use C
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
It also migrates the stopped engine's rule cache to `agent-data/sing-box-cache`
and mounts it at `/var/lib/sing-box`, so replacing the container retains cached
rule sets. Later data backups include this directory.
Historical deployments used `DOCKERFILE=cpp/Dockerfile.unified`; this archived
implementation does not receive current fixes. Use a previously validated C
image for rollback during new deployments.

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

For historical migration comparisons only, the following optional tool compares
a private database snapshot against an archived C++ binary (reports hashes, not
proxy credentials). This is not a current CI or release requirement:

```sh
python3 c/tools/verify_database.py --database /private/snapshot.db \
  --c-server build/c/sb-easy-c-server --cpp-server build/cpp/sb-easy-cpp-server \
  --check-claude-route
```

## Packet capture uploads

Migration `012_packet_captures.sql` adds per-host, content-addressed PCAP blobs.
Android 1.3.0 introduced opt-in capture using its existing agent token.
The published Android 1.3.4 disables capture and uploads, including saved capture
preferences. The 1.4.0 source restores explicit opt-in capture and an optional
isolated HTTPS-debugging plugin, pending device acceptance and release. The
server API and stored captures remain available; Windows capture is provided
by an optional extension. See [Android release notes](../android/README.md).

- `POST /api/agent/captures/{sha256}`: raw `application/vnd.tcpdump.pcap` body.
  The authenticated device determines the owner. Accepts little-endian PCAP 2.4,
  raw IP link type 101, snaplen 65535, complete records, at most 768 KiB.
  A wrong hash or malformed PCAP returns 400. Retrying the same file is idempotent.
- `GET /api/hosts/{id}/captures`: admin-only list of digest, size and upload time.
- `GET /api/hosts/{id}/captures/{sha256}`: admin-only PCAP attachment, `no-store`.
- `DELETE /api/hosts/{id}/captures/{sha256}`: admin-only deletion.

The per-host bound is 128 MiB or 1000 files. A full store returns 409; clients keep
pending files. Existing captures are never evicted automatically. Deleting a host
cascades to its captures. The normal SQLite backup includes captures; deleting rows
allows SQLite to reuse space rather than immediately shrinking the database file.
The frontend device detail page includes listing, download and explicit deletion.

Validation: `http_hosts_test packet_capture` exercises binary round trips, retries,
malformed uploads, agent/admin/viewer authorization, isolation and deletion.

### Background subscription refresh

Enabled subscriptions now refresh automatically while the panel is running, even
when the browser is closed. `SUBSCRIPTION_AUTO_REFRESH=false` disables the worker
for deployments that intentionally schedule refreshes externally. The interval
is in seconds, with a minimum effective interval of 60 seconds. Failed attempts
retry with exponential backoff from 60 seconds to one hour and retain the previous
nodes, successful result and usage metadata.

The subscription UI supports editing and pausing sources, next-attempt status,
`Subscription-Userinfo` usage/expiry, and import compatibility details. Missing or
invalid provider metadata is shown as unknown. Supported input formats are Clash
YAML, sing-box JSON, and plain/base64 URI lists; incompatible entries are reported
without echoing source credentials. The new subscription-report parser also
supports HTTP/HTTPS and SOCKS proxy URLs. SOCKS outbounds are supported by node
storage and config rendering. TLS references to local files are rejected for
subscription imports.

Refresh preserves user renames and disabled nodes. Identical endpoints from
separate subscriptions remain separate, with distinct display tags when names
collide. Source changes during a download invalidate that response; node writes
and success metadata commit in one database transaction. Backup/restore includes
provider names, usage and scheduling state. The new migration is
`013_subscription_refresh.sql`.

## wg-easy v14 migration

The Settings page accepts the `wg0.json` format from wg-easy v14. The source
format is documented by the [upstream migration guide](https://wg-easy.github.io/wg-easy/latest/advanced/migrate/from-14-to-15/)
and [v14 implementation](https://github.com/wg-easy/wg-easy/blob/v14/src/lib/WireGuard.js).
v15 SQLite backups are not accepted.

Use `POST /api/system/migrate/wg-easy` as an administrator with
`{ "action": "preview", "format": "wg-easy-v14", "configuration": { ... }, "options": { "dns": "1.1.1.1", "allowed_ips": "0.0.0.0/0, ::/0", "persistent_keepalive": 25 } }`.
The preview checks server/client key pairs, unique keys and addresses, the v14
`/24` subnet, existing data conflicts, and returns a secret-free report plus
`preview_digest`. Submit the same input with `action: "apply"` and that digest.
Any input or WireGuard configuration change invalidates the preview. Existing
matching peers are retained, including their local edits; conflicting rows
are never overwritten. Public-key-only clients retain their existing client
configuration and cannot download a newly generated private-key configuration.

Applying and rolling back require restarting the panel with `WG_ENABLED=false`.
After import, check the public endpoint, client DNS, listen port, and firewall,
then restart with `WG_ENABLED=true`. The importer preserves the server key and
addresses; the backup does not contain all wg-easy environment settings.
`GET` on the same endpoint lists recent imports without private snapshots.
`POST { "action": "rollback", "migration_id": "..." }` restores the prior
server settings and removes that import's new peers only when WireGuard data
has not changed since the import. Rollback otherwise refuses to discard later
edits. Import and rollback are transactional and recorded in the audit log.
