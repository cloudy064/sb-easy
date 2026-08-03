# sb-easy C++ rewrite

This directory is the incremental C++20 replacement for the Rust backend and
agent. The Vue frontend, SQLite database format, HTTP API contract, and sing-box
configuration format stay compatible during the migration.

The current foundation contains:

- a framework-independent sing-box configuration renderer;
- managed/full profile behavior compatible with the Rust renderer;
- a constrained QuickJS-NG `buildRules(context)` execution engine;
- a Profile UI for enabling/editing QuickJS, running unsaved scripts on the
  bounded server engine, and previewing generated rules before save;
- a SQLite migration runner compatible with the existing SQLx metadata and
  checksums, plus a profile/host repository;
- a Drogon HTTP server for host/profile CRUD, outbound assignment, token
  rotation, and per-host config preview;
- bearer-authenticated Agent APIs with stable ETags, heartbeats, command
  acknowledgement, latency reports, and bounded telemetry snapshots;
- a C++ polling agent with validated, durable atomic config replacement and
  shell-free reload/restart command execution;
- proxy CRUD and sing-box outbound import, including URI/base64/Clash YAML
  subscription parsing with fingerprint reconciliation;
- subscription CRUD and bounded HTTP(S) fetches on an isolated event loop;
- Clash API HTTP control for proxies, groups, rules, connections, and version,
  with local/per-host target resolution and bearer secrets;
- local and remote-agent proxy latency tests, plus agent-side connection and
  traffic telemetry sampling;
- Argon2id/HS256 administrator sessions, viewer read-only RBAC, user management,
  and mutation audit logging compatible with the existing database;
- settings and rendered sing-box config download APIs;
- WireGuard X25519 key generation, peer/managed-host provisioning, client and
  hub/mesh config generation, live stats/sync, quotas, expiry, and SVG QR codes;
- JSON backup/restore plus bounded panel log and system status APIs;
- an opt-in local sing-box supervisor with pre-install validation, atomic
  config replacement, SIGHUP reload, crash recovery, and graceful shutdown;
- a CLI renderer for parity fixtures and migration testing;
- focused tests for rendering, scripting limits, migrations, persistence, and
  live HTTP contracts.

Drogon remains confined to transport adapters; configuration and database code
do not depend on framework types.

## Build

```sh
cmake -S cpp -B build/cpp -DCMAKE_BUILD_TYPE=Release
cmake --build build/cpp \
  --target sb-easy-cpp sb-easy-cpp-server sb-easy-cpp-agent \
           sb-easy-core-tests sb-easy-http-tests sb-easy-agent-tests \
           sb-easy-agent-ui-tests -j
ctest --test-dir build/cpp --output-on-failure
```

Dependencies are pinned and fetched by CMake:

- QuickJS-NG `v0.15.1`;
- Argon2 reference implementation `20190702`;
- Drogon `v1.9.13`;
- JSON for Modern C++ `v3.12.0`.
- yaml-cpp `0.8.0`.
- Nayuki QR Code generator `v1.8.0`.

QuickJS and yaml-cpp are linked statically. The std/os libraries and module
loader are not linked into the rule engine. SQLite and OpenSSL are system build
dependencies; OpenSSL SHA-384 is used to produce the same migration checksums
as SQLx.

## Try the renderer

```sh
build/cpp/sb-easy-cpp render cpp/examples/render-request.json
```

The CLI can also migrate the shared database and render an existing host:

```sh
build/cpp/sb-easy-cpp migrate data/sb-easy.db migrations
build/cpp/sb-easy-cpp render-host data/sb-easy.db self migrations
```

Start the incremental HTTP server:

```sh
export JWT_SECRET='replace-with-a-long-random-secret'
export ADMIN_PASSWORD='replace-before-first-start'
export CONFIG_HASH_SEED='persistent-deployment-seed'
export SINGBOX_API_URL='http://127.0.0.1:9090'
export SINGBOX_API_SECRET='<matching experimental.clash_api.secret>'
export SINGBOX_MANAGED=true
export SINGBOX_BIN='sing-box'
export SELF_SINGBOX_CONFIG_PATH='data/sing-box.gen.json'
export SELF_SINGBOX_INTERVAL=10
export STATIC_DIR='frontend/dist'
export CORS_ORIGINS='https://panel.example.com'
build/cpp/sb-easy-cpp-server \
  data/sb-easy.db migrations 127.0.0.1 51821 https://panel.example.com
curl http://127.0.0.1:51821/api/health
```

Implemented HTTP routes include:

- `/api/hosts` and `/api/hosts/{id}`;
- `/api/hosts/profiles` and `/api/hosts/profiles/{id}`;
- `/api/hosts/{id}/outbounds`;
- `/api/hosts/{id}/config`;
- `/api/hosts/{id}/commands` and `/api/hosts/{id}/telemetry`;
- token reveal and rotation routes used by the existing frontend.
- `/api/proxy/nodes`, node detail CRUD, and outbound import;
- `/api/subscriptions`, subscription detail CRUD, fetch, and fetch-all;
- `/api/sing-box/proxies`, group delay, rules, connections, and version
  forwarding, with optional `?host=<id>`;
- `/api/proxy/nodes/{id}/test-latency` and `/api/proxy/nodes/test-all`;
- `/api/auth/login`, `/api/auth/session`, `/api/users`, and `/api/users/audit`;
- `/api/settings` and `/api/config/sing-box/*`;
- `/api/settings/backup`, `/api/settings/restore`, and `/api/system/logs`;
- `/api/wireguard/peers`, peer config/QR/toggle/one-time-link routes, stats,
  and sync;
- bearer-authenticated `/api/agent/config`, status, commands, latency, and
  telemetry routes.

Subscription fetches accept HTTP(S), verify HTTPS certificates, follow at most
five redirects, and cap response bodies at 8 MiB. Supported inputs are plain or
base64 URI lists and Clash YAML. Supported proxy types are Shadowsocks, VMess,
VLESS, Trojan, Hysteria2, and TUIC. Existing nodes are reconciled by fingerprint
first and tag second, matching the Rust behavior for providers that rotate
server addresses.

Administrative routes require a JWT signed by `JWT_SECRET`; viewer accounts are
read-only and successful mutations are written to `audit_log`. Agent routes use
their separate non-empty per-host bearer tokens. `AGENT_TOKEN` remains an
optional legacy token for the `self` host.

Run the C++ polling agent on a managed host:

```sh
export SB_EASY_SERVER='https://panel.example.com'
export AGENT_ENROLLMENT_CODE='<single-use code from Devices → Add device>'
export SINGBOX_CONFIG_PATH='/etc/sing-box/config.d/90-generated.json'
export SINGBOX_BIN='sing-box'
export SINGBOX_MANAGED=true
export AGENT_UI_PASSWORD='<independent strong local password>'
build/cpp/sb-easy-cpp-agent
```

On first use the agent redeems the same `/api/devices/enroll` authorization used
by the Android app, then stores its per-device bearer credential beside the
generated config with mode `0600`. Existing `SB_EASY_SERVER` + `AGENT_TOKEN`
deployments remain supported for compatibility. Set `AGENT_CREDENTIAL_PATH` to
move the persisted credential.

The agent supervises `sing-box run -c <config>` by default, validates and
atomically installs new configs, reloads the child with SIGHUP, restarts it for
panel commands, and respawns it after unexpected exits. Set
`SINGBOX_MANAGED=false` plus `RELOAD_CMD`/`RESTART_CMD` only when an external
service manager owns sing-box; those commands are parsed into argument vectors
and executed directly without a shell.

With a non-empty `AGENT_UI_PASSWORD`, the Agent also starts a lightweight local
management page on `0.0.0.0:51822`. Its standalone login page uses
`AGENT_UI_USERNAME=admin` by default and creates a 12-hour HttpOnly,
SameSite=Strict session cookie. `AGENT_UI_BIND` changes the listener, and
`AGENT_UI_ENABLED=false` disables it explicitly. The authenticated page
provides live Clash API traffic and connection metrics, a searchable current
config/proxy summary, durable node-local outbound settings, and queued
refresh/reload/restart actions. The runtime configuration separates overview,
network/DNS, routing, QuickJS, outbounds/endpoints, and complete JSON into tabs.
The QuickJS tab remains visible when the assigned Profile has scripting disabled
and links to the central Profile editor; when enabled it identifies the final
generated rules shown by the Agent. The routing tab includes a live URL test: the
Agent opens a short-lived CONNECT tunnel through its current mixed/http inbound
and correlates the source port with Clash API connections to report the actual
rule, selector chain, and final proxy/direct outbound. Settings default to
`agent-ui-settings.json` next to the generated sing-box config and can be moved
with `AGENT_UI_SETTINGS_PATH`. The Agent token is never returned by the UI.
Because the listener is plain HTTP on every interface, restrict port 51822 to a
trusted LAN/VPN or terminate TLS in a reverse proxy.

Node-local compatibility settings match the Rust agent:
`SINGBOX_LOCAL_PROXY_EGRESS`, `SINGBOX_OUTBOUND_SERVER_OVERRIDES`,
`SINGBOX_OUTBOUND_OVERRIDE_FILE`, and `SINGBOX_DEFAULT_PROXY_OUTBOUND`. The
agent also reads `experimental.clash_api` from the installed config, handles
`test-proxies` commands, reports each delay progressively, and samples
connection/traffic telemetry on every poll. Use `--once` for provisioning
checks.
`SINGBOX_VALIDATE_CONFIG=false` is available for isolated development
environments without a sing-box binary.

The authenticated Clash WebSocket bridge exposes the Rust-compatible
`/api/sing-box/ws/{traffic,logs,connections,memory}` routes. Browser handshakes
use the session JWT in the `token` query parameter; after verification, the
bridge resolves the selected `host` and uses only that target's Clash secret for
the upstream connection. The optional `level` query parameter is forwarded to
the log stream.

With `WG_ENABLED=true`, server startup creates or synchronizes the configured
WireGuard interface, persists the server keypair in `app_settings`, and installs
fixed forwarding/masquerade rules using argument-vector process execution.
`WG_INTERFACE`, `WG_PORT`, `WG_ADDRESS`, `WG_DNS`, `WG_MTU`, `WG_EGRESS`, and
`EXTERNAL_HOSTNAME` provide runtime defaults; settings saved by the UI take
priority. Shutdown removes the interface and the rules it owns.

`STATIC_DIR` points at the Vue production build. The server gives immutable
cache headers to `/assets/*`, returns `index.html` for client-side routes, and
keeps unknown `/api/*` and `/downloads/*` routes as JSON 404 responses. Android
artifacts are published through GitHub Releases instead of the management
server. `CORS_ORIGINS` accepts a
comma-separated exact-origin allowlist; empty or `*` is intended for local
development only.

After building both implementations, run the cross-backend shadow check:

```sh
scripts/check-cpp-parity.sh
```

It seeds the Rust server through its public API, stops it, opens the exact same
temporary SQLite database with the C++ server, and compares the normalized
per-host sing-box configuration. Binary paths and ports can be overridden with
`SB_EASY_RUST_BIN`, `SB_EASY_CPP_BIN`, `SB_EASY_RUST_PARITY_PORT`, and
`SB_EASY_CPP_PARITY_PORT`.

The core/database test image can be built independently:

```sh
docker build -f cpp/Dockerfile -t sb-easy-cpp-core .
docker run --rm sb-easy-cpp-core
```

This image is the isolated C++ test image; the repository root image is the
production cutover artifact.

The script contract is deliberately narrow:

```js
function buildRules(context) {
  return [
    {
      domain_suffix: [".example.com"],
      outbound: context.outboundTags.includes("hk") ? "hk" : "direct"
    }
  ];
}
```

Available context:

- `host`: non-secret host metadata supplied by the renderer;
- `outboundTags`: usable generated, built-in, and external route tags;
- `currentRules`: rules from the profile before script execution.

The Profiles editor exposes this contract without requiring direct API calls.
`POST /api/hosts/rule-script/test` executes unsaved source with preview context.
Agent config responses include `X-SB-Easy-Rule-Source`, allowing the local Agent
console to distinguish static Profile rules from the final QuickJS-generated
rules it displays.

Each execution gets a fresh runtime with memory, stack, source, output, and time
limits. `Date` and `Math.random` are disabled to keep generated configs and ETags
deterministic.
