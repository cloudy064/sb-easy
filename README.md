# sb-easy

A self-hosted, single-binary control panel for **WireGuard + sing-box**, in the
spirit of wg-easy. One central server manages many hosts, their proxies, configs
and clients — and can run/supervise sing-box itself, so there's nothing extra to
install.

- **Backend**: C++20 (Drogon + SQLite + QuickJS), serving the Vue frontend.
- **Data plane**: sing-box (supervised in-process by sb-easy when managed).
- **Frontend**: Vue 3 + TS + Pinia.

## Features
- Multi-host central management: register hosts, assign proxies, edit config
  profiles (managed = panel-built, or **full** = paste a complete config).
- Profile-scoped QuickJS rule generation with an enable switch, bounded
  server-side test run, readable output preview, and Agent result provenance.
- Per-host agent token; the image runs the panel as `sb-easy` and preserves
  `sb-easy agent` as a compatibility alias for the dedicated C++ agent.
- Managed sing-box: spawn / reload-on-change / respawn-on-crash; Clash API
  exposed for live monitoring.
- WireGuard hub + clients (keys, QR, quota, expiry); optional host mesh.
- Live monitor (traffic / connections / logs over WebSocket), proxy-group
  switching, subscriptions, config drift detection, downlink commands
  (reload/restart), RBAC + audit log, dark mode, en/zh i18n.

## Quick start (Docker, recommended)

The image bundles sing-box and supervises it in process (`SINGBOX_MANAGED=true`
by default) — no separate sing-box install. Host networking is used because this
is a VPN gateway (WireGuard UDP, tun, Clash API live in the host netns).

```sh
JWT_SECRET=$(openssl rand -hex 32) \
ADMIN_PASSWORD='choose-a-strong-one' \
EXTERNAL_HOSTNAME=your.host.or.ip \
docker compose up -d --build
```

Open `http://<host>:51821` and log in as `admin`.

For the full production topology (server = panel + WG hub + config sync; each
endpoint = `sb-easy agent`) and how to add agent nodes, see
**[docs/deployment.md](docs/deployment.md)**.

> Do **not** run this on a box that already runs sing-box on `:9090`/a tun — the
> managed instance would conflict. Stop the old one first.

> Behind a registry mirror (no Docker Hub access), pass base images, e.g.:
> ```sh
> docker build \
>   --build-arg CXX_IMAGE=docker.1ms.run/library/debian:bookworm-slim \
>   --build-arg NODE_IMAGE=docker.1ms.run/library/node:20-alpine \
>   --build-arg DEBIAN_IMAGE=docker.1ms.run/library/debian:bookworm-slim \
>   -t sb-easy:latest .
> ```

## Security — do this before exposing it
- **Set a random `JWT_SECRET`** (anyone who knows it can forge admin tokens).
  Never use the example/dev value.
- **Set a strong `ADMIN_PASSWORD`** (only seeds the first admin; change later in
  the Users page).
- Keep the **Clash API on `127.0.0.1:9090`** (not `0.0.0.0`) unless a remote
  host genuinely needs reachback over the WG intranet; otherwise firewall 9090.
- Restrict `CORS_ORIGINS` for public deployments.

## Configuration (env)
| var | default | notes |
|-----|---------|-------|
| `BIND_ADDR` | `0.0.0.0:51821` | panel listen |
| `JWT_SECRET` | — | **required**; random |
| `ADMIN_PASSWORD` | `admin` | first-admin seed only |
| `EXTERNAL_HOSTNAME` | `127.0.0.1` | used in client WG endpoints |
| `SINGBOX_MANAGED` | `true` (image) | supervise sing-box in process |
| `SINGBOX_BIN` | `sing-box` | path to the binary |
| `SINGBOX_API_URL` / `SINGBOX_API_SECRET` | `http://127.0.0.1:9090` / — | Clash API the panel talks to |
| `WG_ENABLED` | `true` | manage the WireGuard interface |
| `AGENT_TOKEN` | — | legacy global agent token (per-host tokens preferred) |
| `CORS_ORIGINS` | empty | comma-separated exact origins; empty/`*` is permissive |
| `LOG_LEVEL` | `info` | `trace`, `debug`, `info`, `warn`, `error`, or `fatal` |

Node mode in the production image remains `sb-easy agent`; it dispatches to the
dedicated C++ agent with `SB_EASY_SERVER` + `AGENT_TOKEN` (see
`agent/.env.example`). The agent supervises the bundled sing-box process and
preserves the Rust node-local egress/override environment variables. Set a
separate `AGENT_UI_PASSWORD` to enable its local management page on
`0.0.0.0:51822` (`AGENT_UI_BIND` and `AGENT_UI_USERNAME` are configurable).
The page shows live Clash API traffic plus runtime/config status, persists
node-local outbound settings, and queues refresh/reload/restart operations
without exposing the Agent token. Runtime configuration is split into focused
tabs for overview, network/DNS, routing, QuickJS, outbounds, and raw JSON. The
QuickJS tab is always visible and links directly to the central Profile editor.
The routing tab can open a short-lived test connection for a URL and reports the
actual sing-box rule, selector chain, and final proxy/direct decision.

## Backup & restore
- DB lives at `./data/sb-easy.db`. Online backup with rotation:
  ```sh
  ./scripts/backup.sh           # writes ./backups/sb-easy-<ts>.db.gz
  ```
  Schedule via cron (see the script header). The Users/Settings UI also has a
  full export/import.
- Restore: stop the container, `gunzip` a backup over `./data/sb-easy.db`
  (remove `-wal`/`-shm` first), start again.

## Health
- The container has a healthcheck on `/api/system/status`; `restart: unless-stopped`
  brings it back after crashes/reboots. Wire `docker events` / your monitor to the
  health status for alerting.

## Development
```sh
cmake -S cpp -B build/cpp -DSB_EASY_WARNINGS_AS_ERRORS=ON
cmake --build build/cpp --parallel 2
ctest --test-dir build/cpp --output-on-failure
cd frontend && npm ci && npm run build
scripts/check-cpp-parity.sh           # C++ vs legacy Rust shadow rendering
```
CI builds and tests the C++ backend, keeps the Rust rollback implementation
tested for parity, type-checks/builds the frontend, and builds the Docker image.
