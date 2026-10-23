# sb-easy

A self-hosted, single-binary control panel for **WireGuard + sing-box**, in the
spirit of wg-easy. One central server manages many hosts, their proxies, configs
and clients — and can run/supervise sing-box itself, so there's nothing extra to
install.

- **Backend**: C11 (CivetWeb + SQLite + QuickJS), serving the Vue frontend.
- **Data plane**: sing-box (supervised in-process by sb-easy when managed).
- **Frontend**: Vue 3 + TS + Pinia.

Build and compatibility notes for the C implementation: [c/README.md](c/README.md).
The default `master` branch contains the C11 server and Linux agent.
The server, Linux agent and Windows native application are maintained in C11.
The old `cpp/` and Rust `backend/` directories are historical references only;
they receive no new features and are excluded from primary CI and release builds.

The current source targets the C server/agent **1.1.0**, Android **1.4.0 (29)**,
Windows **0.7.0**, Linux Desktop **0.1.0**, and macOS/iOS/tvOS **0.1.0 (1)**,
using sing-box **1.14.3**.
The [1.1.0 development preview](https://github.com/cloudy064/sb-easy/releases/tag/v1.1.0-preview.1) provides Android 1.4.0 test-signed APKs,
Windows 0.7.0 unsigned ZIP/MSI packages and a Linux Desktop 0.1.0 unsigned Debian 12 amd64 DEB,
with corresponding source, third-party notices and SHA-256 checksums.
Apple clients are supplied as source only. Native device, desktop-session and
production-signing acceptance is still incomplete; this is not a stable release.

Build identities and the verified download inventory are maintained in
[config/client-releases.json](config/client-releases.json); core revisions,
archive digests and compatibility policy are in
[config/runtime-versions.json](config/runtime-versions.json).
The panel's Downloads page uses the published artifact URLs, sizes and hashes.
Platform build and acceptance instructions:
[Android](android/README.md), [Windows](windows/README.md),
[Linux desktop](linux/README.md), [macOS/iOS/tvOS](apple/README.md).

The [product assessment](docs/product-gap-analysis-2026-10-23.md) records the
2026-10-23 baseline. The [implementation and evidence ledger](docs/feature-completion.md)
tracks the subsequent work and remaining native-device and publication checks.

## Features
- Multi-host central management: register hosts, assign proxies, edit config
  profiles (managed = panel-built, or **full** = paste a complete config).
- Profile-scoped QuickJS rule generation with an enable switch, bounded
  server-side test run, readable output preview, and Agent result provenance.
- Per-host agent token; the image runs the panel as `sb-easy` and preserves
  `sb-easy agent` as a compatibility alias for the dedicated C agent.
- Managed sing-box: in-process lifecycle, reload-on-change and recovery; Clash
  API exposed for live monitoring.
- WireGuard hub + clients (keys, QR, quota, expiry); optional host mesh.
- Separate proxy users with SS2022 device credentials, self-service subscription
  links and shared quotas across nodes. Short leases enforce byte limits,
  expiry and revocation in the embedded data plane; see
  [the lease protocol and failure behavior](docs/proxy-user-leases-v1.md).
- MFA/OIDC, device-group access control, session revocation, encrypted preferences
  with conflict handling, historical metrics, alerts and authenticated Prometheus.
- Subscription refresh with failed-update preservation, local routing and health
  policies, and a previewable wg-easy v14 migration path.
- Live monitor (traffic / connections / logs over WebSocket), proxy-group
  switching, subscriptions, config drift detection, downlink commands
  (reload/restart), RBAC + audit log, dark mode, en/zh i18n.

## Quick start (Docker, recommended)

The image bundles sing-box and supervises it in process (`SINGBOX_MANAGED=true`
by default) — no separate sing-box install. Host networking is used because this
is a VPN gateway (WireGuard UDP, tun, Clash API live in the host netns).

Point a DNS hostname at the server and allow TCP 80/443 (plus UDP 51820 for
WireGuard). Create the initial configuration, then start the services:

```sh
python3 scripts/configure-https.py --domain panel.example.com
docker compose up -d --build
```

Open `https://panel.example.com` and log in as `admin` using the generated
`ADMIN_PASSWORD` in `.env`. The helper creates a private file and refuses to
overwrite existing keys. Caddy obtains and renews the certificate, redirects
HTTP to HTTPS, and proxies the panel and WebSockets. The panel itself listens
on `127.0.0.1:51821`. Keep the `caddy_data` volume to preserve certificate state.
For an existing reverse proxy, start only `docker compose up -d sb-easy` and
forward HTTPS and WebSocket traffic to that loopback address.

For the full production topology (server = panel + WG hub + config sync; each
endpoint = `sb-easy agent`) and how to add agent nodes, see
**[docs/deployment.md](docs/deployment.md)**.

> Do **not** run this on a box that already runs sing-box on `:9090`/a tun — the
> managed instance would conflict. Stop the old one first.

> Behind a registry mirror (no Docker Hub access), pass base images, e.g.:
> ```sh
> docker build \
>   --build-arg C_IMAGE=docker.1ms.run/library/debian:bookworm-slim \
>   --build-arg GO_IMAGE=docker.1ms.run/library/golang:1.26-bookworm \
>   --build-arg GOPROXY=https://goproxy.cn,direct \
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
| `PANEL_DOMAIN` | — | required by Compose; public DNS hostname for HTTPS |
| `BIND_ADDR` | `127.0.0.1:51821` (Compose) | panel listen; binary-only default remains `0.0.0.0:51821` |
| `JWT_SECRET` | — | **required**; random |
| `ADMIN_PASSWORD` | required by Compose | first-admin seed only; generated by the setup helper |
| `EXTERNAL_HOSTNAME` | `127.0.0.1` | used in client WG endpoints |
| `SINGBOX_MANAGED` | `true` (image) | supervise sing-box in process |
| `SINGBOX_BIN` | `sing-box` | subprocess builds only; the default image embeds the engine |
| `SINGBOX_API_URL` / `SINGBOX_API_SECRET` | `http://127.0.0.1:9090` / — | Clash API the panel talks to |
| `WG_ENABLED` | `true` | manage the WireGuard interface |
| `AGENT_TOKEN` | — | legacy global agent token (per-host tokens preferred) |
| `CORS_ORIGINS` | `https://${PANEL_DOMAIN}` (Compose) | comma-separated exact origins; binary-only empty/`*` is permissive |
| `LOG_LEVEL` | `info` | `trace`, `debug`, `info`, `warn`, `error`, or `fatal` |

Node mode in the production image remains `sb-easy agent`; it dispatches to the
dedicated C agent with `SB_EASY_SERVER` + `AGENT_TOKEN` (see
`agent/.env.example`). The agent hosts the embedded sing-box engine and
preserves the established node-local egress/override environment variables. Set a
separate `AGENT_UI_PASSWORD` to enable its local management page on
`0.0.0.0:51822` (`AGENT_UI_BIND` and `AGENT_UI_USERNAME` are configurable).
The local console is an independent Svelte build served from `AGENT_UI_PATH`;
the image sets it to `/usr/share/sb-easy/agent-ui`, while a bare Agent can run
API-only when it is unset. The C service contains no embedded HTML and another
compatible UI can be substituted without rebuilding it. The
page shows live Clash API traffic plus runtime/config status, supports live
selector-group node switching, persists
node-local outbound settings, and queues refresh/reload/restart operations
without exposing the Agent token. The configuration view exposes the current
raw JSON and can open a short-lived test connection for a URL to report the
actual sing-box rule, selector chain, and final proxy/direct decision.

The unified managed-node build keeps the C Agent as the host executable and
links the official sing-box engine into that same process. Go is used only in
the disposable build stage; the deployed machine needs neither Go/GCC nor a
separate `sing-box` executable. The Svelte UI remains replaceable on disk:

```sh
docker build -f c/Dockerfile.unified --target artifacts \
  --output type=local,dest=dist/sb-easy-unified-glibc .
```

The output contains one glibc-linked `sb-easy` service executable, the pinned
version inventories, and the replaceable `agent-ui/` directory. A Debian-based runtime image with all runtime
libraries can be built using `--target runtime`; no compiler is installed in
that image.

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
- The container has a healthcheck on `/api/health`; `restart: unless-stopped`
  brings it back after crashes/reboots. Wire `docker events` / your monitor to the
  health status for alerting.

## Development
```sh
cmake -S c -B build/c -DCMAKE_BUILD_TYPE=Release -DSB_EASY_WARNINGS_AS_ERRORS=ON
cmake --build build/c --parallel 4
ctest --test-dir build/c --output-on-failure --timeout 180 --parallel 4
cd frontend && npm ci && npm run build
```
CI builds and tests the C backend in release and sanitizer configurations,
builds the C agent with embedded sing-box, builds/tests the Windows C11 desktop
and its UI, type-checks/builds the management frontend, and builds the Docker image.
The Docker CI also runs Go race tests and the embedded C suite, including actual
SS2022 traffic against two agents and the center. Download metadata can be
checked with `python3 scripts/client-release.py check`;
`verify-published` compares the reviewed inventory with GitHub release assets.
The C implementation and its tests are authoritative for new development;
features and fixes are not mirrored into the historical implementations.
