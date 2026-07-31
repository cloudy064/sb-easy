# C++ rewrite plan

Branch: `rewrite/cpp-quickjs`

## Compatibility boundary

The rewrite is incremental. Until the cutover:

- `frontend/` remains the only UI implementation;
- `migrations/` remains the canonical SQLite schema history;
- Rust API payloads and status codes are parity fixtures;
- generated sing-box JSON must match semantically, including fallback behavior;
- the existing Rust backend remains runnable for comparison.

## Stack

| Concern | Choice |
| --- | --- |
| Language | C++20 |
| Build | CMake + pinned FetchContent dependencies |
| HTTP/WebSocket | Drogon 1.9.13 |
| JSON | JSON for Modern C++ 3.12.0 |
| Database | SQLite C API behind repository classes |
| Scripts | QuickJS-NG 0.15.1 C API |
| HTTP client | Drogon client initially; libcurl only where streaming requires it |
| Tests | CTest, core tests without the HTTP framework |

The configuration, database, WireGuard, and sing-box lifecycle layers do not
depend on Drogon types. HTTP controllers only translate requests and responses.

## Migration stages

### M0 — core foundation (implemented)

- CMake project and dependency pinning.
- Managed/full config rendering.
- Proxy outbound generation.
- Constrained `buildRules(context)` QuickJS engine.
- CLI fixture runner and unit tests.

### M1 — database and profile API (implemented)

- [x] SQLite connection/transaction RAII.
- [x] Migration runner compatible with SQLx metadata and checksums.
- [x] Profile persistence and host render queries over the existing schema.
- [x] Host CRUD and host-outbound assignment repositories.
- [x] `/api/hosts`, `/api/hosts/profiles`, and config preview endpoints.
- [x] Persist `rule_script` and `rule_script_enabled` on profiles.

### M2 — agent control plane (implemented)

- [x] Agent bearer authentication with per-host isolation.
- [x] Config endpoint with byte-for-byte stable serialization and ETags.
- [x] Status, command, latency, and bounded telemetry transport endpoints.
- [x] C++ polling agent and validated atomic config replacement.

### M3 — proxy sources and sing-box control (implemented)

- [x] Proxy CRUD and URI/base64/Clash YAML/outbound parsers.
- [x] Bounded HTTPS subscription fetch and fingerprint/tag reconciliation.
- [x] Clash API HTTP control proxy with per-host target and secret resolution.
- [x] Local and remote-agent proxy latency tests with persisted results.
- [x] Agent-side connection/traffic telemetry sampling from the installed
  sing-box config.
- [x] Authenticated Clash WebSocket proxying for live traffic, logs,
  connections, and memory.
- [x] Local sing-box supervisor with validated atomic config, SIGHUP reload,
  hard restart, crash backoff, and graceful child cleanup.

The WebSocket bridge rejects invalid query JWTs before protocol upgrade, limits
the route to the four supported stream kinds, and resolves local or per-host
Clash URL/secret pairs independently. The polling agent remains the bounded
fallback for hosts whose Clash endpoint cannot be reached by the panel.

### M4 — WireGuard and administrative APIs (implemented)

- [x] Rust-compatible Argon2id password hashes and HS256 JWT sessions.
- [x] Protected administrative routes, viewer read-only RBAC, users, and audit.
- [x] Settings persistence and sing-box config download routes.
- [x] WireGuard peer/managed-host provisioning, kernel sync, client configs,
  live stats, quotas/expiry, and SVG QR generation.
- [x] Settings backup/restore and system log/status parity.
- [x] Static Vue assets, CORS policy, and SPA fallback.

### M5 — cutover

- Contract test the Rust and C++ servers against the same temporary database.
- Run both backends in shadow rendering mode and compare generated configs.
- Switch Docker entrypoint to `sb-easy-cpp`.
- Retire Rust sources only after parity and rollback validation.

## Script failure policy

Scripts run centrally while rendering a host config, never inside the agent and
never on the packet path. A script failure makes rendering fail closed:

- remote agents retain their last accepted config;
- the self supervisor does not overwrite its last good config;
- preview APIs return a structured script error;
- no unscripted fallback config is silently served.
