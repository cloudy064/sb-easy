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

### M1 — database and profile API (in progress)

- [x] SQLite connection/transaction RAII.
- [x] Migration runner compatible with SQLx metadata and checksums.
- [x] Profile persistence and host render queries over the existing schema.
- [ ] Host CRUD and host-outbound assignment repositories.
- [ ] `/api/hosts`, `/api/hosts/profiles`, and config preview endpoints.
- [x] Persist `rule_script` and `rule_script_enabled` on profiles.

### M2 — agent control plane

- Agent bearer authentication.
- Config endpoint with byte-for-byte stable serialization and ETags.
- Status, command, latency, and telemetry endpoints.
- C++ agent mode and atomic config replacement.

### M3 — proxy sources and sing-box control

- Proxy CRUD and URI/outbound parsers.
- Subscription fetch/reconciliation.
- sing-box supervisor and Clash API HTTP/WebSocket proxying.

### M4 — WireGuard and administrative APIs

- WireGuard peer provisioning and config generation.
- Authentication, users, roles, audit, settings, backup/restore.
- Static Vue assets and SPA fallback.

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
