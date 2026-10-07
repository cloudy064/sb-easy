# sb-easy C11 development conventions

`c/` is the authoritative production C11 server and Linux agent implementation.
Windows native code is also C11, in `windows/`. Implement new native features,
fixes and tests in C; do not introduce C++ or mirror changes into `cpp/` or the
Rust `backend/`. Those directories are historical references only, excluded
from primary CI and release builds.

The current C implementation, its tests and the documented public contracts
define behavior. Preserve existing HTTP paths, payloads and status codes,
SQLite schema (`migrations/`), generated sing-box JSON and ETags, environment
variables and CLI flags unless a task explicitly changes that contract.
Historical code may help explain old behavior but is not the specification
for current development. Frontend applications retain their existing languages.

## Build & test

```sh
cmake -S c -B build/c -DCMAKE_BUILD_TYPE=Debug -DSB_EASY_WARNINGS_AS_ERRORS=ON
cmake --build build/c --parallel 4
ctest --test-dir build/c --output-on-failure --timeout 180 --parallel 4
```

* Every `c/src/*.c` is compiled into `sb_core` automatically (glob) — do not
  edit `CMakeLists.txt` to add sources. `src/main_<name>.c` becomes the
  executable `sb-easy-c-<name>`; `src/main_unified.c` becomes `sb-easy`.
* Every `c/tests/<name>_test.c` becomes a ctest (cwd = repo root, env
  `SB_EASY_MIGRATIONS` points at `migrations/`). Use `c/tests/test.h`
  (`TEST(name)`, `CHECK`, `REQUIRE`, `CHECK_STR`, `CHECK_EQ_INT`,
  `CHECK_CONTAINS`). Add regression cases directly here for the current C
  behavior; historical tests may inform compatibility checks when relevant.
* Private helpers shared between .c files of one module go in
  `c/src/<module>_internal.h`. `.inc` files are fine for generated tables.

## Libraries

| Purpose | C API |
|---|---|
| JSON | `sb/json.h` (`sbj`) — sorted keys and stable serialization |
| HTTP server/WebSocket | civetweb (`civetweb.h`, built with USE_WEBSOCKET, NO_SSL) |
| HTTP client | `sb/http_client.h` (libcurl) |
| YAML | libyaml (`<yaml.h>`) |
| Scripts, password hashing, QR codes | `quickjs.h`, `argon2.h`, `qrcodegen.h` |
| Crypto, database | OpenSSL, SQLite |

## Style

* Public API in `c/include/sb/<module>.h`, prefix `sb_`, snake_case.
  Header comments describe behavior, ownership and error contracts.
* Errors: functions that can fail return `int` (0 ok / -1 fail) or a pointer
  (NULL on failure) and take a trailing `sb_err *err` (may be NULL). Use
  `sb_fail(err, SB_ERR_<KIND>, fmt, ...)` with the appropriate category:
  `SB_ERR_NOT_FOUND`, `SB_ERR_VALIDATION`, `SB_ERR_CONFLICT`, `SB_ERR_SCRIPT`,
  `SB_ERR_GENERIC`, `SB_ERR_IO` or `SB_ERR_UPSTREAM`. Preserve established
  client-visible error messages when fixing behavior; the HTTP layer returns
  them to clients.
* Ownership: returned `char *` / `sbj *` are owned by the caller unless the
  doc says "borrowed". Structs have `*_init` / `*_free` (free releases
  members, not the struct). Optional owned strings are nullable `char *`.
  Dynamic arrays use `{T *items; size_t len, cap;}` with push/free helpers.
* Callbacks use a function pointer plus `void *user`.
* Encapsulated modules use opaque `typedef struct sb_x sb_x;` with
  `sb_x_new(...)` / `sb_x_free(...)`.
* Threads: pthreads. Anything shared across civetweb worker threads must be
  guarded; the Store serialises on one mutex.
* Compile cleanly with `-Wall -Wextra -Wshadow`. No VLAs, no GNU nested
  functions. Check every allocation via `sb_x*` helpers (they abort on OOM).
* Logging: `SB_INFO(...)` etc. from `sb/util.h`.
* Must run under ASan/UBSan without reports:
  `-DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"`.

## Working in parallel with other agents

* Several agents edit `c/` at the same time, each owning specific files.
  Only edit files you own. Never edit `CMakeLists.txt`, never run
  `git commit/stash/checkout/reset/clean` — the lead integrates and commits.
* Keep your files compiling at all times: write a compiling skeleton first,
  then fill it in; fix your compile errors immediately. A broken file breaks
  every other agent's `sb_core` build.
* If someone else's file is temporarily broken, exclude it from your build
  dir instead of waiting: configure with
  `-DSB_EASY_EXCLUDE_SOURCES="<regex>;<regex>"` (matched against the file
  name, e.g. `http_routes_admin`), or just retry a bit later. Never edit it.
* Use your own build directories (`build/c-<you>`, `build/c-<you>-asan`).
* Tests that bind ports must use port 0 / ephemeral ports — ports 51821,
  51822, 7890 and 9090 on this machine are production services. Never touch
  the running `sb-easy-agent` container or `agent-data/`.
