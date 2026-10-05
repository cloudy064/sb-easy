# sb-easy C port — conventions

`c/` is the production C11 implementation. The previous C++20 implementation
in `cpp/` is retained for rollback and compatibility comparisons. The C
implementation must remain a drop-in replacement: same HTTP API paths,
payloads and status codes, same SQLite schema (`migrations/`), same generated
sing-box JSON (byte-for-byte, including ETags), same env vars and CLI flags.
The Vue (`frontend/`) and Svelte (`agent-ui/`) UIs are reused unchanged.

**The C++ source is the specification.** Port behaviour faithfully, including
edge cases, error messages and validation rules. When C++ and the Rust
`backend/` disagree, C++ wins.

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
  `CHECK_CONTAINS`). Port the matching `cpp/tests/*_test.cpp` cases.
* Private helpers shared between .c files of one module go in
  `c/src/<module>_internal.h`. `.inc` files are fine for generated tables.

## Libraries (replacing the C++ ones)

| C++ | C |
|---|---|
| nlohmann::json | `sb/json.h` (`sbj`) — sorted keys, dump identical to nlohmann |
| Drogon server/WebSocket | civetweb (`civetweb.h`, built with USE_WEBSOCKET, NO_SSL) |
| Drogon HTTP client | `sb/http_client.h` (libcurl) |
| yaml-cpp | libyaml (`<yaml.h>`) |
| QuickJS-NG, argon2, qrcodegen | same libraries, C APIs (`quickjs.h`, `argon2.h`, `qrcodegen.h`) |
| OpenSSL, SQLite | same |

## Style

* Public API in `c/include/sb/<module>.h`, prefix `sb_`, snake_case.
  Header comments say what, not how; mirror the C++ doc comments.
* Errors: functions that can fail return `int` (0 ok / -1 fail) or a pointer
  (NULL on failure) and take a trailing `sb_err *err` (may be NULL). Use
  `sb_fail(err, SB_ERR_<KIND>, fmt, ...)`; kinds map from the C++ exception
  types (NotFoundError → SB_ERR_NOT_FOUND, ValidationError /
  std::invalid_argument → SB_ERR_VALIDATION, ConflictError →
  SB_ERR_CONFLICT, ScriptError → SB_ERR_SCRIPT, others → SB_ERR_GENERIC /
  SB_ERR_IO / SB_ERR_UPSTREAM). Keep C++'s exception messages verbatim — the
  HTTP layer returns them to clients.
* Ownership: returned `char *` / `sbj *` are owned by the caller unless the
  doc says "borrowed". Structs have `*_init` / `*_free` (free releases
  members, not the struct). `std::optional<std::string>` → `char *` that may
  be NULL. `std::vector<T>` → `{T *items; size_t len, cap;}` + push/free.
* `std::function` callbacks → function pointer + `void *user`.
* Classes with pImpl → opaque `typedef struct sb_x sb_x;` with
  `sb_x_new(...)` / `sb_x_free(...)`.
* Threads: pthreads. Anything shared across civetweb worker threads must be
  guarded (the Store serialises on one mutex, like the C++ Database).
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
