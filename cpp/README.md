# sb-easy C++ rewrite

This directory is the incremental C++20 replacement for the Rust backend and
agent. The Vue frontend, SQLite database format, HTTP API contract, and sing-box
configuration format stay compatible during the migration.

The current foundation contains:

- a framework-independent sing-box configuration renderer;
- managed/full profile behavior compatible with the Rust renderer;
- a constrained QuickJS-NG `buildRules(context)` execution engine;
- a SQLite migration runner compatible with the existing SQLx metadata and
  checksums, plus a profile/host repository;
- a Drogon HTTP server for host/profile CRUD, outbound assignment, token
  rotation, and per-host config preview;
- a CLI renderer for parity fixtures and migration testing;
- focused tests for rendering, scripting limits, migrations, persistence, and
  live HTTP contracts.

Drogon remains confined to the HTTP adapter; configuration and database code do
not depend on framework types.

## Build

```sh
cmake -S cpp -B build/cpp -DCMAKE_BUILD_TYPE=Release
cmake --build build/cpp \
  --target sb-easy-cpp sb-easy-cpp-server \
           sb-easy-core-tests sb-easy-http-tests -j
ctest --test-dir build/cpp --output-on-failure
```

Dependencies are pinned and fetched by CMake:

- QuickJS-NG `v0.15.1`;
- Drogon `v1.9.13`;
- JSON for Modern C++ `v3.12.0`.

QuickJS is linked statically. The std/os libraries and module loader are not
linked into the rule engine. SQLite and OpenSSL are system build dependencies;
OpenSSL SHA-384 is used to produce the same migration checksums as SQLx.

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
build/cpp/sb-easy-cpp-server \
  data/sb-easy.db migrations 127.0.0.1 51821 https://panel.example.com
curl http://127.0.0.1:51821/api/health
```

Implemented HTTP routes include:

- `/api/hosts` and `/api/hosts/{id}`;
- `/api/hosts/profiles` and `/api/hosts/profiles/{id}`;
- `/api/hosts/{id}/outbounds`;
- `/api/hosts/{id}/config`;
- token reveal and rotation routes used by the existing frontend.

The server defaults to loopback because authentication has not been migrated
yet. Binding it to a public interface is not safe at this stage.

The core/database test image can be built independently:

```sh
docker build -f cpp/Dockerfile -t sb-easy-cpp-core .
docker run --rm sb-easy-cpp-core
```

This image is intentionally not a replacement for the production container
until authentication and the agent control-plane milestones are complete.

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

Each execution gets a fresh runtime with memory, stack, source, output, and time
limits. `Date` and `Math.random` are disabled to keep generated configs and ETags
deterministic.
