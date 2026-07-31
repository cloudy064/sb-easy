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
- a CLI renderer for parity fixtures and migration testing;
- focused tests for rendering, scripting limits, migrations, and persistence.

The HTTP server is introduced in the next milestone after the core has fixture
parity with the Rust implementation. Drogon is the selected transport framework;
it does not leak into the core library.

## Build

```sh
cmake -S cpp -B build/cpp -DCMAKE_BUILD_TYPE=Release
cmake --build build/cpp --target sb-easy-cpp sb-easy-core-tests -j
ctest --test-dir build/cpp --output-on-failure
```

Dependencies are pinned and fetched by CMake:

- QuickJS-NG `v0.15.1`;
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

The core/database test image can be built independently:

```sh
docker build -f cpp/Dockerfile -t sb-easy-cpp-core .
docker run --rm sb-easy-cpp-core
```

This image is intentionally not a replacement for the production container
until the HTTP and agent control-plane milestones are complete.

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
