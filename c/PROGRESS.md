# C rewrite completion ledger

Objective: finish the C rewrite, compatibility and integration verification,
release images/CI, and centrally managed Claude egress rollout.

## Verified on 2026-09-27

- Parser/fetcher suite: 12 cases pass. Fixed uninitialized test HTTP request
  storage, truncated byte fixture, and two YAML expectations checked against
  the real C++ parser. Fixture waits are bounded.
- All 18 suites (including the real two-agent test) pass in normal and
  ASan/UBSan builds. Final GCC 12 Release builds also pass with warnings as
  errors after explicitly initializing helper output variables.
- Real central service + two agents: shared profile changes converge on both
  nodes; ETag 304 behavior and invalidation pass.
- Password create/login/reset regression covers embedded NUL bytes.
- Server JSON response encoding validates UTF-8 (regression added).
- Refused HTTP connections compared with C++: fixed transport error wording.

- Both `sb-easy:c-panel-candidate` and `sb-easy:c-unified-candidate` built.
  Panel image health, bundled UIs and executables verified in isolation.
  Embedded start/reload/stop smoke and two real embedded-agent convergence
  test pass (no TUN).
- Production central DB online backup copied privately for preflight: 16 C/C++
  comparisons pass, including all 5 hosts' configs and ETags, schema/migrations.
- Fixed Japanese egress plan covers 5 central profiles. Applying the plan,
  rendering all 5 hosts and rolling it back pass on database copies with both
  C and C++ servers. Japan Z03 live delay check returned 200 (5028 ms).
- C++ central service + C agents mixed-version test passes.
- Local CI YAML parsing and shell syntax checks pass.

## In progress / release gates

- Review documented differences, especially NUL-containing model strings,
  JSON error wording and platform-dependent WireGuard conversions.
- Validate CI configuration and release/rollback documentation.
- Commit the reviewed changes (preserve unrelated untracked `tmp/`).
- Prepare concrete production cutover, backup and rollback evidence before
  any live switch. Production currently runs the old C++ agent image.
- Apply/verify fixed Japanese egress centrally, then verify all subscribed
  agents receive it; the isolated two-agent test proves the mechanism only.

Local verification logs are `/tmp/sb-c-*.log`. Docker builds can require
`--network host` on this machine to use its working proxy route; this does
not start a runtime service or modify host interfaces.
