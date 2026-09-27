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

## Production rollout verified on 2026-09-27

- Central panel now runs the C image. Before and after cutover, all 5 host
  configurations, admin session and WireGuard peer lists matched.
- Compose image configuration and container ownership labels were updated.
  Original C++ rollback container: `sb-easy-rollback-20260927-140913`.
  Original data/config backup on the center:
  `/root/workspace/sb-easy/backups/c-cutover-20260927-140913`.
- Local unified agent now runs the C image. Health and proxy connectivity pass.
  Original rollback container: `sb-easy-agent-rollback-20260927-141856`;
  private offline data backup: `/tmp/sb-easy-agent-backup.sXX5j6`.
- Fixed Japan Z03 Claude egress was applied to all 5 central profiles, with
  backup `/root/workspace/sb-easy/backups/c-rewrite-20260927/claude-profiles-before.json`.
  Both online Linux agents reported the current config ETag without errors.
- Local live route tests for `anyrouter.top`, `api.anthropic.com` and
  `downloads.claude.ai` selected `[iKuuu] 🇯🇵 日本Z03 | IEPL` successfully.
  The conflicting local anyrouter automatic-selection rule was removed;
  unrelated local rules were preserved.
- JSON object keys now preserve embedded NUL bytes through parsing, lookup,
  clone, update and serialization; a field with a NUL suffix cannot alias
  the plain field. Regression coverage added.

## Outstanding verification

- Android devices `xiaomi` and `adrd` are offline. Central configuration is
  ready; actual receipt and routing remain unverified until they reconnect.
- Passwords and JSON keys preserve embedded NUL bytes. Other model strings
  still require a broader compatibility audit; arbitrary-input byte-exact
  parity is not claimed. Detailed JSON error wording and platform-dependent
  WireGuard conversion differences are documented in README.md.
- Final JSON-key hardening is being tested and packaged after the first
  production rollout.

Local verification logs are `/tmp/sb-c-*.log`. Docker builds can require
`--network host` on this machine to use its working proxy route; this does
not start a runtime service or modify host interfaces.
