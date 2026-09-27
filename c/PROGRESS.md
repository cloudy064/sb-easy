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

## Final packaging and outstanding verification

- Android devices `xiaomi` and `adrd` are offline. Central configuration is
  ready; actual receipt and routing remain unverified until they reconnect.
- Passwords, usernames, JSON keys, JWT username claims and audit actors preserve
  embedded NUL bytes. User identity/session/audit end-to-end checks pass on
  both C and C++. Agent UI rejects appended NUL credential suffixes without
  issuing a session. Normal and sanitizer suites pass; production database
  snapshot still passes all 16 comparisons. Other model strings
  still require a broader compatibility audit; arbitrary-input byte-exact
  parity is not claimed. Detailed JSON error wording and platform-dependent
  WireGuard conversion differences are documented in README.md.
- Final JSON-key hardening (`7eacb28`) passed normal and sanitizer checks,
  was packaged into both images and deployed. Final panel cutover retained
  `sb-easy-rollback-20260927-143212` and backup
  `/root/workspace/sb-easy/backups/c-cutover-20260927-143212`.
  Final local agent cutover retained `sb-easy-agent-rollback-20260927-143606`
  and backup `/tmp/sb-easy-agent-backup.kRVIEK`. All three Claude route
  tests passed again after this cutover.

Local verification logs are `/tmp/sb-c-*.log`. Docker builds can require
`--network host` on this machine to use its working proxy route; this does
not start a runtime service or modify host interfaces.

## Identity compatibility follow-up (05168b0)

- Central and unified images tagged `c-panel-05168b0` and
  `c-unified-05168b0` were built and deployed through the candidate tags.
- Central cutover preserved all 5 configs, admin session and WireGuard peers.
  Rollback container: `sb-easy-rollback-20260927-144541`;
  backup: `/root/workspace/sb-easy/backups/c-cutover-20260927-144541`.
- Local agent health/proxy checks passed. Rollback container:
  `sb-easy-agent-rollback-20260927-144956`; backup:
  `/tmp/sb-easy-agent-backup.MHWGiJ`.
- Live UI rejected NUL suffixes on both username and password with 401 and no
  session cookie. All three fixed Japan Z03 route checks passed again.
- Android last-seen values are unchanged; their reception gate remains open.
- Isolated C/C++ API probes confirmed the next remaining differences: NUL
  suffixes on profile names, disabled rule scripts, host names and proxy tags
  survive C++ storage/response but are truncated by C. Evidence:
  `/tmp/sb-c-model-audit.log`. These fields still require fixes; this audit
  is not a claim that other model fields have been exhaustively covered.

## Profile string compatibility follow-up

- Profile names and rule scripts preserve byte lengths through create/update,
  list, copy, SQLite, script preview, rendering and the offline renderer CLI.
- Enrollment responses and saved agent credentials preserve profile names.
- Source limits count bytes after embedded NUL; QuickJS receives a terminated
  copy of the complete byte sequence, including when the caller buffer has
  no trailing terminator.
- All 18 normal and ASan/UBSan suites passed. Follow-up targeted engine/store/
  enrollment and end-to-end tests passed in both builds after final changes.
- C++ also passes the profile lifecycle/enrollment/rendering scenario. Offline
  renderer outputs are byte-identical, and all 16 production DB snapshot
  comparisons still pass. Logs: `/tmp/sb-c-profile-*.log`.
- Versioned images `sb-easy:c-panel-f181f96` and
  `sb-easy:c-unified-f181f96` built successfully with GCC 12 Release warnings
  as errors; the embedded engine smoke test passed during the agent build.
- These source changes are not deployed yet. Host names, proxy tags and the
  wider non-authentication model audit remain in progress; Android receipt
  remains dependent on the two offline devices reconnecting.
