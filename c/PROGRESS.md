# C rewrite completion ledger

Objective: finish the C rewrite, compatibility and integration verification,
release images/CI, and centrally managed Claude egress rollout.

## Current release state

- Production center and local agent run the verified identity fix `05168b0`.
- Profile/script fixes and host/WireGuard name fixes are verified in source;
  versioned images through `d2dd8e5` are built. These changes await the combined rollout.
- Proxy storage/rendering and agent tag operations preserve full bytes;
  remaining non-authentication string boundaries are still under audit. Android `xiaomi` and `adrd` remain offline, so actual reception
  of the centrally prepared rules has not been verified.

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
  `/tmp/sb-c-model-audit.log`. Later fixes are recorded below; this audit
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
- These source changes are not deployed yet. Proxy tags and the
  wider non-authentication model audit remain in progress; Android receipt
  remains dependent on the two offline devices reconnecting.

## Host and WireGuard name compatibility follow-up

- Host names preserve complete byte lengths through API create/update/list,
  SQLite, copy, QuickJS host context, enrollment and saved agent credentials.
- WireGuard peer names preserve full bytes on create/update/read, and name
  matching distinguishes a plain prefix from every NUL-containing name.
  Auto-generated `host: ...` peer names preserve the complete host name.
- Config exports and server file writes carry explicit lengths. Download
  headers and `X-SB-Easy-Profile-Name` preserve the C++ byte-string behavior.
- Isolated C/C++ exports have identical config hashes and filename headers;
  real-agent enrollment checks preserve NUL-containing names in credentials.
- All 18 normal and ASan/UBSan suites pass. Additional fake-tool checks prove
  exact peer reuse, distinct peer allocation, complete client/host/server
  exports, and full server config file writes. All 16 production DB snapshot
  comparisons still pass. Logs: `/tmp/sb-c-host-*.log`.
- Images `sb-easy:c-panel-d3c88a8` and `sb-easy:c-unified-d3c88a8`
  built successfully with GCC 12 Release warnings as errors. Embedded engine
  start/reload/stop smoke passed during the unified image build.
- These changes are staged for the combined release, not deployed yet.

## Proxy model and renderer compatibility follow-up

- Proxy tags, server strings and protocol values preserve full bytes through
  JSON/model copies, API CRUD, import, SQLite, backup restore and rendering.
  Fingerprints include complete server and credential strings, so embedded-NUL
  suffix differences do not incorrectly merge distinct imported nodes.
- Duplicate tag suffixes, Android selectors, reserved-tag comparisons, script
  outboundTags and external endpoint tags use full-byte matching. Panel latency
  requests encode complete tags and latency updates bind complete JSON keys.
- Added renderer, parser, store and real HTTP regression coverage. The same
  HTTP lifecycle and fingerprint expectations pass against C++.
- All 18 normal and ASan/UBSan suites pass; the final expanded HTTP scenario
  also passes separately under sanitizers. Three renderer fixtures (Android,
  NUL-suffixed Android and Linux) match C++ output byte-for-byte, including
  duplicate tags and script context. All 16 production snapshot comparisons pass.
  Evidence: `/tmp/sb-c-proxy-*.log`.
- Remaining related boundaries include the agent Clash test-proxy tag filter,
  result keys and UI selection callbacks, which still take C strings. Broader
  subscription/metadata strings also need review. This batch is not deployed.

## Agent tag compatibility follow-up

- Test-proxies command JSON arrays retain full byte strings. Clash filtering,
  deterministic name ordering, URL encoding and latency result keys retain
  embedded NUL suffixes rather than selecting/reporting a prefix node.
- Local UI selection callbacks carry both lengths through the agent to the
  Clash PUT URL/body and the success response. Leading-NUL names remain valid
  nonempty byte strings, matching C++.
- Fake-controller regression proves exact filtered requests, complete result
  keys and encoded group selection. Authenticated UI regression proves complete
  group/name callback values. Agent Clash/UI and real two-agent integration
  suites pass in normal and ASan/UBSan builds; logs are
  `/tmp/sb-c-agent-tags-*.log`.
- General command strings, telemetry/diagnostic metadata and subscription
  fields still need the broader boundary audit. Release and Android receipt
  gates remain outstanding.

## Proxy compatibility packaging and next verified difference

- Both `sb-easy:c-panel-d2dd8e5` and `sb-easy:c-unified-d2dd8e5` built
  successfully with GCC 12 Release warnings as errors; the unified build
  executed its embedded start/reload/stop smoke. Images are not deployed.
- Isolated subscription API probes confirm that C++ preserves a NUL suffix in
  both the trimmed name and stored URL, while C currently truncates them.
  The disabled test subscription used only `example.invalid` and no fetch.
  Evidence: `/tmp/sb-c-subscription-byte-audit.log`. This is the next concrete
  model-boundary fix, before the combined rollout.
