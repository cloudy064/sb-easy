# sb-easy native Apple clients

This directory contains a C11 configuration/import core, a native SwiftUI app,
and a `NEPacketTunnelProvider` for **iOS 16+, macOS 13+ and tvOS 17+**. The tunnel
uses the same sing-box revision as the other clients, from
[`config/runtime-versions.json`](../config/runtime-versions.json). It does not
launch an external process or expose a local HTTP/Clash control listener.

The current development version is **0.1.0 (build 1)**, read from
[`config/client-releases.json`](../config/client-releases.json). There is no
published Apple release or download entry. Release metadata is added only after
the native build, device acceptance and distribution signing are complete.

**Current verification boundary:** the portable C contracts, ASan/UBSan checks,
real libbox daemon/selector IPC tests, generated Darwin Objective-C bindings,
Swift syntax parsing and shared model type checking have run on Linux. A Linux
check cannot verify Apple framework availability, code signing, NetworkExtension
entitlements or a device tunnel. The macOS CI workflow is provided; its native
build/test jobs and the device acceptance below must pass before a binary is
labelled ready for distribution. No Apple binary has been signed or published by
this change.

## Build on a Mac

Install Xcode with the iOS and tvOS SDKs, XcodeGen, Python 3 and Go at or above the
manifest's `go_minimum`. Select the full Xcode developer directory. From the
repository root:

```sh
python3 apple/scripts/build-deps.py
xcodegen generate --spec apple/project.yml
xcodebuild -project apple/SBEasy.xcodeproj -scheme SharedTests \
  -destination 'platform=macOS' test CODE_SIGNING_ALLOWED=NO
xcodebuild -project apple/SBEasy.xcodeproj -scheme SBEasy-iOS \
  -destination 'generic/platform=iOS Simulator' build CODE_SIGNING_ALLOWED=NO
xcodebuild -project apple/SBEasy.xcodeproj -scheme SBEasy-tvOS \
  -destination 'generic/platform=tvOS Simulator' build CODE_SIGNING_ALLOWED=NO
xcodebuild -project apple/SBEasy.xcodeproj -scheme SBEasy-macOS \
  -destination 'platform=macOS' build CODE_SIGNING_ALLOWED=NO
```

`build-deps.py` verifies libyaml 0.2.5 by SHA-256, checks out the manifest's exact
sing-box commit, installs the matching SagerNet gomobile version in an isolated
build directory, applies the small Apple IPC overlay and builds the XCFramework.
It also writes a version/overlay hash manifest and a corresponding-source archive
under `apple/Vendor`. The dependency/build directories are ignored by Git.
Use `--platform iossimulator,tvossimulator,macos` for the unsigned CI build.

For installation, copy `Signing.xcconfig.example` to `Signing.xcconfig` and set
your registered team, bundle prefix, shared App Group and shared Keychain group.
Both each app and its packet-tunnel extension need matching App Group/Keychain
access and the `packet-tunnel-provider` Network Extensions entitlement. Use Xcode
Signing & Capabilities to create the matching profiles, then build/archive the
appropriate `SBEasy-*` scheme. The application prompts for the system VPN
configuration authorization on its first connection. The app does not enable
VPN On Demand automatically.

The macOS target is an **App Store app-extension** design. Apple's deployment
rules require a system-extension design for Developer ID distribution of a
macOS packet tunnel; this project does not claim that signing its app-extension
with Developer ID produces a supported direct-download client. See Apple's
[Network Extension deployment matrix](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)
and [packet tunnel provider documentation](https://developer.apple.com/documentation/networkextension/packet-tunnel-provider).
Supply the intended App Store icon artwork and product metadata before store
submission. The unsigned CI schemes are compilation checks, not store packages.

## Behavior and boundaries

- Managed profiles redeem a one-time `sbeasy://enroll` link, retain the returned
  device identity in Keychain, fetch `/api/agent/config` with its ETag, report the
  actual running state and preserve a last successful runtime for recovery.
  A config-fetch outage after enrollment leaves a recoverable enrolled profile.
- Independent profiles import HTTPS or offline URI, Clash YAML and sing-box JSON
  subscriptions. Imports use the authoritative C parser, import proxy nodes only,
  rename duplicate node labels and report skipped entries. Inputs are limited to
  512 KB / 8,192 lines; the Apple parser caps YAML depth at 64, parsed events at
  20,000, conversion nodes at 30,000, copied scalar bytes at 2 MB and rewrite work
  at 2 MB / 32 retries. A node exceeding a conversion limit is rejected rather
  than imported with partially omitted settings. Each subscription keeps
  its previous nodes on failed refresh. The UI shows provided quota/expiry data;
  missing usage fields stay unavailable. No central credentials are reused.
- Both modes can retain local subscriptions, select live strategy-group members,
  request real core URL tests, view real counters and add local domain groups.
  A local domain group uses the chosen node for its route and DNS. Management,
  WireGuard, private-network, exact destination and non-routing rules precede
  local overrides. Node removal that invalidates a saved selection/group fails
  until that preference is changed.
- Profiles and their config/subscription contents are sealed with AES-GCM. The
  vault key, management token and subscription URLs use the shared Keychain with
  `AfterFirstUnlockThisDeviceOnly`, no iCloud synchronization. File locking and
  revision checks prevent app/extension writers from silently replacing newer
  data. Per-profile working/cache directories prevent selector state from
  crossing profiles. The libbox Apple start adapter omits its default plaintext
  configuration snapshot.
- Enrollment, config and subscription fetches require HTTPS with normal system certificate validation,
  reject redirects and user-info URLs, disable shared cookies/credential storage,
  cap response bodies, and have bounded request/resource timeouts. Raw network
  errors, proxy credentials, configuration and subscription URLs are not returned
  over provider IPC. Live IPC accepts only state/reload/select/probe operations.
- The provider installs IPv4/IPv6 routes and DNS through NetworkExtension,
  obtains the TUN descriptor through libbox's Darwin API, monitors network paths
  and handles sleep, wake, stop and candidate rollback. It has no process lookup,
  per-app VPN, shell, bridge or external-script backend. Configs requiring those
  unsupported features are rejected. iOS per-app VPN requires MDM; tvOS does not
  offer that facility. This is a tunnel client, not a system kill switch.
- While the tunnel runs, its minute timer fetches managed changes and checks
  subscription due times. When disconnected, the running app checks the selected
  profile on its own minute timer. Remote subscriptions default to six hours, with bounded
  failure backoff; foreground users can refresh immediately. Apple controls
  suspended/background execution. A stopped or suspended app is not an always-on
  subscription scheduler. Profile switching and destructive edits require a
  disconnected tunnel.

## Local verification

On Linux with libyaml/OpenSSL development packages:

```sh
cmake -S apple -B build/apple-contract -DCMAKE_BUILD_TYPE=Debug
cmake --build build/apple-contract -j2
ctest --test-dir build/apple-contract --output-on-failure
```

`apple/Tests/core_test.c` exercises the Apple base64 branch, import reports,
independent/managed config generation, route ordering, invalid preferences and
quota parsing. Passing a filename to `apple_core_test` exports a fixture runtime
for `sing-box check -c <file>`; the command does not start a tunnel.
`SharedTests` exercises URL validation, C/Swift serialization, authenticated
vault tamper rejection, stale writes and profile isolation on macOS. The Go
bridge tests start only an in-memory core with direct outbounds and a selector:
no TUN, route modification, command listener, outbound probe or production port.

## Required device acceptance

Record OS, Xcode, signing team/profile identifiers, manifest/overlay hashes and
results for each platform. Use a disposable test device and a controlled dual
stack endpoint; do not infer network correctness from a successful compilation.

1. Build and sign the app plus extension with a real team. Install, approve VPN
   authorization, enroll, reconnect after relaunch, then verify tokens/config do
   not appear in container plaintext files, IPC responses or exported app logs.
2. Import valid URI/YAML/JSON and offline subscriptions; exercise duplicate names,
   invalid/oversized responses, TLS errors, redirects and quota metadata. Check
   refresh errors keep nodes and selections; check independent mode sends no
   management requests.
3. Capture traffic at the controlled endpoint while connecting. Verify IPv4,
   IPv6, DNS routing, selector changes, local groups and managed WireGuard routes.
   Compare UI counters/delay results with actual traffic. Test captive networks,
   cellular/Wi-Fi changes, absent IPv6 and a physically disconnected network.
4. Stop while starting and while applying network settings, sleep/wake, terminate
   the app and extension, and rapidly reconnect. Verify no double completion,
   stale reload or routes/DNS left behind after disconnect. A core/tunnel crash
   may restore normal system connectivity; no leak-free/kill-switch claim is made.
5. Deliver an invalid managed candidate and a removed selected node; verify the
   last successful profile continues or is restored and the UI reports rollback.
   Delete/switch profiles only when stopped and verify Keychain/profile isolation.
6. Run `SharedTests` and all three native build schemes in `.github/workflows/apple.yml`.
   Keep signing/install/network evidence separate from unsigned simulator logs.
