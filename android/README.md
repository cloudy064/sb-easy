# sb-easy Android

This directory contains the managed sb-easy Android client. It embeds sing-box
1.13.12 through `libbox.aar`; no root access, external executable, local HTTP
server, or administrator account is required on the phone.

## Features

- shared one-time device authorization with a per-device Agent token, using either
  the camera or a QR image selected from the system photo picker;
- Android Keystore AES-GCM credential storage;
- ETag configuration sync over an explicit non-VPN underlying network;
- candidate/active/rollback atomic configuration snapshots and libbox validation;
- Android `VpnService`, foreground notification, Always-on recovery, and a
  Quick Settings tile;
- debounced, Network-identity-aware Wi-Fi/cellular recovery with bounded restart
  retries and post-handover control-plane/proxy probes;
- live libbox traffic, connections, proxy groups, node selection, URLTest, and logs;
- device-owned Claude/GPT and custom domain groups, independent fixed exits,
  a fixed default exit, and private/China direct routing;
- a real HTTP/HTTPS route test correlated with libbox connection events;
- an adaptive dark control surface with status/navigation/cutout safe areas and
  dedicated compact-phone and wide-screen navigation;
- readable config/routing views plus a redacted JSON view;
- visible Profile/QuickJS source, config version, and sync state;
- Agent status, commands, telemetry, and latency reporting.

The server executes QuickJS. The phone only receives the generated, validated
sing-box configuration and never receives administrator credentials or script
execution privileges.

## Local service groups (1.2.2)

The Proxies tab now contains **Default proxy**, **Claude**, and **GPT** cards.
Each selects a concrete provisioned node or `direct`; local selectors never
choose a URL-test group. Initial defaults independently read the centrally
provisioned Claude domain rule, GPT domain rule, and concrete route final.
Fallbacks use a concrete provisioned node. Users can choose different exits
for each card while connected or offline.

The Android profile preset on 2026-10-04 is Claude → MonoCloud **🇺🇸 Los Angeles 5**,
GPT → MonoCloud **🇯🇵 Tokyo 2**, default → iKuuu **🇯🇵 日本Z03 | IEPL**.
Three HTTPS latency rounds from the development host to Google's 204 endpoint
measured medians of 839 / 321 / 279 ms. Los Angeles 5 had the lowest median
among MonoCloud's 14 enabled US nodes; Japan exits were verified reachable.
This is a latency comparison from that network, not a bandwidth or handset
measurement. Choices stay fixed until the user changes them.

For an existing 1.2.0 policy, a complete three-exit server preset migrates the
default and existing built-in group exits once (`preset_revision: 1`). Edited
names, domains, app matching toggles, custom groups and deleted built-in groups
are preserved. Subsequent syncs and upgrades retain the user's selected exits.

Claude/GPT rules cover the service domains and their subdomains. Seeds follow
the [MetaCubeX Anthropic list](https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/anthropic.list)
and [OpenAI list](https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/openai.list),
with the previously used `anyrouter.top` gateway included in Claude. Domain lists
are editable. The built-in groups also match the official Android apps
(`com.anthropic.claude`, `com.openai.chatgpt`) using the platform's connection-owner
lookup; this can be disabled in **Edit rules**. Browser and external-login traffic
is matched by domain, so additional third-party hosts may need to be added.

**Create group** adds a named group with domain suffixes and an independently
selected exit. Up to 32 groups and 256 domains per group are supported. Domain
normalization accepts one domain per line, Unicode names and `*.example.com`;
URLs, IP literals and overlapping domains between groups are rejected. Deleting
a group returns its domains to the remaining direct/default policy.

Sniffing, DNS hijacking, control-plane access and management endpoint routes are
preserved. Private addresses go direct; local group rules then precede the
private/China domain and China-IP direct rules. Other public traffic uses the
default local selector. Centrally pinned proxy route rules are superseded by
the local groups/default. Provisioned direct and non-routing rules are retained.
Each group has a separate Google HTTPS DNS server (`dns.google`) through its selector; direct DNS
and proxy-node bootstrap resolution use direct AliDNS without an explicit
empty-direct detour. DNS reverse mapping assists domain-based routing.

The original server snapshot and ETag remain in `managed-config`; the local
policy is atomically saved in `local-routing.json`. Every server sync renders
from the untouched snapshot and reapplies the user's policy. Switching only a
node updates that selector, interrupting its existing connections. Editing
groups/domains reloads the configuration. Startup/reload restores local choices
synchronously through libbox before reporting ready, overriding historical
selector choices while preserving the existing rule-cache namespace. A removed
node produces a visible warning and a concrete fallback; its saved selection is
retained in case the node returns. Forgetting the device clears its local policy.

The config/routing views show the resulting local configuration; the displayed
configuration version continues to identify the server snapshot. No server
upgrade or administrator credential is required for this feature.

Version 1.2.2 fixes the Claude DNS failure observed on MonoCloud Los Angeles 5:
its HTTP exit timed out/rejected connections to the literal `1.1.1.1:443`
DoH destination. Keeping `dns.google:443` as a hostname lets the selected proxy
resolve and connect remotely; the app does not bootstrap this DoH hostname
through direct DNS. TLS verification remains enabled.

For groups/defaults selecting HTTP nodes, A/AAAA requests return FakeIP addresses.
The core maps browser connections back to the original hostname before HTTP
CONNECT, avoiding the same literal-IP failure for Claude's HTTPS traffic.
HTTPS/SVCB address hints are suppressed for these HTTP routes so they cannot
bypass the mapping. IPv4-only Android TUN configurations suppress synthetic
AAAA answers instead of advertising an IPv6 address without a VPN route.
Non-HTTP exits, domestic/management DNS and groups set to
`direct` use real DNS answers. FakeIP mappings persist in the existing cache
namespace, including switches away from HTTP nodes while a browser still holds
older synthetic addresses. Changing between HTTP/non-HTTP/direct DNS policies
reloads the core; otherwise node changes update only the selector. Node
selections and preset revision are unchanged, including edits on the handset.

The native DNS regression script exercises actual DNS wire requests through
mock HTTP CONNECT exits that reject literal IP destinations. It checks Claude,
GPT, custom/default and direct DNS answers, browser IP + TLS SNI connections,
IPv6, independent switching and mapping restoration after restarts.

## Build

Requirements:

- JDK 17
- Android SDK platform/build-tools 36
- Android NDK 28.0.13004108
- Go supported by sing-box 1.13.12

```sh
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk
export ANDROID_HOME=/path/to/android-sdk

./scripts/build-libbox.sh
./gradlew testDebugUnitTest lintDebug assembleDebug
```

The generated AAR and APK are intentionally ignored by Git. The libbox build
is pinned to sing-box revision
`1086ab2563320e0da0c23b3a491d8dfa0939dff4`, gomobile 0.1.12, and NDK
28.0.13004108.

`assembleDebug` produces architecture-specific APKs for `arm64-v8a`,
`armeabi-v7a`, `x86`, and `x86_64`, plus a larger universal APK. Most current
physical phones should use the ARM64 build; use the universal build when the
device architecture is unknown. Published builds keep these files separate so
users do not need to download native libraries for unrelated architectures.

## Enrollment

1. Install the APK matching the phone architecture from
   `app/build/outputs/apk/debug/`, normally `app-arm64-v8a-debug.apk`, or use
   `app-universal-debug.apk` as the compatibility fallback.
2. In the sb-easy Web panel, open **Devices → Add device**.
3. Name the device and create the ten-minute, single-use authorization QR code.
4. Open the App, scan the code with the camera or select its screenshot from the
   system photo picker, then accept Android's VPN consent dialog. Native agents
   redeem the same authorization with the command shown beside the QR code.
5. Use the four tabs for connection status, proxies, route/config/log tools, and
   device settings.

The current test deployment is plain HTTP and the App calls this out visibly.
Production deployments should put the control plane behind HTTPS; the App never
offers a switch that disables TLS certificate verification.

## Verification

The checked-in project is covered by Kotlin config-inspection tests, Android
lint, APK signing/ABI inspection, C++ enrollment/rendering/HTTP contract tests,
and an end-to-end preflight that feeds a rendered Android profile to sing-box
1.13.12 `check`. A physical Android device remains necessary for the final VPN,
network-switch, Doze, and vendor-ROM acceptance pass.

For a native routing preflight, generate the Kotlin fixtures and run the loopback
mock-exit test with a CLI built from the pinned Android source (include
`with_clash_api` for its test control endpoint):

```sh
export SB_EASY_ROUTING_FIXTURE_DIR=/private/tmp/sb-routing-fixtures
./gradlew :core:testDebugUnitTest --tests '*LocalRoutingTest' --rerun-tasks
python3 scripts/test-local-routing.py /path/to/pinned/sing-box "$SB_EASY_ROUTING_FIXTURE_DIR"
python3 scripts/test-local-routing-dns.py /path/to/pinned/sing-box "$SB_EASY_ROUTING_FIXTURE_DIR"
```

This checks actual Claude/GPT/custom/default routing, direct destinations,
independent selector changes, and restoration after restarts including changing
back to an earlier choice. Android application-owner matching still requires
on-device verification.

## Licensing

The embedded sing-box/libbox core is GPL-3.0-or-later. See
[`NOTICE.md`](NOTICE.md) and the corresponding source/build instructions before
redistributing the APK outside controlled testing. GitHub releases include the
exact `sing-box-1.13.12-source.tar.gz` corresponding-source archive alongside
the APKs.

## Network handover recovery

The monitor retains callback-provided capabilities and link properties for every
eligible physical network. Validated networks outrank unvalidated ones; blocked
networks are excluded. Network handles, interface indexes, addresses, routes and
DNS changes identify a handover, including reconnects that still use `wlan0`.
Loss cancels pending work. Recovery rechecks its generation before and after native
startup, retries failed startup at most three times, and never reports an obsolete
restart as recovered. The notification distinguishes a running core from successful
control-plane and configured URL-test connectivity. Diagnostics record successful
physical-network fallbacks as well as failures.

Version 1.1.7 requires an on-device Wi-Fi/cellular, Wi-Fi/Wi-Fi, airplane-mode and
rapid-toggle acceptance pass; JVM tests cannot reproduce Android/vendor routing.

## Background recovery (1.1.8)

A service-owned watchdog reconciles physical networks and probes the configured
URL-test endpoint every 30 seconds and after handovers/power-state events. The
probe has a 10-second caller deadline including DNS and does not wait for UI
connection observations. Two consecutive failures request recovery, limited to
one watchdog restart per 60 seconds. Network generation checks discard stale
results. No configured endpoint means only core/network presence is checked.

Network callbacks run on a dedicated handler thread. Timed partial wake locks
cover handover debounce/restarts (45 seconds maximum) and individual health
checks (20 seconds maximum), and are released on completion/cancellation; the
service does not keep a permanent wake lock. Power state, blocked-network events,
Activity resume/pause and background probe outcomes are included in diagnostics.

Android Doze and vendor battery restrictions may suspend network access or the
process despite a foreground VPN service. The settings screen links to battery
optimization and app settings. On Xiaomi/HyperOS, allow background execution and
set the app battery policy to unrestricted. This is a system/user setting; the app
cannot silently grant itself an exemption. Test screen-off Wi-Fi/cellular changes,
airplane-mode recovery, background-only browsing, and forced Doze on a device.

## Tiered network recovery (1.1.9)

A handover now uses the existing libbox CommandServer.resetNetwork() to reset
connections and DNS transports while retaining the Android TUN. This closes old
connections; it is not seamless migration. Same-interface reconnects also reset.
The background probe verifies actual connectivity afterward. Two consecutive
probe failures escalate to a full core/TUN rebuild with the existing cooldown;
missing cores and reset exceptions also rebuild. Stale generations and service
cancellation cannot report recovery or start an obsolete fallback. No permanent
wake lock is added. Device acceptance remains necessary.
