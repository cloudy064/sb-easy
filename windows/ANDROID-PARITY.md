# Android / Windows feature comparison (0.6.0)

Reviewed against `android/app/src/main/java/io/sbeasy/android/MainActivity.kt`,
`android/core/src/main/java/io/sbeasy/android/core/AppTrafficLedger.kt`,
`TrafficDomain.kt`, `TrafficBreakdown.kt`, and `LocalRoutingPolicy.kt`.

| Capability | Windows status |
| --- | --- |
| Device enrollment and automatic configuration download | Available in the existing enrollment workflow |
| Configuration validation, activation and rollback | Available; preserves previous working configuration on candidate failure |
| TUN start/stop, managed WireGuard endpoint | Available with the pinned sing-box 1.13.12 |
| Live connections, speeds and node latency history | Available |
| App traffic totals | Added in 0.5.0; process basename instead of Android package/UID |
| Domain totals, host and outbound drill-down | Added in 0.5.0 with public/private suffix grouping |
| Background collection and persistent statistics | Added in the C service; sampled live connections, not Android libbox closed-connection events |
| Statistics search, sort and reset | Added; live checkpoints survive reset |
| Runtime and service logs | Added; bounded sanitized recent view, full historical offline export remains available |
| Recent host/outbound observations | Available through statistics sorted by recent access; does not include all rejected/short connections |
| Runtime configuration overview and service routing | Available as a credential-free projection; raw JSON is not exposed to WebView |
| Default GPT routing override | Available and persistent |
| Local custom service groups, domain editing, arbitrary node selection | Not yet ported; Android has a more complete local routing policy layer |
| Active node/group latency tests | Not yet ported; Windows displays existing core latency results |
| Actual URL route tests and route-record synchronization to center | Not yet ported |
| Android package-specific routing, battery exemptions, Always-on VPN | Platform-specific; no direct Windows equivalent in this release |
| Windows service autostart, tray and installer | Available; service autostart does not imply automatic VPN connection |

## Collection and privacy

The service samples the authenticated, process-owned loopback Clash endpoint every
two seconds, independently of the WebView. Global counters and attributed counters
are deliberately separate. The API returns only live connections, so short flows
and closing tails can be missed by attribution. Opening the UI does not reset data.
Checkpoints suppress repeated/out-of-order counters. Storage uses the existing
protected DPAPI store in `core-work/device-state.dat`, separate from enrollment's
parent `device-state.dat`. Saves happen every 30 seconds and on normal shutdown.
Load corruption is not overwritten by automatic saves; explicit clear can reset it.

The display is bounded to 512 detail groups and 20,000 checkpoints per core process.
Capacity is surfaced in the UI. App attribution uses only a process basename;
the API does not expose full local paths. Statistics and sanitized logs require
the active console user or an administrator, just like runtime/config inspection.
Domain grouping uses tldts with private suffixes enabled and performs no DNS lookup.

The next parity work requires a general local routing-policy layer (including DNS
detours and preservation of center-managed WireGuard routes), controlled core
mutations for node tests/selection, and an actual proxy-routed URL probe. These are
not simulated by the new statistics UI.

## Android 1.3.1 capture alignment (Windows 0.6.0)

Implemented: raw-IP PCAP, app/domain/host/IP filters, libpcap BPF validation,
file and total storage limits, timed rotation, export/delete, authenticated
manual/automatic upload, digest acknowledgement and optional local deletion.

Windows selects process basenames rather than Android UIDs/packages. It requires
an elevated service and a running TUN, and uses WinDivert sniff copies. Attribution
comes from core connection snapshots, so short flows can be missed. Wi-Fi gating
checks whether Wi-Fi is connected before starting an upload; it does not bind the
transfer to that adapter. These differences remain; full Android parity is not claimed.
