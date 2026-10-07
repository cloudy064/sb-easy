# sb-easy Windows Client Design

Status: **approved for implementation**

Implementation update (2026-10-05): an executable development preview
now lives in `windows/`. All native service, host, adapter and test code is C11;
the frontend remains Vue/TypeScript. The preview includes Windows Service/console
entry points, authorized named-pipe IPC, a C COM WebView2 host, WinHTTP
enrollment/config download, shared sbj JSON, DPAPI persistence and ETag refresh.
`config.validate` invokes the separately prepared sing-box 1.13.12 executable's
real `check` command. `connection.start` and `connection.stop` now connect the GUI
to real core lifecycle control, Windows configuration adaptation, authenticated
local API health, active ETag commit, durable last-good rollback and background
monitoring. Downloading or validating a candidate alone does not activate it.
The desktop now has overview, proxies, live connections/traffic, profiles,
readable rules, session activity and settings pages. Authorized display-only
`config.inspect` and `runtime.snapshot` keep candidate/active revisions distinct
and project bounded credential-free data from the owned sing-box API. Theme
selection and automatic refresh are local preferences. Node selection, active
latency testing and Android-style editable local routing groups are not yet implemented.
API health proves local core readiness, not internet reachability or TUN routing.
The current session is unelevated: actual TUN adapter, route and DNS acceptance
requires a separately elevated service. Non-TUN actual-core validation and TUN
acceptance must be recorded separately; this update does not claim either passed.
The remaining sections describe the full target unless explicitly marked as
implemented. See [windows/README.md](../windows/README.md) for current build,
optional core preparation, limitations and smoke-test commands.

Implementation update (2026-10-07): the development preview now requires only
launching `sb-easy.exe`. Its C11 host serializes background startup, verifies and
reuses a running backend, starts a matching installed SCM service if permitted,
or launches the bundled current-user backend without a console window. Refresh
recovers a missing portable backend using the existing DPAPI data directory.
It does not replay enrollment or connection operations, install a privileged
service automatically, or restore an active core connection after a backend crash.
The two-process architecture below remains internal to the application; users
are not expected to start two executables.

Decision date: 2026-08-04

Initial target: Windows 10 22H2 and Windows 11, x64

## 1. Decision

The Windows client will use two processes delivered by one installer:

1. `sb-easy-service.exe`: an auto-start Windows Service that owns enrollment,
   configuration sync, sing-box, Wintun, runtime state, logs, telemetry, and
   local statistics.
2. `sb-easy.exe`: an unelevated desktop and system-tray application that owns
   presentation only and communicates with the service over an ACL-protected
   local named pipe.

Although there are two processes, the product remains one **sb-easy device**.
The control plane must not introduce a separate Windows authorization model or
a separate Windows device collection.

```text
┌──────────────────────────────────────────────────────────────┐
│ User session                                                 │
│                                                              │
│  sb-easy.exe                                                 │
│  Win32 shell + tray + WebView2/Vue UI                        │
└───────────────────────┬──────────────────────────────────────┘
                        │ ACL-protected local named pipe
                        ▼
┌──────────────────────────────────────────────────────────────┐
│ Session 0                                                    │
│                                                              │
│  sb-easy-service.exe                                         │
│  enrollment · sync · rollback · telemetry · local database   │
│             │                    │                           │
│             ▼                    └──────► sb-easy control plane│
│  sing-box.exe (embeds Wintun)                                │
│  local Clash API on 127.0.0.1 with a random secret           │
└──────────────────────────────────────────────────────────────┘
```

## 2. Why not a single process

A TUN client changes machine-wide adapters, routes, and DNS behavior and
therefore needs elevated privileges. A desktop UI belongs to the logged-in
user's session and should not remain elevated. Windows services run in Session
0 and should not directly display interactive UI.

Separating the processes gives the required behavior:

- closing the window or signing out does not interrupt the VPN;
- everyday connect, disconnect, and node-selection actions do not cause UAC
  prompts;
- a UI crash cannot take down sing-box;
- the Service Control Manager can recover the service after a crash;
- device and proxy credentials never need to enter the UI process;
- startup, sleep/resume, and network handover behavior is deterministic;
- uninstall can stop the core and restore networking before removing files.

References:

- [Microsoft: Interactive Services](https://learn.microsoft.com/en-us/windows/win32/services/interactive-services)
- [Microsoft: About Services](https://learn.microsoft.com/en-us/windows/win32/services/about-services)
- [sing-box: TUN inbound](https://sing-box.sagernet.org/configuration/inbound/tun/)

## 3. Product principles

### 3.1 One device and one authorization protocol

Windows uses the existing device protocol:

- the same single-use registration code and `sbeasy://enroll` URI;
- `POST /api/devices/enroll`;
- one long-lived per-device Agent token;
- the existing config, status, command, latency, telemetry, and diagnostic
  endpoints;
- the same Devices page and authorization semantics as Android and native
  agents.

`platform=windows` and capability flags describe technical differences. They
must not become a separate permission system. Server rendering should become
capability-driven, for example `interactive_client` and
`supports_proxy_selection`, instead of treating `platform == android` as the
definition of an interactive client.

### 3.2 The server remains the policy authority

QuickJS executes only on the server. Windows receives the rendered and
validated sing-box configuration. The first release provides readable and
redacted configuration views, but does not edit routing rules locally.

Local settings may adapt platform mechanics such as strict DNS routing, LAN
compatibility, automatic connection, and the private Clash API address. They
must not silently replace central routing policy.

### 3.3 Fail open by default

If sing-box cannot start successfully after repeated recovery attempts, the
service must remove its active TUN routing state and leave ordinary networking
usable. A broken client must not leave the computer offline.

A future opt-in kill-switch may intentionally fail closed, but it is not part
of the initial release.

## 4. Technology selection

### 4.1 Service and platform adapters: native C11

The service, native host, platform adapters and native tests are built as C11
with MSVC and CMake. Windows APIs and COM interfaces are called directly from C.
Shared business logic comes from the current C11 implementation in `c/`; the
Windows build already compiles `c/src/json.c` and its sbj interfaces through a
small Windows utility adapter. The old `cpp/` implementation is a historical
reference only; new behavior and tests are maintained in C. Windows does not
link that runtime or introduce a second JSON library. The current POSIX entry
point cannot be compiled unchanged.

Reusable concepts and code include:

- device enrollment and Agent HTTP contracts;
- ETag configuration synchronization;
- candidate/active/last-good configuration state;
- managed configuration transformation;
- telemetry and per-domain route aggregation;
- route testing and proxy latency models;
- bounded command handling.

Windows-specific adapters are required for:

- service lifecycle and recovery;
- process creation, termination, and Job Objects;
- atomic file replacement and durable flush;
- DPAPI credential encryption;
- WinHTTP transport and Windows certificate validation;
- Winsock and network-change notifications;
- named-pipe IPC and client authorization;
- event log and rolling file logs;
- host metadata, power events, and interface changes.

The current Linux implementation uses `posix_spawn`, `waitpid`, Unix signals,
`chmod`, `uname`, and other POSIX APIs. Those calls should move behind platform
interfaces rather than accumulating large `_WIN32` branches inside
the portable C orchestration code.

### 4.2 UI: Win32 host + WebView2 + Vue

The visible application uses a small native C11 Win32 shell for window,
tray, protocol activation, and WebView2 hosting. Its content will be a dedicated
Vue/Vite client UI bundled as local static assets.

WebView2 is hosted through the SDK's C COM interfaces with explicit reference
counting. The host links the loader import library and packages the matching
`WebView2Loader.dll` beside `sb-easy.exe`; the Evergreen Runtime remains a
separate prerequisite. The native build has no C++ source targets.

This choice provides:

- a modern, Clash Verge-inspired interface without copying its assets;
- reuse of the repository's existing TypeScript, Vue, and visual language;
- significantly less distribution overhead than Qt;
- no Rust/Tauri toolchain;
- no self-contained .NET or Windows App SDK payload;
- straightforward dark/light themes and high-DPI layout.

The WebView must load only packaged resources. A strict Content Security Policy
will deny remote scripts and frames. External documentation links open in the
system browser. JavaScript talks only to the native host bridge, and the native
host talks to the service over the named pipe.

Windows 11 includes the Evergreen WebView2 Runtime and it is present on most
eligible Windows 10 systems. The installer must still detect it and chain the
Evergreen bootstrapper when absent.

Reference: [Microsoft: Evergreen vs. fixed WebView2 Runtime](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/evergreen-vs-fixed-version)

### 4.3 Installer: WiX bootstrapper and MSI

The consumer artifact will be a signed
`sb-easy-windows-setup-x64.exe`. A corresponding MSI may be published for
managed environments.

The installer will:

- request elevation once;
- install binaries beneath `%ProgramFiles%\sb-easy`;
- create and configure the Windows service;
- configure delayed automatic start and service failure actions;
- register the `sbeasy://` protocol handler;
- create Start Menu and optional user-logon shortcuts;
- install WebView2 Evergreen only when missing;
- preserve or remove `%ProgramData%\sb-easy` according to the uninstall choice;
- stop sing-box and verify route cleanup before upgrade or uninstall.

MSIX is not the initial choice because a traditional installer is simpler for
a machine-wide service, TUN support, enterprise deployment, and upgrade
rollback. MSIX can be reconsidered after the Win32 package is stable.

## 5. Process responsibilities

### 5.1 `sb-easy-service.exe`

The service is the only trusted local authority. It owns:

- enrollment and encrypted credentials;
- configuration polling and ETag state;
- candidate validation and last-good rollback;
- the sing-box child process and its runtime files;
- Wintun and machine route lifecycle;
- automatic connection policy;
- private Clash API address and secret;
- proxy selection and latency operations;
- real route tests;
- traffic, connection, route, and domain aggregation;
- service/core logs and diagnostic uploads;
- all calls to the remote control plane.

Implemented: `--console` for development and automated tests, and an SCM entry
point using `StartServiceCtrlDispatcherW`. No installer or service registration
command is added in this increment; production installation and recovery policy
remain work for the installer milestone.

The service initially runs as LocalSystem because sing-box must manage
machine-wide networking. Hardening requirements are:

- an explicit service SID;
- an administrators/System-only install directory;
- a System/administrators-only data directory;
- a minimal `SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO` set after Wintun testing;
- no shell-command or arbitrary-process IPC methods;
- no writable executable or DLL paths for ordinary users.

### 5.2 `sing-box.exe`

The core version is pinned to sing-box 1.13.12. The development archive does not
bundle the core. Its optional `scripts/prepare-core.ps1` downloads the
official Windows x64 archive and verifies a fixed SHA-256 before copying
`sing-box.exe`, `libcronet.dll` and `LICENSE` into the executable directory's
`core/` subdirectory. In a checkout this is `build/windows-release/core/` by
default. Preparation does not execute the core; an already running service must
be restarted to discover it. This upstream executable already embeds Wintun;
it does not require a separate adjacent `wintun.dll`.

The versioned source chain is [sing-box v1.13.12 go.mod](https://github.com/SagerNet/sing-box/blob/v1.13.12/go.mod)
pinning sing-tun v0.8.9, [the amd64 DLL embedding](https://github.com/SagerNet/sing-tun/blob/v0.8.9/internal/wintun/dll_windows_amd64.go),
and [its in-memory DLL loader](https://github.com/SagerNet/sing-tun/blob/v0.8.9/internal/wintun/dll_windows.go).
The future installer must retain the relevant dependency versions and notices,
without adding an unused second Wintun download.

Implemented now: `config.validate` runs `sing-box check -c <private-file>` with
bounded execution and cancellation. The GUI receives a redacted validation
result for the candidate's ETag. Validation does not activate configuration,
start a VPN, or change `active_etag` or `core_running`.
The validation result is cleared on service restart or a changed candidate.

The C process adapter places child processes in a Job Object with
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, assigns the suspended process before resume,
and restricts inherited handles. GUI/IPC start and stop use this adapter. Stop
first requests a bounded graceful shutdown, then uses Job termination if needed.
A forced TUN stop cannot claim DNS/route cleanup; it is reported as degraded.
Core exit or failure of its local API clears active state, even with the UI closed.

Each activation chooses an available `127.0.0.1` port and a cryptographically
random ephemeral secret, replacing server-supplied Clash API settings. Health
checks verify the listener PID before sending an authenticated `/version` request,
disable proxies and redirects, and bound response size and elapsed time. Ports
and secrets are runtime-only and never returned through UI IPC. The API never
binds `0.0.0.0` and does not assume port `9090`.

### 5.3 `sb-easy.exe`

The UI remains unelevated. It owns:

- the application window and navigation;
- the notification-area icon and context menu;
- `sbeasy://` activation forwarding;
- image/clipboard enrollment QR decoding;
- theme, window geometry, and non-sensitive UI preferences;
- presentation of data returned by the service.

Closing the window hides it to the tray by default. “Exit UI” exits only the UI.
Disconnecting the VPN is an explicit separate action.

## 6. Local IPC contract

Pipe name: `\\.\pipe\sb-easy-control-v1`

Transport:

- duplex named pipe;
- 32-bit little-endian message length followed by UTF-8 JSON;
- maximum request and response size of 1 MiB unless a method defines a lower
  limit;
- request IDs for correlation;
- explicit protocol version negotiation;
- request/response status polling; bounded status/traffic/log subscriptions remain future work.

Example request:

```json
{
  "id": "10",
  "version": 1,
  "method": "connection.start",
  "params": {}
}
```

Example response:

```json
{
  "id": "10",
  "ok": true,
  "result": {
    "phase": "RUNNING",
    "core_running": true
  }
}
```

Implemented methods:

| Category | Methods |
| --- | --- |
| Protocol | `protocol.hello` |
| Enrollment | `enrollment.status`, `enrollment.apply`, `enrollment.forget` |
| Runtime | `status.get`, `connection.start`, `connection.stop` |
| Sync | `config.refresh`, `config.summary`, `config.validate` |

Further target methods (not implemented by the current preview):

| Category | Methods |
| --- | --- |
| Sync | `config.redacted` |
| Proxies | `proxies.list`, `proxy.select`, `proxies.test` |
| Routing | `route.test`, `routes.stats` |
| Logs | `logs.tail`, `logs.clear`, `logs.export`, `logs.upload` |
| Settings | `settings.get`, `settings.update` |
| Events | `events.subscribe`, `events.unsubscribe` |

The pipe DACL permits System, administrators, and local interactive users and
explicitly denies the Network SID. Sensitive mutations impersonate the pipe
client and inspect its actual token, requiring either the active console session or an
administrator. No method returns the Agent token, proxy passwords, UUIDs, or
the unredacted generated configuration.

References:

- [Microsoft: Named Pipe security and access rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [Microsoft: DPAPI `CryptProtectData`](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)

## 7. Local storage

Implemented service-owned state (console mode uses
`%LocalAppData%\sb-easy\dev-service` instead):

```text
%ProgramData%\sb-easy\
├── device-state.dat            DPAPI identity + candidate + last-good envelope
├── state.lock                  exclusive service state owner
└── core-work\
    ├── state.lock              exclusive private runtime directory owner
    └── core-<32hex>.json       temporary check/run configuration, removed on stop
```

UI-owned state:

```text
%LocalAppData%\sb-easy\
├── ui-settings.json
└── WebView2\
```

`device-state.dat` is encrypted by DPAPI under the service identity. Filesystem
owners and ACLs are checked, ancestors are pinned, reparse points are rejected,
and updates use flushed atomic replacement. Runtime configurations contain proxy
credentials and receive the same restricted directory ACL. Normal completion
removes them. A hard service termination closes the Job and kills the child tree;
owned `core-<32hex>.json` remnants are removed safely at the next startup and
remain ACL-protected until then. Active state and API secrets are not restored
as a running connection after restart. Cache databases, telemetry and rotating
log files shown elsewhere in this design remain future work.

## 8. Runtime state and recovery

The service exposes this state machine:

```text
UNENROLLED
    │ enroll
    ▼
STOPPED ── start ──► STARTING ── healthy ──► RUNNING
   ▲                     │                       │
   │                     │ failure               │ config/network change
   │                     ▼                       ▼
   └─────────────── ERROR/DEGRADED ◄────── ROLLING_BACK
```

Implemented configuration activation:

1. Download a candidate with `If-None-Match`.
2. Apply bounded Windows-specific local transformations.
3. Run `sing-box check` against the candidate.
4. Keep a healthy old process running if candidate adaptation or checking fails.
5. Stop the old process and start sing-box with private adapted configuration.
6. Require process existence and its authenticated local Clash API within a deadline.
7. Persist last-good atomically, then publish `RUNNING` and `active_etag`.
8. On activation or durable-commit failure, attempt the previous last-good if safe;
   otherwise report `DEGRADED` without an active ETag.

`downloaded_etag` can differ from `active_etag`; refresh alone never switches the
running process. A successful rollback publishes the restored ETag and a
`ROLLED_BACK` notice. Normal stop clears active state but keeps last-good. An
observed crash or failed API probe also clears active state and reports an error.
The monitor runs independently of the UI. No automatic reconnect/backoff is
implemented yet. The service restarts in `STOPPED`, retaining credentials,
candidate and last-good but requiring a new explicit start.

`RUNNING` means the local process/API checks passed, not that internet access,
DNS leakage, proxy reachability or actual TUN routes have been tested. A non-TUN
Profile remains a local proxy. `tun_active` additionally requires a TUN with the
server's `auto_route:true`; `auto_route:false` is preserved.

Further target failure policy (not a current recovery guarantee):

- restart sing-box with bounded exponential backoff;
- let the Service Control Manager restart the service after a service crash;
- after three consecutive core failures in sixty seconds, stop the core, clean
  the known TUN state, enter `DEGRADED`, and leave ordinary networking usable;
- retain sufficient redacted diagnostics for the user to upload.

Further target network-event handling:

- subscribe to interface, address, route, power suspend, and resume events;
- debounce changes before rebuilding the core;
- keep the control-plane address and proxy server connections out of the TUN
  loop;
- verify connectivity after Wi-Fi/Ethernet/mobile-hotspot transitions;
- never depend on a fixed physical interface name.

## 9. Windows routing defaults

Implemented adaptation preserves the candidate's `auto_route` value and supports
at most one TUN. The interface name defaults to `sb-easy`; an explicit name must
contain 1–48 ASCII letters, digits, `_` or `-`. Linux TUN/dialer options are removed,
`route.auto_detect_interface` is enabled, and control-plane/service/core direct
rules precede server rules. HTTP/SOCKS/mixed listeners are restricted to loopback.
No TUN is added to a Profile which does not contain one.

The initial adapter rejects multiple TUNs, platform hooks, endpoints, services,
local rule-set and hosts files, certificate/key/ECH paths, ACME and executable
plugins. It replaces external Clash/UI/cache/debug settings, disables file logs
and NTP, and retains remote rule-set downloads. WireGuard endpoint profiles and
other rejected configurations need explicit support rather than silently losing
their semantics. The field contract is pinned to sing-box 1.13.12, not newer
online documentation. Actual adapter/route/DNS recovery needs elevated tests.

Target routing defaults for centrally managed Windows Profiles:

- TUN `auto_route` enabled only when selected in the central policy;
- central private/CN domain and IP rules remain direct;
- LAN access enabled;
- multicast and local discovery traffic preserved where possible;
- control-plane endpoints explicitly protected from the proxy loop;
- automatic interface detection enabled;
- strict DNS leak prevention exposed as a visible compatibility toggle;
- no kill switch by default.

sing-box documents that `strict_route` prevents Windows multihomed DNS leakage,
but may interfere with applications such as VirtualBox. The UI must explain the
trade-off and must not hide it behind raw JSON.

The platform adapter should avoid broad route exclusions that bypass sing-box
entirely because doing so also bypasses route telemetry and central policy.
Exceptions should be narrow and evidence-driven.

## 10. Local observability

The Windows client will record route results locally instead of relying only on
server telemetry.

`runtime.db` stores daily aggregate rows keyed by:

- date;
- normalized domain or destination;
- final outbound and outbound type;
- selector chain;
- matched rule and payload.

Each row stores connection count, uplink/downlink bytes, first seen, and last
seen. Initial retention is 90 days with a bounded row count. Configuration
activation starts a new policy generation so observations from different rule
sets are not silently merged.

The server continues receiving its existing bounded aggregate telemetry. Raw
connection history is not uploaded automatically.

Logs must:

- rotate by size and count;
- redact Agent tokens, enrollment codes, proxy passwords, UUID credentials,
  and URL query strings;
- include network transitions, service/core lifecycle, config version, rollback
  reason, and local API health;
- support explicit export and explicit diagnostic upload.

## 11. UI information architecture

### 11.1 Dashboard

- prominent connect/disconnect control;
- current state and useful error recovery action;
- current Profile, config version, rule source, and last sync;
- live upload/download rate and totals;
- current proxy selection and latency;
- service and sing-box versions.

### 11.2 Proxies

- selector/urltest groups rather than a flat, misleading node list;
- live selected node;
- per-node latency and progressive group test;
- manual selection with visible confirmation from the running core;
- persistence across service/core restarts.

### 11.3 Routing

- real HTTP/HTTPS URL test correlated with the sing-box connection event;
- final direct/proxy/block result;
- selector chain and matched rule;
- local domain statistics with search and filters;
- today, seven-day, and all-time summaries.

### 11.4 Runtime configuration

- readable DNS, TUN, rule, rule-set, outbound, and selector sections;
- a visible QuickJS badge and explanation when rules came from server-side
  QuickJS;
- redacted JSON mode as an advanced view;
- no local policy editor in the first release.

### 11.5 Logs

- separate service and sing-box sources;
- severity and text filtering;
- copy/export/clear;
- explicit “Upload diagnostics” action and upload receipt.

### 11.6 Settings

- connect at boot;
- launch UI at user logon;
- minimize/close-to-tray behavior;
- LAN compatibility;
- strict DNS leak prevention;
- log retention;
- update notification;
- device information and forget/re-enroll action.

Visual requirements:

- original sb-easy branding with a restrained Clash Verge-inspired layout;
- native-feeling Fluent spacing, typography, motion, and controls;
- light and dark themes following Windows by default;
- correct 100%, 125%, 150%, and 200% DPI behavior;
- usable minimum window size and responsive wide layouts;
- keyboard navigation and visible focus states;
- no browser chrome, remote page navigation, or basic-auth dialog.

## 12. Enrollment UX

Supported entry paths:

1. Click a `sbeasy://enroll?...` link in the management UI.
2. Paste a registration link or enrollment code.
3. Paste a QR screenshot from the clipboard.
4. Choose a QR image from disk.

The UI parses and previews only the server origin and one-time code. The service
performs the actual enrollment and stores the returned credential. Registration
codes are never written to logs or persisted after redemption.

The control plane should receive capability metadata similar to:

```json
{
  "platform": "windows",
  "architecture": "x86_64",
  "interactive_client": true,
  "supports_proxy_selection": true,
  "supports_local_route_stats": true,
  "supports_diagnostic_upload": true
}
```

## 13. Repository layout and remaining extraction

```text
windows/
├── CMakeLists.txt
├── README.md
├── common.c / common.h       # Windows utilities for shared c/src/json.c
├── runtime/
│   └── state.c / state.h
├── service/
│   ├── service_main.c
│   ├── controller.c / controller.h
│   ├── core_process.c / core_process.h
│   ├── runtime_config.c / runtime_config.h
│   ├── control_plane.c / control_plane.h
│   ├── secure_store.c / secure_store.h
│   ├── protocol.c / protocol.h
│   └── pipe_server.c / pipe_server.h
├── ui-host/
│   ├── main.c
│   ├── webview_guids.c
│   ├── server_identity.c / server_identity.h
│   └── pipe_client.c / pipe_client.h
├── ui/
│   ├── package.json
│   └── src/
├── scripts/
│   ├── build.ps1
│   ├── prepare-core.ps1
│   ├── smoke.ps1
│   ├── enrollment-smoke.ps1
│   └── connection-smoke.ps1
├── tests/                   # C11 native tests and local fixtures
└── licenses/
```

The WiX installer directory, network-change handling and elevated networking
acceptance remain future work.

Portable agent orchestration should be extracted from the current C11 tree,
for example (these production-loop extractions remain future work):

```text
c/include/sb/agent_runtime.h
c/include/sb/platform_process.h
c/include/sb/platform_storage.h
c/src/agent_runtime.c
c/src/platform/posix_*.c
```

The exact filenames may change during implementation, but the boundary between
portable policy/orchestration and operating-system mechanics is mandatory.
The initial `windows/runtime/state.c` module establishes a small OS-independent
test boundary; it does not yet replace or extract the Linux Agent loop.

## 14. Build and dependency policy

Windows build prerequisites:

- Visual Studio 2022 Build Tools with MSVC C11 and Windows SDK support (the
  installer labels these components as C++ tools);
- CMake 3.24 or newer;
- Ninja or the Visual Studio CMake generator;
- Node.js 22 LTS or a compatible version >=20.19 for the UI;
- WebView2 SDK restored from a pinned package version and SHA-256;
- WebView2 Evergreen Runtime for the GUI and actual GUI smoke tests.

WiX is not required for this development preview; pin it at project level when
implementing the installer. The native project uses `LANGUAGES C`, C11 and
`/W4 /WX`. Ordinary CI uses local test doubles and does not download sing-box.
Its archive includes `WebView2Loader.dll`, packaged UI/licenses and
`scripts/prepare-core.ps1`, while the core remains an optional direct upstream
download. `enrollment-smoke.ps1 -ValidateCore` exercises actual-core checking;
`-ConnectCore` exercises non-TUN start/stop through the GUI.
`connection-smoke.ps1` separately exercises actual-core loopback SOCKS forwarding
and stop. Its optional elevated `-Tun` mode checks a unique adapter and isolated
`198.18.255.0/30` route; it does not certify full routing, internet access or DNS
recovery. The current unelevated session cannot perform that TUN acceptance.

Third-party artifacts must be version- and checksum-pinned. The build must not
download an unversioned “latest” sing-box or Wintun binary.

The release must contain:

- the signed setup executable;
- SHA-256 checksums;
- third-party notices and licenses;
- the exact corresponding sing-box source archive required by GPL-3.0-or-later;
- reproducible version metadata for the bundled sing-box and Wintun artifacts.

The production installer and executables require Authenticode signing. Internal
development builds may use a documented test certificate, but unsigned builds
must not be presented as production-ready because SmartScreen will warn users.

## 15. Implementation work packages

### W1 — portable runtime boundary

- extract the agent state machine from the POSIX `main`;
- define process, storage, clock, HTTP, and platform metadata interfaces;
- retain Linux behavior and tests;
- add capability-driven interactive-client rendering on the server.

Exit condition: Linux agent tests remain green and the portable runtime can run
against test doubles without POSIX headers.

### W2 — headless Windows Service

- implement Service Control Manager integration and `--console` mode;
- implement DPAPI storage, atomic config files, WinHTTP, process supervision,
  Job Objects, logs, and the named-pipe server;
- bundle and start sing-box/Wintun;
- support enrollment, sync, start/stop, rollback, status, and telemetry.

Exit condition: a fresh Windows VM can enroll and maintain a working TUN without
the UI process.

### W3 — desktop shell and UI

- build the WebView2 shell, tray, protocol activation, and IPC bridge;
- implement all six pages;
- implement effective proxy selection, route tests, local route statistics,
  redacted config, and diagnostic upload;
- implement QR image and clipboard enrollment.

Exit condition: all user workflows can be completed without editing files or
running a terminal.

### W4 — installer and lifecycle hardening

- build WiX bootstrapper/MSI;
- configure service recovery and upgrades;
- install WebView2 when missing;
- verify install, repair, upgrade, uninstall, and optional data cleanup;
- add signed-release and license assets.

Exit condition: installation and uninstall leave no running process, captured
default route, DNS override, or inaccessible network adapter.

### W5 — release validation

- automated Windows build and unit/integration tests in GitHub Actions;
- Windows 10 22H2 and Windows 11 x64 VM acceptance passes;
- Wi-Fi/Ethernet/hotspot, sleep/resume, core crash, service crash, invalid
  config, occupied local port, and unreachable control-plane scenarios;
- GitHub Release publication and management-panel download link.

Exit condition: all acceptance criteria below pass with a signed installer.

## 16. Acceptance criteria

The first Windows release is complete only when all of the following are true:

- one installer produces one visible sb-easy application and one background
  service;
- installation is the only normal workflow requiring UAC;
- Windows enrolls through the same Devices flow as Android and native agents;
- closing the UI does not stop an active connection;
- reboot with “connect at boot” enabled restores the connection without login;
- invalid configuration cannot overwrite the last working configuration;
- repeated core failures restore normal networking instead of leaving the PC
  offline;
- control-plane access remains possible while the TUN is active;
- LAN access works with the default managed routing policy;
- no component binds a Clash controller to `0.0.0.0` or assumes port `9090`;
- proxy latency testing and manual node selection affect the running core and
  survive restart;
- URL route tests report the actual final rule and outbound chain;
- domain route statistics remain visible locally across UI and service restarts;
- QuickJS-derived rules are clearly visible in the readable config view;
- logs can be exported and explicitly uploaded with secrets redacted;
- Wi-Fi/Ethernet changes and sleep/resume do not require reinstall or re-enroll;
- uninstall restores ordinary routes and DNS and removes the service;
- credentials and unredacted proxy configuration cannot be read through the UI
  IPC contract;
- the layout works at supported Windows DPI settings and remains usable at its
  documented minimum window size.

## 17. Deferred work

The following are intentionally outside the first release:

- Windows 7/8 support;
- x86 builds;
- ARM64 until x64 is stable;
- local editing of central routing or QuickJS rules;
- per-application split tunneling;
- a default fail-closed kill switch;
- Microsoft Store publication;
- unattended self-update before an Authenticode signing and rollback chain is
  established.

Update notification may open the GitHub Release page in the first version.
Automatic signed updates can be added after the installer and rollback model is
proven.
