# sb-easy Windows development preview

## 0.7.0 unsigned development preview

The application version comes from `development.windows.version` in
[`config/client-releases.json`](../config/client-releases.json); the core version
comes from [`config/runtime-versions.json`](../config/runtime-versions.json).
The current source builds application **0.7.0** with sing-box **1.14.3**. Unsigned
development binaries report `0.7.0-dev`; their ZIP/MSI filenames use `0.7.0` and
their numeric PE version is `0.7.0.0`. Packaging rejects stale or mixed identities.
The private UI package's npm metadata is not the application version: the UI
displays the version reported by its connected service.

The [1.1.0 development preview](https://github.com/cloudy064/sb-easy/releases/tag/v1.1.0-preview.1) provides **0.7.0 unsigned ZIP/MSI**
packages with sing-box **1.14.3**, built and tested on the native GitHub Windows
runner. Publisher signing and full desktop/network/driver acceptance remain
pending; the preview is not a production-trusted updater release.
The signed updater and signed extension catalog require 0.7.0 or later; install
the first trusted updater-capable build manually when it becomes available.

### HTTP(S) debugging extension

The extension store now offers a local mitmproxy-based HTTP(S) debugging plugin:
read decrypted request/response bodies, edit/replay requests, use breakpoints,
and export HAR. Install the optional engine, explicitly trust its per-device CA,
then choose domain suffixes to capture. Stopping/disabling restores normal
routing. Raw PCAP capture remains a separate network-diagnostics tool.
See [setup, build instructions and limits](../extensions/http-debug/README.md).
The base installer does not contain the Python engine or automatically install a CA.

This is an executable Windows development preview with real core connection control.
It connects a packaged Vue UI in an unelevated Win32/WebView2 window to a real
local service over an ACL-protected named pipe. Starting a TUN configuration can
change network adapters, routes and DNS; downloading or validating one does not.
This is not a completed or signed VPN release.

## Implemented

- Independent mode imports subscriptions without center enrollment. URL and
  offline JSON/YAML/URI/Base64 imports are parsed by the C service and return a
  redacted compatibility report. Local subscription IDs remain stable on
  refresh; failed downloads, parsing or configuration checks preserve saved nodes.
  URL imports support 15-minute to seven-day refresh intervals or manual refresh,
  including with the desktop window closed. Traffic quota and expiry come only
  from a valid `Subscription-Userinfo` header; absent values remain unknown.
  Mode switching requires a stopped connection and preserves both profiles in
  the protected store. Independent mode never sends center heartbeats or commands.
- The background service polls managed configuration with ETags, reports status,
  optionally reports aggregate traffic, and acknowledges center reload/restart
  commands with durable receipts. New configuration is checked, activated and
  health-checked before replacing the known-good source and local policy.
  Manual disconnect persists across restarts. Optional boot connection and
  bounded recovery handle core exits, physical-interface changes and resume.
  The default boot-connection setting is off; closing the UI does not stop work.
- Local custom routing groups support domain suffixes and Windows process names,
  with validated default/node choices and DNS detours. Diagnostics can request
  live core delay tests and actual proxy-routed HTTP(S) URL probes. Probe results
  distinguish response success from observed core connection/rule evidence;
  unavailable DNS or public-exit-IP observations are labeled unobserved.

- Windows accepts managed WireGuard endpoints using sing-box's userspace engine,
  preserves per-device keys/peers and the server's intranet route, and includes
  endpoints in the node catalog without exposing keys. The center device must
  have `capabilities.embedded_wireguard=true`; older center enrollment handlers
  do not infer this from `platform=windows`. Enabling it on the correct host
  causes the next config fetch to provision its own peer. No separate Windows
  WireGuard service is needed. Unknown endpoint types remain unsupported.

- Service Routing supports persisted local exit choices for the default route,
  GPT/Codex, Claude, and other supported domain groups discovered in the center
  configuration. The service preserves the downloaded snapshot and ETag, then
  overlays route and DNS choices during validation and startup. A dedicated DNS
  clone prevents an override from changing other services sharing that resolver.
  Runtime selectors can change exits through the authenticated Clash API without
  restarting the core or TUN; existing connections retain their previous exit.
  Failed durable saves restore the previous live selection. Missing selected
  nodes and unsupported rule/DNS shapes are rejected instead of silently changing
  exits. Custom local groups can be added, edited and removed from the desktop.
  These are manual exit preferences; automatic failover is not provided by this UI.

- The 0.4.4 diagnostic test build captures sing-box debug output through a C11
  pipe reader, filters credentials before disk writes, and retains four 4 MiB
  logs in the protected `core-work` directory. Service operation results and
  forced/graceful stop details are timestamped alongside core DNS/routing errors.
  The tray's **Export diagnostics (offline)** command (Chinese UI), or packaged
  `Export-Diagnostics.cmd`, saves a ZIP on the desktop with these logs, projected
  service status, adapters, routes, DNS settings/cache and relevant TCP sockets.
  Export while the failure is present, before switching to another proxy.
  Domain/IP/node names remain; raw configurations and encrypted device state
  are excluded. No upload occurs. Log capture continues with the GUI closed.

- Registration immediately downloads the latest candidate in the same GUI flow.
  A download failure leaves the completed registration intact and offers sync
  retry, without exchanging the one-time enrollment code again.
- Cold starts with remote rule sets allow 25 seconds for readiness, and use a
  service-owned rule cache for subsequent starts. Connection-start IPC has a
  bounded 90-second deadline covering validation, startup, cleanup and rollback;
  other requests retain their existing limits. Service shutdown allows five
  seconds, including a graceful interval before bounded Job termination.
- User actions wait for an in-progress background health/snapshot read instead
  of intermittently returning `BUSY`; overlapping user mutations remain rejected.
- Pure C11 service, Win32 host, platform adapters and native tests, built with MSVC.
  The frontend remains Vue/TypeScript. JSON uses the existing `c/` sbj implementation;
  WebView2 uses C COM interfaces and the packaged dynamic `WebView2Loader.dll`.
- C11 state transitions without OS headers or I/O.
- Windows Service Control Manager entry point and `--console` development mode.
- x64 MSI installer alongside the portable ZIP: automatic LocalSystem service,
  Start menu/desktop shortcuts, repair, major upgrades with rollback and downgrade
  prevention. Uninstall stops/removes the service and preserves device data.
- One desktop entry: automatically reuse a verified backend, start a matching
  installed Windows service, or launch the bundled backend invisibly for the
  current user. Refresh can recover a stopped portable backend. Concurrent starts
  are serialized; enrollment and other state-changing requests are never replayed.
- Local-only, bounded, cancellable named-pipe transport, service-process identity
  verification and authorization of mutations for admins/the active console session.
- Strict `sbeasy://enroll` parsing, WinHTTP enrollment and authenticated configuration
  download through the existing Devices API, including URL path prefixes and ETag 304.
- DPAPI-encrypted device identity, candidate and last-good configuration, restricted filesystem
  ACLs, atomic replacement, one writer per data directory and recovery after restart.
- Candidate validation through a separately prepared sing-box 1.14.3 executable's
  real `check` command, with a deadline, cancellation and private temporary files.
- Real `connection.start`/`connection.stop` from the GUI through the service to the
  pinned core, Windows runtime adaptation, authenticated local API health checks,
  active ETag commit, last-good rollback and monitoring while the GUI is closed.
- Job Object process supervision, bounded graceful stop with forced termination
  fallback, cancellation and cleanup of private temporary configurations.
- Packaged WebView2 UI, system light/dark theme, real service availability,
  registration, candidate summary, connection diagnostics, close-to-tray and UI exit.
- Desktop dashboard with overview, proxies, connections, profiles, rules, activity
  and settings pages. Light/dark/system theme and automatic refresh preferences
  persist locally; the bounded activity timeline stays in UI memory only.
- Authorized `config.inspect` returns separate candidate/active display catalogs;
  `runtime.snapshot` reads real core connections, totals, proxy groups and existing
  delay history. The C service pins the API listener to its owned process before
  sending the private secret. No raw config, proxy credentials or local API secret
  are passed to WebView2. The UI derives rates from timed counter differences.
- Native state/protocol/pipe/HTTP/controller/storage/identity/core tests, frontend tests,
  Windows CI and actual WebView2-to-service screenshot smoke tests.

After enrollment the service reports `STOPPED`. Downloaded configurations remain
candidates even after a successful core check. **启动连接** adapts and checks the
candidate, starts the core, verifies that its authenticated `127.0.0.1` API belongs
to that process, and only then commits `RUNNING`, `active_etag` and durable
`last_good_etag`. A rejected candidate leaves an existing connection running.
An activation failure can restore last-good; a stop or observed crash clears the
active ETag. Restarting the service restores credentials and saved candidates,
but starts disconnected. Downloading a newer candidate does not switch the live core.

Local API health is not an internet reachability test. A configuration without
TUN remains a local proxy configuration. A TUN with `auto_route:false` keeps that
value; the adapter never silently enables global routing. TUN operation needs an
elevated service process, while the desktop stays unelevated. The 2026-10-05 development
validation session is not elevated, so actual TUN adapter/route/DNS acceptance remains pending.

Local verification on 2026-10-07: MSVC C11 Release with `/W4 /WX`, all 12 native
test groups and 33 frontend tests passed. The WebView2 enrollment/restart smoke
exercised desktop-only hidden backend startup, real-core validation, connection
and disconnection, and DPAPI recovery after backend restart. Startup tests also
covered concurrent starts, reuse, cancellation and rejection of an impostor.
A separate real
sing-box test forwarded HTTP through its SOCKS listener, verified graceful exit
(`stop_forced=false`) and listener closure, and rejected an unelevated TUN start.
These local checks do not replace elevated TUN acceptance or the Linux CI
regression runs for the server-side C changes.

Additional 0.4.4 validation: automatic post-registration download through the real
GUI; an eight-second delayed remote rule-set fixture; real Wintun creation and
cleanup with only an isolated /30 route; and the installed candidate under
LocalSystem with global route/DNS takeover disabled for diagnosis. The original
three-second readiness deadline reproduced `TUN_FORCE_STOPPED`; the revised
startup reached `RUNNING`. Full global route/DNS takeover remains a separate test.

## Build

Install Visual Studio 2022 Build Tools with these components:

- `Microsoft.VisualStudio.Workload.VCTools`
- `Microsoft.VisualStudio.Component.VC.Tools.x86.x64`
- `Microsoft.VisualStudio.Component.Windows11SDK.26100`
- `Microsoft.VisualStudio.Component.VC.CMake.Project`

The Visual Studio component names use “C++”; this project compiles its native
sources and tests as C11.

Also install PowerShell 7, Node.js 22 LTS or a compatible version >=20.19,
Python 3.10 or newer, and the OpenSSL CLI. `python` (or `python3`) and `openssl`
must run from PATH. The build checks both tools before invoking CMake; Python
and OpenSSL generate isolated test signatures for the native plugin storage and
sandbox tests. They are build dependencies and are not required by the base
desktop application.

Install WebView2 Evergreen Runtime to run the desktop. The SDK is restored
automatically at its pinned version; the Runtime is not pinned or bundled.

From a normal PowerShell at the repository root:

```powershell
./windows/scripts/build.ps1
./windows/scripts/smoke.ps1
./windows/scripts/enrollment-smoke.ps1
```

The build script initializes the x64 developer environment, restores locked
frontend dependencies, tests and builds the UI, then uses CMake/Ninja to build
and test the native targets. Files are written to `build/windows-release/`.
`-Configuration Debug` selects a separate debug build. Use `-SkipUi` only after
building the UI, for native-only iterations.
`-Clean` rebuilds all native objects, useful after changing compiler language/settings.

Core preparation is optional for building, testing, registration and config download.
To enable the GUI's **校验配置** and **启动连接** operations, prepare the pinned core before starting
the service:

```powershell
./windows/scripts/prepare-core.ps1
./windows/scripts/enrollment-smoke.ps1 -ValidateCore
./windows/scripts/enrollment-smoke.ps1 -ConnectCore
./windows/scripts/connection-smoke.ps1
./windows/scripts/connection-smoke.ps1 -Dashboard
```

The preparation script reads `config/runtime-versions.json` (or the packaged
`runtime-versions.json`) and downloads the pinned official Windows x64 sing-box
1.14.3 archive,
verifies its fixed SHA-256 and copies `sing-box.exe`, `libcronet.dll` and `LICENSE`
to `build/windows-release/core/`. Use `-Configuration Debug` for the debug output.
It does not launch the core. Restart an already running service after preparation.

This official core embeds Wintun through the pinned sing-tun revision; it does not require an
adjacent `wintun.dll` download. The pinned dependency and embedded amd64 bytes are
documented in [sing-box v1.14.3 go.mod](https://github.com/SagerNet/sing-box/blob/v1.14.3/go.mod),
[sing-tun's amd64 embedding](https://github.com/SagerNet/sing-tun/blob/bca4bf029237/internal/wintun/dll_windows_amd64.go)
and [its in-memory loader](https://github.com/SagerNet/sing-tun/blob/bca4bf029237/internal/wintun/dll_windows.go).
Preparation does not create an adapter or install a service.

To create a portable development archive after building:

```powershell
./windows/scripts/package.ps1
```

This writes `build/sb-easy-0.7.0-windows-x64-portable.zip` and prints its
SHA-256. An explicit file list includes the desktop, service, loader, UI, notices
and preparation script; an optional core already present in the build directory
is not included unless `-IncludeCore` is supplied. That switch verifies and
extracts the pinned upstream core again; it never trusts an arbitrary core binary
left in the build directory. The native C runtime is statically linked (`/MT` in
Release), so the desktop and service need no separate VC runtime installation.

### MSI and portable packages

Install .NET SDK 8 for the **build machine only**, then run:

```powershell
$env:DOTNET_ROLL_FORWARD = 'Major'
dotnet tool install wix --version 5.0.2 --tool-path build/wix
./build/wix/wix.exe extension add -g WixToolset.UI.wixext/5.0.2
./windows/scripts/package.ps1 -Msi -IncludeCore -WixPath ./build/wix/wix.exe
```

This produces both `build/sb-easy-0.7.0-windows-x64.msi` and the portable ZIP
above, from the same staged payload, with sing-box and its license included.
Omit `-IncludeCore` for lightweight packages. MSI requires the machine-wide
[WebView2 Evergreen Runtime](https://go.microsoft.com/fwlink/p/?LinkId=2124703);
setup gives a prerequisite error if it is missing. The application requires
64-bit Windows 10 or later. These are unsigned development packages.

Double-click the MSI and accept the administrator prompt. It installs under
`C:\Program Files\sb-easy`, registers and starts the `sb-easy` LocalSystem service,
and adds Start menu and desktop shortcuts. Open the desktop normally; no second
service launch or elevated desktop is required. Setup does **not** connect the VPN.
Service startup after reboot also remains disconnected until the user connects.

Before switching from portable, disconnect and exit the portable UI and stop its
background process. A conflicting running backend makes installation fail and
roll back rather than taking over that process. Portable device data is encrypted
for the current user; the installed service uses its own DPAPI identity and
`%ProgramData%\sb-easy`. Register the installed edition again; do not copy encrypted
portable state into the service store. Launch from the installed shortcut after
installation, since a portable executable from another directory is deliberately
rejected by service identity verification.

Windows Settings → Apps can repair/remove the MSI. A later MSI with a higher
three-part version upgrades in place, stops the old service and starts the new
one. Downgrades are rejected. Uninstall stops the core, removes packaged files,
service and shortcuts, but retains `%ProgramData%\sb-easy` and the user's UI
preferences. Use **忘记设备** before uninstall to clear locally stored registration.

For a quiet installation/removal with logs, from an administrator terminal:

```powershell
msiexec /i "build\sb-easy-0.7.0-windows-x64.msi" /qn /norestart /l*v install.log
msiexec /x "build\sb-easy-0.7.0-windows-x64.msi" /qn /norestart /l*v uninstall.log
```

`scripts/installer-smoke.ps1 -Msi <new.msi> -PreviousMsi <older.msi>` exercises
install, upgrade, missing-file repair, downgrade rejection, real service IPC and
uninstall/data retention. Run elevated on a disposable clean Windows machine;
it refuses an existing service, app, device store or running backend. CI builds
a 0.3.99 test baseline from the same payload and runs this lifecycle test. That
baseline is a test fixture, not a release. Actual elevated TUN route/DNS acceptance
is separate from installer testing.

## Run

Launch only the desktop, either by double-clicking it or running:

```powershell
./build/windows-release/sb-easy.exe
```

Closing the window hides it to the tray. The tray menu's **退出界面** exits the
desktop only. The desktop automatically starts the bundled backend in the
background if needed and reuses it on subsequent launches. You do not need a
second terminal or to run `sb-easy-service.exe` yourself. Background operation
continues after the UI exits; use **断开连接** to stop an active core connection.
If a portable backend exits, reopening the UI or refreshing its status starts
it again and restores the existing device registration; it does not reconnect
the core automatically. Missing files, mismatched installed services and failed
startup have distinct messages in the UI.
Enrollment, configuration validation and non-TUN local proxy operation can be
evaluated without elevation. TUN startup returns `CORE_ELEVATION_REQUIRED` from
an unelevated backend. The desktop also queries and starts a matching installed
SCM service when permitted, without launching a second portable backend. A stopped
installed service that denies start permission reports the required elevation.
The MSI installs that elevated service automatically. Portable operation still
uses the current user's permissions. Production code signing remains pending.

For a downloaded CI/development archive, keep both executables,
`WebView2Loader.dll`, `ui/`, `licenses/` and `scripts/` together. The archive does
includes sing-box only when built with `-IncludeCore`. For a lightweight archive, prepare the core,
then double-click `sb-easy.exe`:

```powershell
./scripts/prepare-core.ps1 # optional; installs the checked download into ./core/
./sb-easy.exe
```

The native executables require Microsoft's x64 Visual C++ Redistributable
(`VCRUNTIME140.dll` and the Universal C Runtime). This is the runtime package
name used for MSVC-built C binaries; the native application sources are C11.

Paste a registration URI issued by the management panel into the desktop. The
desktop previews the destination and warns for HTTP. The one-time registration
code is cleared on submission; enrollment is never retried automatically. Use
**下载最新配置** to download a candidate, then **校验配置** to check it with the prepared
local core. A successful check marks that revision as valid but leaves it inactive.
Use **启动连接** to activate it, **应用新配置** to switch a running instance to a newly
downloaded candidate, and **断开连接** to stop it. Activation commits the version only
after process and authenticated local API health checks. A failed replacement can
report `ROLLED_BACK` while the previous last-good revision is running.
The check result is reset on service restart or a changed candidate; rerun it before
relying on the displayed revision. **忘记此设备** removes this stopped device's local
identity and candidate after an inline confirmation; it does not revoke the device
on the management panel. A new enrollment needs a new registration code.

Console data defaults to `%LOCALAPPDATA%\sb-easy\dev-service`; SCM mode uses
`%ProgramData%\sb-easy`. `--data-dir <path>` is available only in console mode.
The automatically launched portable backend uses the same current-user console
directory, preserving existing registration. For developer diagnostics only,
`sb-easy-service.exe --console` remains available; Ctrl+C stops that console instance.
DPAPI binds stored credentials to the Windows account running the service: console
development data cannot be copied into a LocalSystem installation. The service
refuses damaged state rather than silently overwriting it or registering again.
Core checks and running instances use temporary plaintext configuration files inside a restricted,
locked work directory. Normal completion removes them; if the service is forcibly
terminated, the Job Object ends its child processes and the next startup safely
removes matching owned temporary files. Residual files remain ACL-protected until
that startup.

`smoke.ps1` starts isolated hidden processes with a random local pipe/data directory,
verifies real UI requests, captures the rendered WebView2 to
`build/windows-smoke-*/desktop.png`, checks the 760px window for horizontal
overflow, then stops its service and verifies the offline UI. It stops only
the processes it created. This check requires an available WebView2 Runtime.
`startup-smoke.ps1` launches only the desktop with an isolated test pipe and state,
checks that it starts the real hidden backend, verifies a second UI reuses the
same PID, and verifies recovery after that backend exits. All screenshots and
count-only receipts stay under `build/windows-startup-smoke-*/`. Test-only custom
pipes do not start a backend unless explicitly opted in, preserving offline tests.

`enrollment-smoke.ps1` also starts a loopback-only HTTP fixture with synthetic
credentials. It fills the actual GUI registration form, downloads a candidate,
terminates/restarts its isolated service, restores the persisted state and verifies
a conditional refresh receives HTTP 304. Screenshots and count-only receipts are
saved under `build/windows-enrollment-smoke-*/`. It does not use a production panel.
With `-ValidateCore`, it also requests an actual core check through the GUI and
verifies that the candidate stays inactive. With `-ConnectCore`, it exercises
actual-core start, active revision and disconnect through WebView2 before and
after the service restart. These are non-TUN configurations.
Adding `-AutoStartService` makes both GUI launches start/recover their own hidden
backend rather than starting a service manually. Use
`./windows/scripts/enrollment-smoke.ps1 -ConnectCore -AutoStartService` to cover
desktop-only startup through registration, real core start/stop and DPAPI recovery.

`connection-smoke.ps1` uses an isolated pipe, state directory and loopback control
plane. It starts the prepared real core, sends an HTTP request through its SOCKS
listener, then verifies stop clears the active revision and closes the listener.
In an unelevated session it also checks that a TUN candidate cannot start.
Artifacts are kept in `build/windows-connection-smoke-*/`.
`-Dashboard` adds a real streamed loopback request through SOCKS and captures all
seven dashboard pages in the native WebView2 host, including explicit light/dark
themes and 760px layouts. It requires real telemetry and timed samples before
capture, checks overflow, and stops only its own processes. This fixture produces
actual core traffic; it does not inject fake UI counters or contact a production panel.
The opt-in `-Tun` variant requires elevated PowerShell and creates a uniquely named
TUN with only the isolated `198.18.255.0/30` test route; it checks that route disappears
on stop. It is not a full default-route, DNS-leak or internet acceptance test.
Native lifecycle tests use local fake child/API fixtures, so ordinary CI does not
download or run sing-box.

## Boundaries and next work

The service owns state. The GUI is a presentation client and never receives an
Agent token. IPC uses 32-bit little-endian length-prefixed UTF-8 JSON, capped at
1 MiB. Network logons and remote pipe clients are rejected. The WebView2 bridge
forwards only twelve explicitly allowed methods: `protocol.hello`, `status.get`,
`enrollment.status`, `enrollment.apply`, `enrollment.forget`, `config.summary`,
`config.refresh`, `config.validate`, `connection.start`, `connection.stop`,
`config.inspect` and `runtime.snapshot`. Before sending a registration code, the
desktop verifies the pipe server's executable file identity and SCM registration
or matching development user.
Only admins or the active console session may mutate state; the same authorization protects private runtime
connections and config catalogs. Display projections bound nodes/connections/rules
to 128 each, group members to 16, API JSON to 256 KiB, and each API request to 1.5 seconds.
Long rule conditions are abbreviated; unsupported predicates are visibly marked.
Tokens and raw candidate
configuration never appear in IPC responses. WinHTTP preserves normal TLS validation,
rejects redirects and bounds response sizes and deadlines.

The C11 state module establishes a testable runtime boundary; it does not yet
extract or replace the production Linux Agent loop. Further shared agent logic
must come from the current `c/` implementation, with C adapters for Windows APIs.
Do not link the entire POSIX `sb_core` target into this desktop project.

The runtime adapter supports at most one TUN and loopback-only mixed/HTTP/SOCKS
inbounds. It preserves server `auto_route` semantics, removes Linux dialer/TUN
options, enables interface detection, and prepends control-plane/service/core
direct rules. It replaces the external Clash API with an ephemeral loopback port
and random secret. External UI downloads, file caches, file logs and NTP are disabled.
Remote rule-set downloads remain part of the server policy.

Not every Profile is supported. Multiple TUNs, `platform`, endpoints (including
WireGuard topology), services, local rule-set/hosts/certificate/key/ECH paths,
plugins and ACME are rejected. TUN interface names must use at most 48 ASCII
letters, digits, `_` or `-`; the default is `sb-easy`. Node selection, route
statistics, protocol activation, automatic reconnect and a signed installer remain
future work. A forced TUN termination reports uncertain network cleanup; adapter,
route and DNS recovery still require elevated Windows acceptance testing.

Native fixtures cover lifecycle, rollback, persistence and fake loopback health.
Actual-core non-TUN connection validation and elevated TUN acceptance are tracked
separately; a unit test or successful `check` is not evidence of working VPN routing.

The dashboard organization draws on [Clash Verge Rev's navigation](https://github.com/clash-verge-rev/clash-verge-rev/blob/dev/src/pages/_navigation.tsx)
and this repository's [Android client](../android/README.md). This phase implements
read-only nodes/groups/rules and live connections/traffic; manual node selection,
active latency tests, Android-style local Claude/GPT/custom routing groups, route
tests, retained domain statistics and Windows system proxy control
remain future work. UI activity records are not core logs.

The service-routing view presents server domain groups (including Claude and
GPT/Codex), their assigned exits, the default exit and local/domestic address
scopes. Internal rule-set identifiers are not exposed as user-facing rules.
These are server policy summaries, not locally editable Android routing overlays;
a service label does not imply all traffic from its desktop process is captured.
DNS and application traffic can use a dedicated service exit independently of
the default proxy. When only one service fails, compare both its DNS detour and
route exit with the default path before diagnosing TUN capture as broken.

## Windows application icon

`assets/sb-easy.svg` is the editable desktop icon source, retaining the green/blue
connection mark on a dark teal tile. `assets/sb-easy.ico` contains 16, 20, 24, 32,
40, 48, 64, 128 and 256 pixel frames. Both C executables embed it through
`ui-host/app.rc`; the desktop uses the resource for its window and tray, and
WiX uses it for shortcuts and the installed-apps entry.
Regenerate with `npm install --prefix build/icon-tools @resvg/resvg-js@2.6.2`
then `node windows/scripts/generate-icons.cjs`. Normal builds use the committed
ICO and do not require the icon renderer.


### 0.5.0 statistics and runtime logs

The C service now collects traffic while the desktop is closed, with DPAPI-backed
cumulative statistics, application/domain → host → outbound drill-down, and a
sanitized runtime/service log viewer. See [ANDROID-PARITY.md](ANDROID-PARITY.md)
for the exact Android comparison and [TESTING-0.5.0.txt](TESTING-0.5.0.txt) for
acceptance steps and sampling/retention limits.

### 0.6.0 filtered packet capture

The Capture page adds opt-in raw-IP PCAP recording for this application's TUN,
with process-name/domain/exact-host-or-IP OR filters and a libpcap BPF AND filter.
It offers export/delete, file rotation, a bounded local quota, manual upload and
opt-in periodic upload to the enrolled control plane. Native code remains C11.
Build preparation downloads pinned WinDivert and flex/bison tools and builds the
vendored libpcap with its null backend. The old 0.6.0 ZIP/MSI included capture dependencies; current base packages exclude them (see Optional capture extension below).

Files are scoped by center and device under the protected core-work directory.
Diagnostics exports do not contain raw PCAPs. Uploads verify the server's digest
acknowledgement before marking success or deleting a local file. The center needs
migration 012 and the capture endpoint. See TESTING-0.6.0.txt for limits and testing.

### 0.6.1：后台启动授权

已安装后台停止且当前账户没有启动权限时，界面提供“授权并启动服务”。点击后由 Windows UAC 授权独立的 C helper，仅启动 SCM 中已安装且路径匹配的 sb-easy 服务，随后自动重新读取状态。不会启动代理内核或修改 DNS；取消 UAC 后可重试，无需重启电脑或以管理员身份运行整个界面。未安装服务时仍需运行 MSI 安装包；便携目录不会被注册为 SYSTEM 服务。

Live GPT switching acceptance: `windows/scripts/live-routing-smoke.ps1` uses
loopback-only proxy fixtures and a real sing-box core, verifies unchanged PID,
an uninterrupted existing GPT stream, new requests after each switch, and rollback
on a failed preference write. It does not create a TUN or contact OpenAI.

### IPv6 状态与双栈接入

Windows 的设置与连接诊断显示本机 IPv6 和 TUN 接管证据。服务使用 Windows
网卡/路由 API：只统计启用网卡上处于 Preferred 状态的全球单播地址，联网条件
要求同一接口存在 IPv6 默认路由；TUN 接管要求正在运行的确切网卡存在默认路由
或两条覆盖全空间的 /1 路由。检测失败显示“尚未检测”，旧服务保持兼容。
此检测不会发送联网请求，不证明节点出口可用，也不证明不存在路由例外或泄露。

内核配置适配已支持保留双栈地址。例如在共享模板 tun inbound 的 address 中同时
配置 `172.19.0.1/30` 与 `fd71:5be:a5e::1/126`（部署前检查地址冲突），配合
`auto_route: true`、`strict_route: true`，并检查自定义 route_address/exclude_address。
DNS 应允许 AAAA（例如 prefer_ipv4，而非 ipv4_only）；AI 分组 DNS detour 和流量
出站继续一致。客户端到代理可用 IPv4，因此本地没有公网 IPv6 不妨碍节点代连
IPv6 目标。启用接管不代表节点具备 IPv6 出口。

双栈上线验收必须包含真实 TUN 路由、仅 AAAA 的 HTTPS 目标经所选节点访问、
原有 IPv4 回归、断开后的路由恢复和直连例外检查。当前新增回归验证双栈模板在
Windows 适配中保留、检测字段与旧版协议兼容；尚未完成真实 IPv6 出口验收，
界面明确显示节点“尚未实测”，本次更新不自动修改共享模板启用双栈。

### 统一的 Windows 本地服务分流

服务分流支持默认代理、Claude、GPT/Codex，以及可安全识别的其他域名后缀分组。
Windows 首页集中显示连接状态和服务出口。点击出口可搜索节点，也可选择跟随服务器
或默认代理；选中即提交，不再单独点击应用。切换中禁止重复提交，结果由服务回读
确认；断开时提示下次连接生效。配置版本和校验保留在配置管理，规则与日志收进更多工具。
每组可选择本机节点或恢复服务器设置，服务组还可跟随本机默认代理。界面明确
区分服务器、本机覆盖和跟随默认；运行期间编辑当前运行版本，停止时编辑下载版本。
原有 GPT 本地选择自动兼容。覆盖通过受保护的设备状态持久化，不修改服务器原配置。

运行配置为每个可编辑组添加独立 selector 和 DNS 副本；默认代理同时覆盖最终路由
及最终 DNS，bootstrap 和其他分组不会被一起改写。跟随默认使用 selector 引用，
因此后续默认出口切换无需重启。选择写入失败会恢复原 selector；恢复失败明确报错。
启动时重新确认所有本地 selector 的选项，防止内核缓存覆盖持久化设置。

复杂条件、缺少对应 DNS、重名服务或保留标签冲突显示为不可编辑，继续遵循服务端。
其他分组以排序后的域名集合生成稳定 ID，规则调整顺序不影响覆盖。节点/分组消失
时拒绝悄悄回退；用户需重新选择或恢复服务器设置。已有连接保持原出口，新连接
使用新选择。升级到此版本需重建一次内核以添加分组；之后切换无需断开。

`windows/scripts/service-routing-smoke.ps1` 使用本机回环代理与真实内核，验证三组
实时切换、长连接保持、默认跟随、保存失败回滚和服务重启后的持久化。不会创建
TUN 或访问真实 AI 服务。`windows_routing_groups_test` 验证 DNS 副本隔离及规则拒绝。


### Subscription sources and local subscriptions

The Nodes & Subscriptions page groups nodes by the provenance delivered with
`GET /api/agent/config?sources=1`. The C server returns an opt-in envelope with
`config` and `subscription_sources`; legacy clients still receive plain sing-box
JSON. Provenance includes only the names and tags of subscriptions whose nodes
are actually rendered for this device, never subscription URLs or credentials.
Older servers continue working and are explicitly labelled as missing provenance.
Update the Docker server with `scripts/update-docker-subscriptions.sh` using the
existing deployment's Compose file, then sync/apply the Windows configuration.

Local subscriptions support bounded HTTP(S) downloads (256 KiB), Clash YAML,
sing-box JSON, and plain/base64 URI lists. Supported nodes are Shadowsocks,
VMess, VLESS, Trojan, Hysteria2, TUIC, HTTP and SOCKS. Unsupported protocols,
plugins, external-file TLS settings, duplicate names and invalid nodes reject the
whole import. No public conversion service is used. Each subscription has a stable
ID and isolated node tags; URLs and credentials are persisted with the protected
device identity, never in localStorage or public subscription summaries.

Adding/updating/removing a subscription validates the merged configuration before
changing the running core. sing-box 1.13's PUT /configs is a no-op, so topology
changes automatically restart the core and may briefly interrupt connections;
ordinary selection among existing nodes remains live. Failed activation or save
restores the previous configuration. Deleting a currently selected node is rejected:
first select another exit. Local changes survive shared configuration sync and
service restarts, and never modify the shared profile. Up to 16 local subscriptions,
256 nodes each, and 1024 combined nodes are supported. Refresh is manual in this
release. The isolated service-routing smoke test covers real traffic through an
imported node, persistence, used-node deletion rejection and failed-save rollback.


## Signed optional plugins

The base installer excludes the capture, statistics and HTTP(S) debugging workers
and their UI modules. New plugin packages declare API 1, version 1.1.0 and build 2.
A signed publisher catalog authorizes installation and upgrades. The default
`config/plugin-catalog-keys.json` is empty, so a development build cannot accept
remote plugin releases until a reviewed public key is supplied at build time.
The catalog cannot replace this trust anchor. See the
[shared catalog specification](../docs/plugin-catalog-v1.md).

Import the catalog in Extensions, then install its compatible release. Downloads
use HTTPS, send no device/account credentials and reject redirects. The service
checks signature, sequence, expiry, host/core/OS versions, capability allowlist,
artifact length and SHA-256, fixed archive layout and the embedded manifest.
Installed files are checked again before activation. Legacy 1.0.0 digests remain
only to verify already-installed packages and support their first signed upgrade;
new installs never use the old HTTP URLs or self-supplied checksum files.

Downloading and verification leave an existing worker running. The controller
stops it only for publication, after restoring any HTTP debugging routes. A DPAPI
journal and same-volume directory moves recover interrupted replacement; cached
signed receipts keep a previous verified version available for explicit rollback.
A failed activation can restore that version. New installations and replacements
remain disabled until enabled. Known revoked builds cannot start or be selected
for rollback, including offline. Catalog expiry blocks new installation; previously
verified, non-revoked installed code and cached recovery remain usable. Catalog
sequence and the highest installed build survive removal and rollback.

Workers use Windows AppContainer with a private profile, a filtered environment,
private framed pipes, an explicit inherited-handle list and job limits. Statistics
and PCAP receive no network capabilities. HTTP debugging receives network
capabilities and a loopback exemption for its local proxy/UI; the host preserves
other applications' exemptions and removes its own on normal shutdown. The host
verifies the child's AppContainer SID, low integrity and absence of dangerous
privileges before resuming it. If sandbox creation fails, the plugin stays stopped.
This boundary still requires native Windows acceptance; Wine cannot establish it.

PCAP parsing, BPF and capture files remain in the worker. Only the host opens the
WinDivert driver, and only after capture is explicitly enabled. It checks the
vendor DLL/driver against independent host pins, copies them to a host-only
location, and opens a fixed read-only/sniff handle for the managed TUN interface.
The child receives that handle through the private broker. It cannot nominate a
filter, load a different privileged DLL, or obtain packet-injection access. The
host shuts down the shared handle on disable, core stop or worker failure.

Statistics state remains encrypted in the host and is loaded only while enabled.
The first sample establishes a baseline; re-enabling cannot recount traffic from
while the plugin was disabled. Optional UI modules load only when opened. Removal
retires binaries/UI and preserves private settings and captures. Connections,
rules and redacted logs remain built-in features; `network-tools` is retained only
for removing legacy installations.

Build and publish a reviewed release:

1. Build the optional native workers with `build.ps1 -CaptureExtension
   -StatisticsExtension`, build the HTTP worker with `build-http-debug.ps1`, and
   run `npm --prefix windows/ui run build:plugins`.
2. Run `windows/scripts/package-capture-extension.ps1` to stage the versioned
   capture ZIP. It is a build input, not an unsigned installation bypass.
3. Run `python windows/scripts/package-plugins.py --base-url
   https://downloads.example.com/plugins --sequence 1`. Review
   `build/plugin-release/catalog-payload.json` and all artifact hashes. Supply
   `--revocations reviewed-revocations.json` when required.
4. Sign with the shared publisher using an external private key and the same
   reviewed public-key allowlist embedded in the host. The packaging tool also
   accepts `--private-key`, `--key-id` and `--keys` together. Upload only the signed
   catalog and verified artifacts to the HTTPS origin. No private keys enter the
   repository or packages.

Native CTest includes RSA-PSS cross-language vectors, installation/upgrade,
interrupted publication at every rename, locked directories, tampering, durable
revocations and rollback/downgrade tests. `windows_plugin_sandbox` runs a real
signed fixture worker and checks private data/code/environment/handle/process
boundaries. `extensions-smoke.ps1 -SignedCatalog ...` additionally exercises real
host lifecycle and optional HTTP debugging with a matching trusted build and
HTTPS artifacts. These scripts are acceptance requirements, not evidence that
Windows TUN, driver capture, AppContainer networking or production signatures have
already been verified in this Linux workspace.

## Publisher-signed release packages

Ordinary CI packages remain development previews. `Windows trusted release packages`
(`.github/workflows/windows-release.yml`) is a separate manual workflow restricted
in code to `master` and the `windows-release` environment. Configure that environment's
reviewers/branch protection, secrets `WINDOWS_SIGNING_PFX_BASE64` and
`WINDOWS_SIGNING_PFX_PASSWORD`, and variables `WINDOWS_SIGNING_THUMBPRINT` and
`WINDOWS_TIMESTAMP_URL` before running it. No publisher certificate or private key
is included in this repository. Missing credentials, untrusted certificate chains,
signing failures or missing timestamps fail the release instead of producing an
artifact labeled signed. Environment approval requirements are repository settings;
the workflow cannot create them.

For a Windows signing workstation with PowerShell 7 and an approved code-signing
key already in `Cert:\CurrentUser\My`, run:

```powershell
./windows/scripts/build.ps1 -PublisherThumbprint $publisherThumbprint
./windows/scripts/package.ps1 -Msi -IncludeCore -TrustedRelease `
  -CertificateThumbprint $publisherThumbprint -TimestampUrl $rfc3161Endpoint
```

The pipeline signs this project's executables and distributed PowerShell scripts
before packaging, signs the MSI, and verifies the expected publisher and RFC3161
SHA-256 timestamp using SignTool and Authenticode. Upstream core/DLL bytes retain
upstream provenance and are covered by the package digest. ZIP and MSI hashes are
written to `sb-easy-0.7.0-windows-x64-release.json`; its detached CMS `.p7s` signature
covers the exact manifest bytes. The workflow uploads verified artifacts for review;
it does not automatically publish a GitHub Release or change installed services.

Download both packages, the JSON manifest and its `.p7s` beside one another. Obtain
the expected publisher thumbprint through a trusted release channel, then run the
repository's verifier:

```powershell
./windows/scripts/verify-release.ps1 `
  -Manifest ./sb-easy-0.7.0-windows-x64-release.json `
  -CertificateThumbprint $publisherThumbprint
```

The verifier requires a trusted signer, the externally supplied publisher identity,
exact file sizes and SHA-256 hashes; on Windows it also validates the installer's
publisher signature and timestamp. The detached manifest itself is not timestamped,
so its trust check requires a currently valid certificate chain. Real release-key
access, RFC3161 availability, signed MSI lifecycle, SmartScreen reputation and
Windows driver/network acceptance remain release-environment checks. Source tests
verify rejection paths; they do not establish that a signed production release exists.
See [SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool)
and [Get-AuthenticodeSignature](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature).

### Verified application and core updates

Settings provides explicit check, download, install and recovery actions. Updates
require an installed LocalSystem service, a matching registered MSI version, and
the publisher thumbprint embedded at build time. Portable and unconfigured builds
report that updates are unavailable. Neither the UI nor the feed can nominate a
new trusted publisher. The application and pinned core move together in one MSI;
there is no independent unverified core download or automatic installation.

Enter a direct HTTPS manifest URL. The service fetches its adjacent `.p7s`, verifies
the exact bytes with the embedded publisher, and checks the schema-2 Windows/x64
version matrix before offering a download. A persisted random cohort honors the
signed rollout percentage. Older versions, incompatible protocol/minimum versions,
unknown fields, duplicate keys and malformed UTF-8 are rejected. Artifact names
resolve only beside the manifest on the same origin. Downloads reject redirects,
credentials, cookies and ambient authentication, enforce deadlines and size limits,
and support cancellation before installation.

The installer must match the signed SHA-256/size, trusted timestamped Authenticode
publisher, product/upgrade identity, x64 architecture and version. It is checked
again immediately before use. Staging and encrypted state backups use protected
non-reparse directories. A verified helper runs outside the installation directory,
stops the service, and snapshots the existing encrypted device state before starting
the Windows Installer transaction. The UI closes after the install request is
accepted; reopen it after the transaction to inspect the final result.

Before MSI commit, a service health action verifies the new protocol/application
version, executes the packaged core's version command, and checks the stored
configuration. A previously connected device must reconnect using its known-good
configuration. Failure aborts the MSI transaction; after Windows Installer restores
the previous product, the helper restores the exact encrypted state backup and
checks the old service. A durable journal supports interrupted-update recovery.
Ambiguous installer/product state is reported as recovery required and preserves
the backup. Requested WFP disconnect protection remains through major upgrades.

`scripts/update-acceptance.ps1` is the disposable, elevated Windows VM gate. Supply
a trusted previous MSI, a valid newer signed manifest, and a separately signed
newer test MSI whose declared core version intentionally differs from its core.
It checks pre-commit health rollback, altered staged-package rejection and successful
application/core commit, and retains a receipt and installer logs. It refuses an
existing installation/data store and never changes certificate trust. Linux/Wine
source tests cover manifest/hash rejection, bounded downloads, version checks,
private encrypted backup/restoration and RPC guards; they do not establish successful
Windows Installer rollback or a production signing identity.

## Optional disconnect protection

The Settings page offers a default-off WFP kill switch. Enabling it requires the
installed, automatic `sb-easy` Windows service and its pinned core. Persistent
IPv4/IPv6 connect/receive filters block ordinary applications outside loopback or
the current TUN. Only the fixed service/core programs, constrained DHCP and IPv6
neighbor discovery are exempt. There is no blanket physical-interface DNS permit.
An uncached center hostname can therefore be unavailable while the tunnel is down.
The status view reports observed filter state separately from the saved preference;
the service checks it periodically and attempts to restore requested protection.

Manual disconnect, core failure and service exit retain protection. Turning the
setting off explicitly removes this product's WFP objects. To recover when the UI
or saved state is unavailable, open an elevated terminal, stop the installed
service, and run its fixed command:

```powershell
Stop-Service sb-easy
& "$env:ProgramFiles\sb-easy\sb-easy-service.exe" --disable-kill-switch
Start-Service sb-easy
```

Recovery removes only sb-easy rules and records an administrator-only machine
marker. The next service startup persists the disabled preference under LocalSystem
without exposing or replacing DPAPI credentials. If storage is damaged, the marker
remains and protection cannot silently return. Genuine MSI uninstall runs recovery
after stopping the service and before deleting its executable; major upgrades
retain protection. Cleanup failures abort uninstall instead of stranding unreported
rules. This lifecycle still requires the disposable Windows VM acceptance script;
policy-emitter tests and Wine runs do not prove packet-level leak prevention.

### Exit health and explicit automatic groups

The connection page exposes service-owned health policy: HTTPS probe URL, interval
(default 180 seconds), timeout (default 5000 ms), failover/fastest strategy, and
improvement tolerance (default 100 ms). A background cycle performs one owned-core
probe or selector change per tick; closing the UI does not stop it. PID, physical
network generation, group or policy changes discard incomplete results.

A fixed selection reports probe failure and keeps its exit. Automatic groups
require an explicit list of 1–32 leaf proxy nodes (128 candidates across groups).
Their generated selectors contain only those available candidates, and DNS uses
the same selector. Direct, nested selectors and unknown nodes cannot be added.
Failover keeps a healthy current choice; fastest changes only when improvement
exceeds the configured tolerance. If every candidate fails, the current choice is
retained. If a downloaded configuration removes every allowed candidate, that
configuration is rejected and the known-good configuration remains. Choosing a
fixed exit rebuilds the selector and leaves automatic mode.

Native policy/controller/transport tests cover these rules under Wine. This does
not replace Windows TUN, sleep/resume or packet-leak acceptance on a disposable VM.
If stored kill-switch preference is absent or invalid while persistent WFP filters
exist, startup preserves those filters and reports recovery required. Unrelated
settings writes keep the preference unknown; only an explicit valid opt-out or
administrator recovery removes the rules.

### Encrypted preferences and personal synchronization

Settings can export an encrypted JSON file, read a selected file, preview its
contents, and apply that reviewed preview. Imports replace local subscriptions,
general group selections and health policy. Device registration, custom domain
and process groups, automatic connection, kill-switch policy, capture/MITM state
and certificates remain on the destination. The service checks the resulting
configuration before saving or reconnecting. Preview capabilities are one-use,
expire after five minutes, and reject intervening local changes. Failed writes
leave the previous preferences intact. Import never implicitly connects a stopped
device.

The encryption envelope follows [the shared format](../docs/preferences-format.md):
PBKDF2-HMAC-SHA256 with 600,000 iterations and AES-256-GCM, random salt/nonce and
fixed authenticated context. Windows accepts 12–1024 UTF-8 password bytes and
limits plaintext to 640 KiB/envelopes to 900 KiB to fit bounded IPC frames. The
shared Unicode vector is tested with the native Windows CNG implementation.
Windows imports Windows payloads only. Subscription URLs and cached credentials
are encrypted inside the archive; they are absent from the preview.

Personal synchronization signs into an HTTPS panel with a separate account
session and supports authenticator/recovery-code MFA. Panel tokens and binding
cookies remain in service memory, never in device enrollment state or WebView
responses. A random per-window capability gates later requests. Passwords are
cleared from the form after each operation. The panel stores only ciphertext in
`windows-personal`; it cannot decrypt the archive. Fetch the remote state before
uploading/deleting. Conditional revisions reject conflicts, and deletion preserves
a tombstone revision so stale clients cannot recreate an old version silently.
Sign out to revoke the panel session; reopening the window requires a fresh login.
