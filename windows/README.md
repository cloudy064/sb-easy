# sb-easy Windows development preview

This is an executable Windows development preview with real core connection control.
It connects a packaged Vue UI in an unelevated Win32/WebView2 window to a real
local service over an ACL-protected named pipe. Starting a TUN configuration can
change network adapters, routes and DNS; downloading or validating one does not.
This is not a completed or signed VPN release.

## Implemented

- Pure C11 service, Win32 host, platform adapters and native tests, built with MSVC.
  The frontend remains Vue/TypeScript. JSON uses the existing `c/` sbj implementation;
  WebView2 uses C COM interfaces and the packaged dynamic `WebView2Loader.dll`.
- C11 state transitions without OS headers or I/O.
- Windows Service Control Manager entry point and `--console` development mode.
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
- Candidate validation through a separately prepared sing-box 1.13.12 executable's
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
regression runs for the server-side C/C++ changes.

## Build

Install Visual Studio 2022 Build Tools with these components:

- `Microsoft.VisualStudio.Workload.VCTools`
- `Microsoft.VisualStudio.Component.VC.Tools.x86.x64`
- `Microsoft.VisualStudio.Component.Windows11SDK.26100`
- `Microsoft.VisualStudio.Component.VC.CMake.Project`

The Visual Studio component names use “C++”; this project compiles its native
sources and tests as C11.

Also install Node.js 22 LTS or a compatible version >=20.19, and WebView2
Evergreen Runtime to run the desktop. The SDK is restored automatically at its
pinned version; the Runtime is not pinned or bundled.

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

The preparation script downloads the official Windows x64 sing-box 1.13.12 archive,
verifies its fixed SHA-256 and copies `sing-box.exe`, `libcronet.dll` and `LICENSE`
to `build/windows-release/core/`. Use `-Configuration Debug` for the debug output.
It does not launch the core. Restart an already running service after preparation.

This official core embeds Wintun through sing-tun v0.8.9; it does not require an
adjacent `wintun.dll` download. The pinned dependency and embedded amd64 bytes are
documented in [sing-box v1.13.12 go.mod](https://github.com/SagerNet/sing-box/blob/v1.13.12/go.mod),
[sing-tun's amd64 embedding](https://github.com/SagerNet/sing-tun/blob/v0.8.9/internal/wintun/dll_windows_amd64.go)
and [its in-memory loader](https://github.com/SagerNet/sing-tun/blob/v0.8.9/internal/wintun/dll_windows.go).
Preparation does not create an adapter or install a service.

To create a portable development archive after building:

```powershell
./windows/scripts/package.ps1
```

This writes `build/sb-easy-windows-x64-development-preview.zip` and prints its
SHA-256. An explicit file list includes the desktop, service, loader, UI, notices
and preparation script; an optional core already present in the build directory
is not included.

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
This preview does not install an elevated service automatically; a production
installation still needs a signed installer and the appropriate service account.

For a downloaded CI/development archive, keep both executables,
`WebView2Loader.dll`, `ui/`, `licenses/` and `scripts/` together. The archive does
not include sing-box. From the extracted directory, optionally prepare the core,
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
tests, retained domain statistics, core logs and Windows system proxy control
remain future work. UI activity records are not core logs.
