# sb-easy Windows development preview

## 0.6.9 HTTP(S) debugging preview

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

- Windows accepts managed WireGuard endpoints using sing-box's userspace engine,
  preserves per-device keys/peers and the server's intranet route, and includes
  endpoints in the node catalog without exposing keys. The center device must
  have `capabilities.embedded_wireguard=true`; older center enrollment handlers
  do not infer this from `platform=windows`. Enabling it on the correct host
  causes the next config fetch to provision its own peer. No separate Windows
  WireGuard service is needed. Unknown endpoint types remain unsupported.

- GPT/Codex can follow the server, use the default proxy, or use a chosen node via a persisted local routing preference.
  The service keeps the downloaded server snapshot unchanged and overlays the local
  choice on both the GPT route and its DNS detour during validation and startup.
  Sync and service restarts preserve the choice. Open Service Routing, select a
  node, then save the local choice. A runtime-only selector switches GPT traffic
  and DNS through the authenticated Clash API without restarting the core or TUN.
  Existing user connections retain their exit; new connections use the selection.
  A failed durable save restores the previous live selection. Restore server settings removes
  the override. No separate server profile is needed. If the chosen node disappears,
  refresh fails explicitly and retains the previous candidate instead of silently
  changing exits. Arbitrary rule editing and other service groups remain future work.
  Both its domain route and a dedicated clone of its DNS server use that exit;
  other services sharing the original DNS server stay unchanged. The server
  snapshot/ETag remain intact. Switching requires a stopped core and validates
  the effective configuration before saving. Unsupported rule shapes or sync
  changes are rejected without replacing the last downloaded configuration.
  This is a manual exit selection, not automatic failover or a node repair.

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

This writes `build/sb-easy-0.6.0-windows-x64-portable.zip` and prints its
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

This produces both `build/sb-easy-0.6.0-windows-x64.msi` and the portable ZIP
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
msiexec /i "build\sb-easy-0.6.0-windows-x64.msi" /qn /norestart /l*v install.log
msiexec /x "build\sb-easy-0.6.0-windows-x64.msi" /qn /norestart /l*v uninstall.log
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


## Optional capture extension (API 1)

The default Windows build and portable/MSI payload exclude capture implementation,
libpcap, WinDivert, and the capture UI. The first official extension is `capture`
version 1.0.0. Settings > Extension Store manages its lifecycle. This is the first
migration. Windows 0.6.4 also extracts historical statistics and the network troubleshooting UI as described below.

Build the optional package with `-DSB_EASY_BUILD_CAPTURE_EXTENSION=ON`, run
`npm --prefix windows/ui run build:capture`, then
`windows/scripts/package-capture-extension.ps1`. Default builds set the option OFF
and do not require capture dependencies. The `build.ps1 -CaptureExtension` switch
prepares those dependencies when requested.

In Windows 0.6.3, open Settings > Extension Store and click Install. The service
downloads the official package in the background, reports progress, verifies the
release SHA-256, and publishes staged files. Installation leaves the extension
disabled and does not restart sing-box. The Installed tab provides enable,
disable and uninstall. Re-enabling permits saved capture preferences to resume;
new installations have capture disabled. Failed downloads/installations can be
retried. The separate ZIP/Install.cmd remains an offline fallback.

This first store is an official curated catalog shipped with the client, with three
available extensions. It does not accept third-party repositories or silently
trust new code advertised by a remote catalog. Adding a release requires reviewing
and updating the client catalog pin. Build a store release with
`python windows/scripts/package-plugins.py`; it writes all `.sbe` artifacts,
`build/store-release-index.json` and `service/store_catalog.h`. Rebuild the host
after pinning. The old package-store.py creates a capture artifact only.
The fixed-layout bundle contains only the predefined files for each release, no executable
installer, archive paths, or links. Size is pinned and capped at 16 MiB. The
compiled digest authenticates package contents even over the current HTTP
hosting endpoint. Downloads send no device credentials and reject redirects.

`scripts/deploy-extension-store.py <bundle> <sha256>` runs on the Docker host.
It publishes the package under `/assets/store/` using a persistent read-only
Compose mount, preserves other Compose settings, and rolls back on failed
download verification. It does not change device profiles or subscriptions.

The protected `extensions/capture/extension.json` declares `id`, `version` and
`api_version`. The first host only accepts the official capture ID/API/version.
It launches `sb-easy-capture.exe` in a kill-on-close job, with an explicit inherited
handle list and private framed pipes. Calls have a three-second deadline and a
2 MiB frame ceiling. Failure stops the child, not sing-box. This is process crash
isolation, not a security sandbox: capture runs with the service's privileges.
Only the device storage scope and requested connection metadata are sent; device
authentication credentials and server upload authentication remain in the host.

The extension UI is a separately built module at `ui/extensions/capture/view.js`.
It is loaded only when opened. Disable/uninstall stops its worker without stopping
the proxy. Uninstall retires extension binaries/UI into timestamped `*-removed-*`
directories, preserving existing device-scoped capture settings and PCAP files.
Reinstalling and enabling restores those settings. Saved data is not deleted by
uninstallation. Compatible updates use uninstall, then install the newly approved
release from an updated client catalog.

`extensions.list` and `extensions.change` (`id: capture`, `action: enable|disable|remove`)
require the same authorized local session as other private operations. Capture
calls return `EXTENSION_MISSING` while absent/disabled and `EXTENSION_FAILED` if
the worker exits. Re-enable to restart a failed worker.

`extensions.catalog` lists trusted releases, `extensions.install` accepts only
`{id: "capture"|"statistics"}`, and `extensions.progress` reports the asynchronous install job.
The legacy `network-tools` installation request returns `BUILTIN_FEATURE` in 0.6.6.
All three require the authorized local session. URLs, digests and destination
paths cannot be supplied by RPC. Downloading does not hold the connection mutation
lock. Extension lifecycle changes are rejected while installation is active.

Verification: `windows/scripts/extensions-smoke.ps1` exercises absent/disabled
states, real store download/installation, worker crash recovery, disable, uninstall, reinstall,
saved preferences, unchanged sing-box PID and real proxy requests on an isolated
loopback fixture. `capture_test` continues testing packet filtering and files
against the optional implementation.
`windows_extension_store_test <bundle>` additionally verifies corruption rejection,
occupied-destination rollback, disabled installation and overwrite rejection.


## Additional optional plugins (Windows 0.6.4)

The store offers `statistics` in addition to capture, each API 1/version 1.0.0.
Both install disabled. Sidebar entries appear only for enabled plugins, and
their Vue modules load only when opened. Neither optional module is part of the
base UI bundle. Installed settings/history survive uninstall.

Statistics aggregation (`traffic.c`) is linked only into the optional
`sb-easy-statistics.exe` worker and its tests. The host links `traffic_proxy.c`,
a small broker using the shared, bounded `extension_process` transport. With
statistics disabled, the host does not launch that worker, load its history,
accumulate per-application/domain history, or poll connections for statistics.
Capture can still request its own samples independently. Basic live speed and
connection counts remain available through sing-box's runtime API.

Existing encrypted history is loaded lazily when statistics is enabled and saved
through the protected host store. The first sample after a worker start only
establishes a baseline, so reinstall/re-enable cannot recount earlier traffic.
A crashed or unresponsive worker never overwrites saved history with empty data.
Disable saves a final checkpoint, then terminates the worker without restarting
sing-box. The history was already bounded to 512 aggregate rows; that limit stays.

As of Windows 0.6.6, active connections and runtime logs are default sidebar
pages. Effective rule inspection is also built in under advanced navigation.
These pages require no installed or enabled extension. `logs.snapshot` retains
local-session authorization and redaction, but no longer requires Network Tools.
The store no longer advertises Network Tools to new users. Existing legacy
packages remain manageable under Installed, with an explanation that removal
only deletes the old extension files and does not remove the built-in pages.
Legacy package identities and integrity pins are retained for that migration.

Release build order:
1. Build the base and optional worker with
   `-DSB_EASY_BUILD_STATISTICS_EXTENSION=ON` (or `build.ps1 -StatisticsExtension`).
2. Run `npm --prefix windows/ui run build:plugins`. Keep the approved capture ZIP
   in `build/sb-easy-capture-1.0.0-windows-x64.zip`.
3. Run `python windows/scripts/package-plugins.py`, upload every indexed artifact
   to the existing server's read-only store mount, then rebuild the base service.
4. Build the base UI and package the MSI. Base packaging excludes all plugin
   workers and modules. A bootstrap catalog cannot be packaged.

`extensions-smoke.ps1` now covers all three real store downloads, concurrent
plugin lifecycle independence, statistics persistence, first-sample baselines,
disabled-period exclusion, worker crash recovery and unchanged proxy PID/traffic.
Run `windows_extension_store_test <bundle> <id>` for each indexed release to verify
integrity and atomic disabled installation for each layout.
