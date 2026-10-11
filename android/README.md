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

## Official Android application routing (1.2.8)

The Claude and GPT group cards explicitly show **Android App 全流量** status.
Their existing, default-enabled **编辑规则** switches match the official Android
packages `com.anthropic.claude` and `com.openai.chatgpt`. All connections identified
as belonging to each app follow that group's selected exit, independently of the
hostname, IP address, network protocol or the other group's domain list. Selecting
`direct` for the group remains an explicit direct-exit choice. Existing saved
node selections, domain edits and manually disabled app switches are retained.

Application routing now precedes every destination-based route, including
private-address, management-host and management-endpoint exceptions; sniffing and
DNS interception still run first. Non-matching apps retain these exceptions and
the established domain/default policy. All application DNS rules now precede
all group-domain and management DNS rules, so a ChatGPT-owned lookup for a Claude
hostname uses GPT's DNS/FakeIP policy, regardless of group ordering. Bootstrap
DNS for proxy nodes remains explicitly direct to avoid resolver loops.

Browser traffic continues to match service domains. External browser login
belongs to the browser, not the originating app; unidentified owners fall back
to destination rules rather than being guessed. No server or non-Android agent
policy changes are needed. TCP/UDP matching does not add capabilities missing
from the selected outbound transport.

Verification covers owner-only route conditions and priority, cross-group and
unlisted/management DNS requests across A/AAAA/HTTPS/SVCB/TXT, browser fallback,
reordered groups, disabling/persisting app matching, and the existing pinned-core
native DNS/routing regression. Actual Android connection-owner detection still
requires device acceptance: inspect each app's host/exit traffic while testing.

## Clear traffic statistics (1.2.7)

Use **诊断 → 流量统计 → 清空统计** and confirm to reset all app, domain,
host and exit counters together. The action is available from either dimension,
does not disconnect the VPN, and persists an empty snapshot immediately. A failed
save leaves the existing history visible and reports an error.

Live connection baselines are retained: unchanged/replayed counters do not
recreate rows, and subsequent samples count only their positive increments.
Old connections first observed after the reset adopt their first sample as a
baseline instead of restoring older history. Counter sampling means the exact
instant of reset cannot split bytes between samples. Fresh core lifetimes start
with fresh baselines. Tests cover cancellation/confirmation, both dimensions,
active/replayed/closed connections, identity retention and persisted empty data.

## Domain, host and exit drilldowns (1.2.6)

**诊断 → 流量统计 → 按域名** groups by the registrable domain using
OkHttp's bundled Public Suffix List (including private suffixes), rather than
by complete hostname. For example `api.example.co.uk` and `cdn.example.co.uk`
share the `example.co.uk` row; unrelated `alice.github.io` and `bob.github.io`
remain separate. Hostnames are normalized to lowercase ASCII/IDNA without a
trailing dot. Local/suffix-only names retain their own label. IP destinations
are listed separately and never assigned a guessed domain.

Both dimensions now open real detail screens:

- **App → hosts → exits** shows the application's individual host counters and
  their actual direct/proxy exits. Shared UIDs stay grouped; component names
  remain available under **应用信息**.
- **Domain → hosts → exits** shows the specific hosts within that registrable
  domain, with counters aggregated across apps and broken down by actual exit.
- Each host previews its busiest paths; opening it shows every path's upload,
  download, outbound type and selector chain. Search matches hosts and nodes.
  System Back and the visible Back button return one level.

The persisted grain is application identity + registrable domain + host +
observed concrete outbound/type/chain. The pinned libbox tracker supplies the
final outbound and a final-first chain; the UI reverses the chain for display.
Changing the selected proxy never rewrites previous traffic. Unknown metadata
is labelled as unknown rather than inferred from the current configuration.
Connection replay/final totals share a per-core checkpoint so all dimensions
count the same byte increments.

Storage v3 retains 1.2.4/1.2.5 app totals. Existing 1.2.5 full-host totals are
regrouped into registrable domains and retained as explicitly historical host
rows with unknown application/exit. App detail screens show the amount lacking
host attribution; older app totals cannot be joined to independent host totals.
New connections provide the complete relationship. Up to 20,000 detailed keys
are retained; excess keys contribute to an explicit overflow bucket while app
totals continue to count their bytes. Statistics publish at most once per
second, including on status ticks, and force publication/persistence on stop.

Tests cover public/private/multi-label suffixes and exceptions, IDN/IP/local
names, app/domain filtering, cross-app host aggregation, direct vs multiple
proxy exits, replay, final counters, storage migration and overflow. Android UI
tests cover the three-level navigation, actual exit labels and paths, and the
compact shared-UID view at 360dp width.

## Traffic statistics (1.2.5, historical)


Open **Tools → 流量统计**, then choose **按应用** or **按域名**. Both views
show independently accumulated upload/download totals, ranked compact rows,
search and each row's share of the selected dimension's total. Shared system
UIDs show a short title (for example Android 系统); package names and component
labels are available in a bounded, scrollable details dialog instead of filling
the traffic list. Package-label lookups run off the main thread.

Domain accounting aggregates full observed hostnames across apps and exits,
normalizes case and a trailing dot, and keeps unknown/IP-only connections in a
separate bucket. It does not infer domains from destination IPs. Up to 10,000
named domain buckets are retained; additional domains contribute to an explicit
other-domains bucket so their bytes are not lost. These totals are independent
of domain route observations and survive route/configuration changes.

The v2 storage format migrates 1.2.4's application totals without loss. Domain
history starts with this version; pre-upgrade application bytes cannot be
retrospectively attributed to domains, so the two historical totals can differ.
Both dimensions remain local and share the same checkpoint/retention lifecycle.

Validation includes migration, per-domain aggregation across apps/routes,
replayed and final connection counters, restart persistence and domain overflow.
An Android Compose test uses 50 shared-UID components at 360dp width to verify
that traffic and the next application stay visible, details open separately,
and domain switching/search work.

## Per-application traffic (1.2.4)

The initial 1.2.4 **Tools → 应用流量** view provided cumulative upload/download totals, sorted by
combined bytes, searchable by application name, package or UID. Accounting uses
libbox connection payload counters for traffic passing through the VPN,
including direct and proxy routes. It is not the Android system's device-wide
or carrier-billed usage; bypassed traffic, transport overhead and pre-upgrade
history are not included. Shared-UID packages appear as one group, and missing
owner information remains visible as unknown/UID-only traffic.

Android-rendered configurations enable process lookup even when app-based
routing rules are disabled. Package visibility is used to resolve arbitrary
connection-owner UIDs to package names and labels. Owner lookup can still fail
on short-lived connections or older/vendor Android systems.

Totals stay exclusively in `app-traffic.json` in app-private storage, with
atomic checkpoints every 30 seconds while connection events arrive and a flush
on normal VPN shutdown. Force-stop/crash can lose the unsaved interval; the
last interval before shutdown can also be missed when the core stops sending
events. Totals survive configuration changes, core rebuilds and app restarts;
forgetting the device or clearing app data removes them. They are not uploaded
as telemetry. Replayed connection snapshots and final close counters are
reconciled against per-core checkpoints to avoid double counting.

JVM tests cover cumulative/replayed/final counters, shared UIDs, unknown owners,
restarts, persistence and recent closed-history pruning. Device acceptance:
upgrade without clearing data, transfer data with two different apps, verify
separate upload/download rows, switch nodes/reconnect/restart, and check that
saved totals remain and shared/unknown owners are shown honestly.

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

Sniffing and DNS hijacking are preserved. Since 1.2.8, enabled official-app
rules take priority over destination exceptions. For other traffic, control-plane
access, management endpoints and private addresses retain their existing routing;
local domain groups precede private/China domain and China-IP direct rules. Other public traffic uses the
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

## Wi-Fi recovery (1.2.3)

The October 9 handset report recorded 25 watchdog core/TUN rebuilds after
switching to Wi-Fi. The old policy treated two failures of one remote URL as a
broken core, repeatedly dropping every active connection. Physical-network
control-plane fallbacks succeeded while requests through the VPN failed.
This establishes the rebuild loop, but does not by itself establish why the
first TCP request failed on the handset.

Android-rendered TUN inbounds now use `gvisor`, bypassing the vendor system TCP
path used by `mixed`. This is a compatibility mitigation pending handset
verification, not proof of a vendor-kernel defect. Addresses, MTU, routing,
FakeIP persistence and saved node choices are retained; the server's original
configuration is unchanged. Diagnostics include the effective TUN stack.

The watchdog confirms a failed configured URL with Cloudflare's HTTPS 204
endpoint through the normal VPN route. Each attempt includes DNS in its
10-second deadline; successful primary probes do not send the extra request.
Screen-on/handover events cannot start checks less than 15 seconds after the
previous completed check. Three or more consecutive failed checks spanning
at least 90 seconds allow one core rebuild for that outage. Further failures,
isolated successful checks and network churn cannot trigger repeated rebuilds.
At least two minutes of regularly sampled success rearm recovery, with a
five-minute minimum between repairs. Long sleep gaps do not count as health.
The health-check wake lock is bounded to 25 seconds for two sequential probes.
Missing cores/reset failures during actual handovers retain their existing
recovery path. Notifications distinguish failed probes from an active repair.

Acceptance on the affected phone remains required: upgrade without clearing
data, verify `tunStacks=[gvisor]`, switch between cellular and multiple Wi-Fi
networks, browse for at least 15 minutes, then repeat with the screen off.
Upload diagnostics if requests still fail; look for the reached probe host,
failure type and absence of repeated core rebuilds. JVM tests and loopback
DNS/routing tests cannot validate Xiaomi/Android 16 Wi-Fi behavior.

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

Historical behavior below is superseded by the 1.2.3 policy above.

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

The handover path below remains; the repeated probe-driven escalation policy
is superseded by 1.2.3.

A handover now uses the existing libbox CommandServer.resetNetwork() to reset
connections and DNS transports while retaining the Android TUN. This closes old
connections; it is not seamless migration. Same-interface reconnects also reset.
The background probe verifies actual connectivity afterward. Two consecutive
probe failures escalate to a full core/TUN rebuild with the existing cooldown;
missing cores and reset exceptions also rebuild. Stale generations and service
cancellation cannot report recovery or start an obsolete fallback. No permanent
wake lock is added. Device acceptance remains necessary.

## 原始流量采集（1.3.0 起）

进入 **诊断 → 流量采集**，选择已安装的应用，或填写域名、精确 host/IP，
开启采集后点击“保存并应用”。采集和自动上传默认关闭；默认只允许 Wi-Fi 上传。
启用或修改配置会重启正在运行的 VPN，未运行时在下次连接生效。

- **App**：点击应用选择按钮，按名称搜索并勾选，首页显示已选应用名称，可直接移除。
  默认显示非系统应用，也可显示系统应用；搜索会覆盖系统应用。清单已有
  `QUERY_ALL_PACKAGES` 权限，无需手动输入包名或额外运行时授权。按 Android 提供的
  UID/包名归属筛选；共享 UID 的组件无法区分。
- **域名**：匹配自身及子域名，例如 `example.com` 包含 `api.example.com`。
- **host/IP**：精确匹配，例如 `api.example.com` 不包含 `sub.api.example.com`。
- App、域名、host 多项条件之间为“或”；域名/host 每行一项，也可用逗号分隔，最多 100 项。
- **BPF（1.3.1 起）**：可选标准 libpcap 抓包表达式，例如 `tcp port 443`、
  `udp port 53`、`src net 10.0.0.0/8 and not udp port 443`、
  `tcp[tcpflags] & tcp-syn != 0`。与 App/域名/host 组合条件之间为“且”，每个包单独判断。
  只填 BPF 时筛选全部 VPN TCP/UDP 流量。至少选择应用/域名/host 或填写 BPF。
  保存前原生编译校验，错误不会覆盖已保存配置；可先点击“检查 BPF 语法”。
  使用 libpcap 1.10.6 原生编译器及用户态 cBPF 执行器，无需 root、内核 BPF 或 QuickJS 模拟。
  不支持 Wireshark 显示过滤语法（如 `tcp.port == 443`）。原始 IP 链路不含以太网头，
  不能按 MAC 地址筛选；仅 TCP/UDP 包进入现有采集链，`icmp` 等表达式不会扩大采集协议范围。
  BPF IP 按原始 TUN 包匹配（可能是 FakeIP），网站名建议填入域名栏。
  表达式最多 4096 UTF-8 字节，过滤在异步采集线程执行，不阻断网络转发。
- 单文件 128–768 KiB（默认 512）、轮转 10–600 秒（默认 60）、本地总量
  8–256 MiB（默认 64），另有 1000 文件上限。达到上限暂停写入，保留已有文件；
  删除文件释放空间后自动继续。可选“上传成功后删除本地文件”。
- 自动上传间隔 30–3600 秒（默认 60），随前台 VPN 服务运行；VPN 停止后可以
  手动上传。Wi-Fi 限制也适用于手动上传。没有可用物理网络或上传失败时保留文件，
  下一轮重试。上传连接绑定物理网络，避免抓到自身上传的数据而循环生成文件。
- 本地文件可通过 Android 文件选择器导出。上传只针对当前注册服务器及设备身份，
  不会把旧注册身份的文件发送到新服务器。解除注册会关闭采集和自动上传。

### 文件格式与采集边界

输出标准 little-endian PCAP 2.4，link type `101`（raw IP）、微秒时间戳，完整记录
VPN TUN 内 IPv4/IPv6 的双向 TCP/UDP 包；保留现有 gVisor 栈。PCAP 可以用
Wireshark/tshark 打开。这里记录的是封装进代理协议之前、仍保持 HTTPS/QUIC
应用层加密的原始 IP 包，不是 HTTP 解密或代理服务器外层连接抓包。

仅能采集经过本机 VPN 的流量。域名依赖 sing-box 的 DNS/FakeIP/协议识别信息；
无法识别的加密域名、绕过 VPN 的应用、ICMP、IP 分片以及超出解析范围的 IPv6
扩展头不保证采集。按 App/IP 筛选可用于无法识别域名的 TCP/UDP 连接。IP 按 TUN 内的原始目标地址
匹配；FakeIP 连接建议按 App 或域名筛选。
域名是在**连接级**匹配：同一条连接内复用的 HTTP/2 请求不会再按单个请求拆分。

为保留域名识别前的握手，先在内存暂存最多 10 秒、每连接 128 KiB、总计 8 MiB；
异步写队列最多 128 个包，连接表最多 4096 项。超限或磁盘故障会丢弃采集副本并
显示计数/错误，不因 PCAP 写盘阻塞 VPN 转发。未匹配的暂存内容不落盘。
TCP 新握手会重新分类，避免复用端口时继承旧域名；关闭连接短暂保留以采集尾包。

本地路径为应用私有目录 `files/captures/<server-and-host-hash>/`，不参与 Android
备份。正在写入的文件使用 `.part`，同步并关闭后原子重命名为 `.pcap` 才能上传。
应用重启会截去异常退出留下的半个记录，保留完整数据包。上传以文件 SHA-256
作为身份，服务端校验内容并幂等存储，断网重试不会重复创建文件。

### 服务端升级

PCAP 上传需要同时部署本次 C11 服务端与 `012_packet_captures.sql` 迁移。
网页 **设备详情 → PCAP 采集** 提供管理员文件列表、下载和删除。
每台设备服务端上限为 128 MiB / 1000 文件，满后拒绝新文件且客户端保留重试，
不会自动删除历史采集。旧版服务器返回 404 时请先升级服务端。

### 内核扩展与验证

`libbox-overlay/` 是基于固定 sing-box 1.13.12 revision 的 GPL 扩展：在 Android
TUN 和原网络栈之间透传包，并在路由识别后提供连接归属。`build-libbox.sh` 会调用
`apply-capture-overlay.py` 安装扩展；发布的内核源码包含这些改动。

```sh
python3 scripts/apply-capture-overlay.py
(cd .libbox-src && go test -race ./experimental/sbcapture)
./gradlew testDebugUnitTest lintDebug assembleDebug :app:assembleDebugAndroidTest
```

`PacketCaptureIntegrationTest` 是面向隔离 Android 测试设备的可选真 VPN 测试，
通过 instrumentation 参数 `captureEnrollment`、`captureAddress`、`capturePort`
和 `captureUdpPort` 接收临时控制面注册链接及 TCP/UDP 回显服务。
它验证 App/域名/精确 host 筛选、未匹配请求排除、握手和双向原始包、PCAP 封口、
上传后的本地状态。必须先授予该测试设备 VPN 权限；不要对个人已注册设备运行。
