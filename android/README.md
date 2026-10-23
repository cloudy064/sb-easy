# sb-easy Android

## 开发预览：Android 1.4.0（版本码 29）/ sing-box 1.14.3

当前应用版本从统一的 [`client-releases.json`](../config/client-releases.json) 读取，为 `1.4.0` / `29`；内核从 [`runtime-versions.json`](../config/runtime-versions.json) 读取，锁定 `1.14.3` / `7054cac5124465ffdb145870d7c01885566711b1`。已重建包含采集扩展的四 ABI libbox AAR，并适配 DNS 服务器迭代器、原生 JNI 证书存储、CrashReport 路径及新增平台回调；普通 VPN 不提供 root shell、二层桥接或 SSH 托管能力。1.4.0 已随 [1.1.0 开发预览](https://github.com/cloudy064/sb-easy/releases/tag/v1.1.0-preview.1) 提供五种测试签名 APK、对应源码和校验值；未经真机/模拟器验收。公开发布的 1.3.4 与本次签名相同，但实际系统覆盖安装仍待验证。

新版原生验证覆盖本地健康 API 的鉴权/TLS/截止时间，以及 Claude/GPT/自定义/默认分流和 DNS 出口、FakeIP/IPv6、HTTPS/SVCB 地址提示、核心重启映射和直连切换。IPv4-only TUN 通过显式 A 查询与 AAAA 空答案保留原行为，不再使用 `strategy` DNS 规则字段；1.14 已按服务器隔离 DNS 缓存，因此移除旧 `independent_cache`。

受管注册、配置、命令、状态与诊断请求默认要求 HTTPS，并拒绝 HTTP 重定向和注册响应更换服务器地址。开发/局域网测试可在注册页明确允许当前内网或回环 IP 的 HTTP 中心；不接受域名、公共 IP 或链路本地地址作为例外。该授权和设备令牌一起加密保存，不随偏好导出；已有 HTTP 注册默认不授权，可在停止 VPN 后到“设置 → 设备与中心”明确启用合格的局域网地址，或使用 HTTPS 重新注册。使用反向代理时应把中心公开地址配置为二维码所用的最终 HTTPS 地址。

## 开发预览：应用分组与健康策略

“代理 → 编辑规则”支持搜索已安装应用或填写包名，分组允许只匹配应用、只匹配域名或两者任选。域名与应用按 **OR** 匹配，同一包名不能落入多个组；Android 官方 Claude/ChatGPT 开关兼容旧配置。数据连接和 DNS 都跟随同一组，中心地址与受管 WireGuard 网络/DNS 保持优先，之后应用规则优先于普通目的域名。中心更新不会清除包名列表。

每组及默认代理可以选择固定节点，或在用户确认的候选池内启用自动模式（1–32 个节点，不含直连）。健康设置包括 HTTPS 探测 URL、间隔 30–86400 秒、超时 500–30000 ms、择优容差 0–10000 ms；默认“仅故障切换”，也可选择“改善超过容差才择优切换”。固定节点故障只提示，不更换出口；全部候选失败时保持当前出口，不回退直连。固定节点被中心移除、或自动池的节点全部被移除时，生成显式数据拒绝和 DNS REFUSED 规则，保留中心/私网的既有例外。独立订阅更新仍优先保留上次可用节点，要求用户先调整已移除的固定出口。

探测运行在 VPN 服务中，UI 退出后继续；切网后重新检测，核心/配置变化期间的旧结果会丢弃。运行时注入仅监听 `127.0.0.1` 的随机端口和随机 token，使用核心的逐节点测速 API；此 token 不进入已保存/展示配置。客户端总截止时间会取消挂起请求。关闭健康设置只影响后台探测，仍可手动测速；启用自动组需开启后台探测。

实现依据：[官方 URLTest](https://sing-box.sagernet.org/configuration/outbound/urltest/)、[路由规则](https://sing-box.sagernet.org/configuration/route/rule/)、[DNS 规则](https://sing-box.sagernet.org/configuration/dns/rule/) 与 sing-box 1.13.12/1.14.3 Clash API 源码。两版 URLTest JSON 都没有探测 timeout 字段，因此本机通过原生逐节点 API 执行完整健康策略。可设置 `SB_EASY_SINGBOX=/path/to/sing-box` 运行 `:core:testDebugUnitTest --tests '*NativeHealthApiTest' --rerun-tasks`，验证本机隔离核心的鉴权、TLS 探测、超时及选择组边界；未配置路径时该用例明确跳过。尚需真机验证应用归属、VPN 退出后任务及实际 DNS/IPv6 路径。

## 开发预览：独立模式与本机订阅

当前工作区新增独立模式：新装页面选择“无需中心，使用本机订阅”，在“订阅”页添加订阅 URL 或粘贴内容，导入通过核心校验后即可连接。支持 sing-box JSON、Clash YAML、普通分享链接和 Base64 订阅，节点协议为 Shadowsocks、VMess、VLESS、Trojan、Hysteria2、TUIC、HTTP、SOCKS。只提取代理节点；源路由、DNS、选择组和脚本不迁移。插件、文件路径和跨节点引用会被拒绝，并展示按输入序号说明的跳过原因。核心不支持的参数仍会导致校验失败并保留原配置。

- 独立配置由本机生成双栈 TUN、DNS 和服务分组。默认直连私网、代理公网，无首次启动必须下载的 Geo 规则；可继续编辑默认/Claude/GPT/自定义域名分组。受管模式保留原有 Geo 分流行为。
- 订阅支持添加、编辑、删除、手动更新和 15 分钟至 7 天自动更新间隔；0 表示关闭自动更新。Android JobScheduler 在 UI/VPN 退出后继续安排刷新，重启后保留任务，休眠及省电策略可能推迟执行。提供方返回 `Subscription-Userinfo` 时显示余量与到期时间。
- 下载限制 1 MB，每个订阅最多 512 节点，最多 16 个订阅。HTTPS 默认开启；HTTP 须在该订阅显式允许，HTTPS 重定向禁止降级。下载客户端不持有中心 token，禁止 URL 用户名/密码，不调用第三方订阅转换服务。
- 更新先解析、校验和应用，再提交缓存。下载/校验/应用/磁盘失败保留旧节点和配置；已选固定出口从更新内容消失时拒绝替换，须先改选出口。订阅更新保留本机分组与选择。已缓存配置优先启动，刷新在 VPN 建立后进行。
- 订阅原文、URL 和节点集合使用 Android Keystore AES-GCM 加密，运行配置保存在禁止备份的应用私有目录。独立/受管模式拥有独立缓存和路由偏好，须断开 VPN 才可切换；切换清除会话日志和连接统计，避免独立流量元数据进入中心。独立模式不发送心跳、遥测、测速或诊断，既有受管注册凭据保留在 Keystore 中以供切回。

本机验证：`ANDROID_HOME=/path/to/sdk ./gradlew :core:testDebugUnitTest :libbox-bridge:testDebugUnitTest :app:assembleDebug`。新增解析/下载和仓储测试覆盖模式/凭据隔离、缓存重建、固定出口消失、刷新失败及磁盘提交失败回滚。首轮生成配置检查通过 sing-box 1.13.12 `check`；当前 1.14.3 原生回归见本文开头。这些是 JVM/构建与配置检查，尚不等同真机 VPN/休眠/切网与 DNS/IPv6 泄漏验收。

## 开发预览：可选 PCAP 与 HTTP(S) 调试

“诊断 → 可选流量采集”恢复实验入口，默认关闭，每次必须明确启用本次会话；进程重启、VPN 停止或切换模式后清除授权。旧设置不会自动恢复采集。PCAP 保留在本机，独立模式禁止上传；受管模式仍须单独选择自动上传或手动上传。会话停止保留已有 PCAP 文件。

HTTPS 调试需要另外构建并安装 1.0.1 或更新的同签名插件。入口通过系统文件选择器读取 APK，检查包名、最低版本和主应用签名后交给 Android 安装；不自动下载旧版插件。使用 `extensions/http-debug/build-android.sh` 构建 arm64/x86_64 插件；需要与主应用相同的签名身份。仅对明确指定的域名及 TCP 80/443 截获，管理地址、WireGuard 网络/解析器和应用专属分流保留原优先级。回程 HTTP 入口与插件入口仅绑定 loopback，并分别要求每次生成的凭据。被截获的连接从原有域名分流选择出口；应用分组优先的流量不被调试覆盖。

停止调试先撤销拦截，再释放插件；插件异常断开撤销拦截并保留错误。正常退出删除插件本地 CA 私钥与会话，崩溃遗留文件在下一次插件启动前删除。已导出的 CA/HAR/PCAP 文件由用户管理。Android 普通应用不能卸载用户已安装的系统 CA：界面保留所有已导出证书的指纹与系统安全设置入口，实际读取信任存储确认这些 CA 都不存在后才能清除提醒。重新开始生成新 CA，旧 CA 需在系统设置移除。参考 [Android KeyChain](https://developer.android.com/reference/android/security/KeyChain) 与 [DevicePolicyManager](https://developer.android.com/reference/android/app/admin/DevicePolicyManager)。

JVM 测试覆盖会话授权、回程鉴权、路由优先级与退出配置；原生 1.14.3 测试验证未鉴权回程被拒绝、鉴权 CONNECT 与恢复原配置；Python 测试实际执行 HTTPS 截获、编辑重放、鉴权及 CA 清理。[Android 隔离验收说明](../docs/android-device-acceptance.md) 提供可运行的临时 C 中心、HTTP/UDP echo、PCAP 上传校验和显式 adb 驱动。已编译设备用例覆盖原始 TUN 采集、插件引擎、真实 VPN 调试 overlay/HAR/停止恢复/CA 轮换，以及同签名不同 UID 的私有文件与 IPC 拒绝；不安装系统 CA。当前无在线测试设备，**这些 instrumentation 尚未执行；本次开发预览仅提供实验入口，尚不构成移动抓包/HTTPS 调试的稳定恢复**。

## 开发预览：加密偏好与中心漫游

“设置 → 加密偏好备份与中心漫游”支持系统文件选择器导出/导入、Android 设备之间迁移以及中心私有槽位同步。文件采用共同 `sb-easy.preferences` v1 格式：PBKDF2-HMAC-SHA256（600000 次、16 字节随机盐、32 字节密钥）与 AES-256-GCM（12 字节随机 nonce、16 字节 tag、固定用途 AAD）。口令按 UTF-8 编码、不做 Unicode 归一化，至少 12 字节，不保存或上传；加密文件限制 1 MiB。丢失口令无法由中心恢复。

内容只包含本机订阅来源/缓存节点及独立、受管模式的一般域名/出口/健康偏好。手动粘贴来源重新生成为已接受节点的 JSON，丢弃原文中未采用的 WireGuard、路由或脚本内容。中心 Agent token、WireGuard 密钥、设备绑定、应用包名/应用专属规则、采集授权与 CA 没有对应的可导出字段。纯应用组不导出；混合组只导出域名部分。导入保留目标设备应用规则；节点/分组/应用出口冲突会拒绝导入，必须先调整本机设置。两种模式与中心注册保持不变。解密后先验证内容与核心配置并显示替换预览，VPN 运行时拒绝导入；预览后本机变更会要求重新预览，磁盘失败回滚原订阅/策略/配置。

中心漫游使用单独的 HTTPS 账户登录与 MFA 动态码/恢复码，保留登录流程绑定 cookie，完全不使用设备 Agent token。会话只留在此页面的内存中，退出账户会请求撤销会话。用户显式点击时才传输加密文件；中心只存密文。默认私有槽位 `android-personal`，读到的 revision 通过 `If-Match` 传入写入/删除，409 显示冲突并拒绝覆盖。删除后保留递增版本，旧设备不能用版本 0 恢复已删除的旧内容。当前 Android 拒绝其他平台的 payload，通用 envelope 不代表跨平台路由转换已经实现。

JVM 验证使用共享 [`testdata/preferences-v1.json`](../testdata/preferences-v1.json) Unicode 向量，WebCrypto 密文解密与重新加密逐字节一致；覆盖错误口令、篡改、参数/大小拒绝、白名单和设备规则隔离、预览冲突与磁盘回滚。真实 loopback HTTPS 测试覆盖 MFA cookie 绑定、账户 token、If-Match、409、删除版本及退出会话。尚未执行实际 Android SAF、系统键盘、中心账户登录和跨设备 UI 验收。


## 开发预览：插件签名目录、更新与恢复

Preview plugin lifecycle implementation is documented in the
[signed catalog specification](../docs/plugin-catalog-v1.md). In “HTTP(S) 调试 →
插件目录、更新与恢复”, signed catalogs authorize HTTPS downloads, exact artifact
hash/size, ABI, host/core/API compatibility and cumulative build revocations.
Catalog sequence rollback, changed payload at the same sequence, expired new
downloads and unknown publisher keys are rejected. Known revoked installed
builds are stopped and cannot be started through the local APK path either.
Before replacement, a catalog-authorized installed APK is copied and verified;
up to two package versions and their signed receipts are retained. Explicit
offline recovery rechecks receipt, hash, compatibility and known revocations.
Android recovery to a lower version requires OS-confirmed plugin removal and
reinstallation; it is not an atomic rollback and ends capture.

The compiled publisher allowlist defaults to empty until a release owner provides
a public trust configuration; remote installs then remain unavailable. Explicit
local-file installation still requires the actual APK signer to match the host,
and applies the same package/manifest/compatibility/revocation checks. Shared
external signing parameters for host and plugin are in `signing.gradle`; neither
keys nor passwords are committed. Current APKs use the test/debug identity
`14a2ddad…`, which also matches the published Android 1.3.4 APK (its published
ARM64 SHA-256 is `7786f8f06381ea06a01a4e0037183cfb90c58ea0021a4730d452fb0202415513`).
Some earlier local development builds used `5d7a2a82…`; those different-signature
installations cannot accept these APKs as an in-place upgrade. Do not uninstall
an official 1.3.4 installation merely because of the preview version label.
Use an explicitly chosen keystore for consistent upgrade identity and perform
real installation/recovery/UID acceptance before a stable release.

## 开发预览：主应用更新与旧版恢复

“设置 → 应用与内核更新、旧版恢复”使用独立应用签名目录。目录公钥默认空，正式发布者尚未配置时更新关闭；通过 `-PsbAppCatalogKeys=/absolute/public-keys.json` 注入外部公钥。下载同时检查实际 APK 的版本、单一当前签名证书、ABI/min SDK，以及由实际 AAR 构建生成的内核版本、源码 revision、overlay 和逐架构原生库摘要；内核跟随应用整体更新。目录序号防重放、累计撤销、HTTPS/长度/摘要验证和原子缓存提交均在本机执行。

安装前保存已验证的当前 APK，并强制通过系统文档选择器导出**应用外救援 ZIP**：恢复 APK、签名目录、加密偏好与无需打开应用即可阅读的恢复说明一起保存。只有写入后重新读回、摘要匹配，且当前 APK/目标 APK/偏好未变化时才允许提交 Android PackageInstaller；安装仍要求断开 VPN 和系统确认。新版启动即崩溃时也能从系统文件管理器取得救援材料。当前版已撤销时不作为恢复候选，无安全旧版时明确提示只能保存目标 APK、不能回退。较旧 APK 仍需手动卸载重装；卸载丢失设备秘密、缓存及本机防重放/撤销状态，受管设备需重新注册，不声称无损或静默回滚。完整发布命令、信任格式和恢复限制见 [Android 应用更新协议](../docs/android-app-updates-v1.md)。

本地 JVM/OpenSSL/HTTPS 负例与 APK 构建检查不等于真机自更新验收。`AppUpdatePackageTest` 可在设备上检查实际安装包的 manifest、证书与内核来源；系统确认、自更新重启、取消/失败及卸载恢复仍需在线设备验收，当前没有正式更新源或生产信任密钥。

## 1.3.4 — packet capture temporarily withdrawn

Version code 28 removes mobile capture features while preserving ordinary VPN,
local routing, traffic statistics and logs.

Android packet capture (PCAP and HTTP(S) debugging) is temporarily withdrawn.
The PCAP entry and background capture/upload are disabled, including saved capture
preferences. Existing capture files are preserved. Ordinary traffic statistics remain available.
The client no longer offers
the plugin store entry, CA export, session window, or VPN interception overlay.
Previously installed plugin APKs and user CA certificates can be removed through
Android system settings.

## 1.3.2 maintenance release

Version code 26 rebuilds the existing 1.3.1 feature set from the current source
revision. Android plugin extraction is not included. The published APKs retain
the previous debug signing identity for upgrade compatibility; these are test
builds, not production-key-signed builds. All five APK variants, 89 JVM tests,
and lint pass. No new physical-device VPN acceptance is claimed for this release.
The pinned native libraries are unchanged from the published 1.3.1 ARM64 APK.

This directory contains the managed and standalone sb-easy Android client. Current builds embed sing-box
1.14.3 through `libbox.aar`; no root access, external executable or administrator account is required on the phone.
The authenticated health controller binds only to loopback and is created per VPN runtime.

“设置 → 系统 VPN”分别说明 Always-on 与“阻止未通过 VPN 的连接”，并提供系统 VPN 设置入口。Android 10/API 29+ 通过当前运行中的 `VpnService` 读取两项真实状态；旧系统或服务未运行时显示未知，不把历史值当作当前保护。应用不能替用户打开系统断线阻断。实际退出、切网、DNS/IPv6/UDP 阻断仍需设备联网验收。

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

In the published 1.2.8 behavior, application routing precedes every destination-based route, including
private-address, management-host and management-endpoint exceptions; sniffing and
DNS interception still run first. Non-matching apps retain these exceptions and
the established domain/default policy. All application DNS rules now precede
all group-domain and management DNS rules, so a ChatGPT-owned lookup for a Claude
hostname uses GPT's DNS/FakeIP policy, regardless of group ordering. Bootstrap
DNS for proxy nodes remains explicitly direct to avoid resolver loops. The preview custom-application implementation above restores management/WireGuard exceptions ahead of app matching.

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
- Go 1.25.5 or newer, as required by sing-box 1.14.3

```sh
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk
export ANDROID_HOME=/path/to/android-sdk

./scripts/build-libbox.sh
./gradlew testDebugUnitTest lintDebug assembleDebug
```

The generated AAR and APK are intentionally ignored by Git. The libbox build
is pinned to sing-box revision
`7054cac5124465ffdb145870d7c01885566711b1`, gomobile 0.1.12, and NDK
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

Historical test deployments used plain HTTP. Current enrollment requires HTTPS
unless the user explicitly allows a literal private or loopback IP for local
testing. There is no option to disable TLS certificate verification.

## Verification

The checked-in project is covered by Kotlin config-inspection tests, Android
lint, APK signing/ABI inspection, C++ enrollment/rendering/HTTP contract tests,
and an end-to-end preflight that feeds a rendered Android profile to sing-box
1.14.3 `check`. A physical Android device remains necessary for the final VPN,
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
exact corresponding-source archive alongside the APKs. New 1.14.3 builds must ship
`sing-box-1.14.3-sb-capture-source.tar.gz`, including the capture overlay and build scripts;
previous 1.3.4 artifacts retain their matching 1.13.12 source archive.

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

## 原始流量采集（1.3.4 历史状态）

已发布的 1.3.4 不提供 PCAP 或 HTTP(S) 抓包。网络包采集入口、后台采集初始化及自动上传循环已移除；
VPN 启动时显式关闭内核采集，因此旧版本保存的启用设置也不会恢复采集。
已有私有目录中的 PCAP 文件保留，不会自动上传。普通流量统计、路由测试和日志仍可使用。

固定版本的 libbox 仍包含采集扩展，当前客户端不启用它；相关底层代码及文件格式测试保留。
Windows 抓包和服务端历史 PCAP 管理不受此变更影响。
