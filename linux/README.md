# Linux 原生桌面端

当前开发版 **0.1.0**，版本来自 [`config/client-releases.json`](../config/client-releases.json)。本目录提供 C11 / GTK 3 原生窗口，复用 C agent 客户端、订阅解析和内嵌 sing-box；无浏览器窗口或外部核心可执行文件。[1.1.0 开发预览](https://github.com/cloudy064/sb-easy/releases/tag/v1.1.0-preview.1) 已提供 Debian 12 amd64 未签名 DEB、对应源码、许可证和校验值；真实桌面授权/休眠/切网仍待验收。当前没有正式 APT 地址或发行签名密钥。

## 使用

打开桌面菜单中的 **sb-easy**。需要可用的 Secret Service 密钥环（例如已解锁的 GNOME Keyring）和桌面 D-Bus 会话；密钥环不可用或锁定时明确报错。应用不以 root 身份运行。

- **独立模式**：新建连接，粘贴 URI、Base64、Clash YAML 或 sing-box JSON，或添加 HTTPS 订阅。文件导入仅接收普通文件，最大 512 KB。节点凭据不会作为脚本或命令执行。更新失败保留此前有效节点；显示订阅提供的流量、期限及跳过节点数量。
- **托管模式**：在设置输入一次性 enrollment 链接，或打开 `sbeasy://enroll` 链接后确认。保存设备身份、按 ETag 拉取中心配置、上报真实状态、流量和测速结果。桌面不宣告共享代理入口能力，不消费服务器 ingress leases。重新绑定或退出管理会清除旧身份与旧配置。
- **连接**：普通连接启动当前用户的带认证本地 HTTP/SOCKS mixed 代理。界面提供实际策略组、节点选择、测速、实时流量及连接列表。关闭窗口会断开并清理当前运行时。
- **系统代理**：可选择写入 GNOME 的 HTTP/HTTPS 系统代理设置；只接管能够携带认证的协议。其他桌面、浏览器以及忽略系统代理的程序需要自行配置带认证的代理。已有设置先备份；断开时只恢复仍等于本应用所写值的字段，保留其他程序后来的修改。
- **TUN**：由 system D-Bus 激活单独的 root 服务，经 Polkit 管理员授权；请求受 D-Bus 连接与 UID 绑定。客户端退出或总线断开时停止隧道。服务只支持开始、停止、状态、选择、测速和 HTTP 探测，不接受程序路径或任意命令。
- **分流与诊断**：可添加域名组、Linux 进程名/绝对路径规则。进程识别依赖内核可见连接，普通系统代理无法可靠识别原始程序；需要此功能时使用 TUN。自定义规则对应的 DNS 使用相同出口，管理、内网、WireGuard 和精确目标保护规则优先。诊断执行真实 HTTP GET，并尽可能从核心连接记录关联规则与出口；请求结束太快而未观察到记录时明确显示不可用。

配置、订阅 URL、节点凭据和设备身份统一保存在 AES-256-GCM 加密 vault，随机密钥仅存于当前用户的 Secret Service 默认持久集合。目录为 0700、文件为 0600；文件锁和版本检查防止并发覆盖。HTTPS 验证使用系统信任库，远程 URL 禁止用户信息和重定向；HTTP 仅允许 loopback 测试。日志及界面错误不回显 token 或完整配置。

TUN 只接管发起连接用户的 UID，使用 `sbeasy0`、路由表 42041、规则区间 12040–12050，以及 `198.18.252.1/30` / `fd7e:5342:4541:5359::1/126`。为避免上游全局 nftables 表与另一实例冲突，`auto_redirect` 关闭。已有同名接口、该表中的路由或该区间的策略规则会阻止启动。DNS 设置通过核心的 Linux resolver 集成管理；共享系统 resolver 的行为仍须按目标桌面环境验收。此实现没有承诺系统 kill switch、崩溃断网或所有桌面环境代理兼容性。

系统代理异常退出后的恢复：

```sh
sb-easy-desktop --recover-proxy
```

该命令只恢复当前用户留下的代理快照，不需要运行核心或 root 权限。

## 构建与测试

推荐发布构建基线为 Debian 12（amd64 首批；CMake 也识别 arm64）。依赖 GTK 3.24+、GLib 2.66+、libsecret、Polkit、OpenSSL、libcurl 7.85+、SQLite、libyaml、CMake 3.24+、Python 3.11+、Ninja、Git、Go（最低版本见运行时清单）。本机测试另需 Xvfb、dbus-run-session、GNOME Keyring。

```sh
linux/scripts/build.sh
ctest --test-dir build/linux-desktop -R '^linux_' --output-on-failure
```

`prepare-core.sh` 校验 `config/runtime-versions.json` 的 sing-box 精确 commit，复制本仓库完整 bridge、应用经 SHA-256 校验的依赖修复，再生成 c-archive。输出的 `provenance.json` 记录核心版本、commit、bridge 和依赖修复摘要。只在脚本自行创建的目录工作；可设置 `SBL_CORE_SOURCE` 指向本地上游源码镜像，仍校验精确 commit。CMake 引用完整 `sb_core`，不下载运行时可执行文件。

可重复的 Debian 环境构建、运行测试并导出 DEB：

```sh
linux/scripts/package.sh build/linux-package
```

该脚本仅构建新容器，无宿主网络、端口发布或生产数据挂载。`linux/packaging/Dockerfile` 的最终 package 阶段导出 DEB、核心 provenance 和实际 GTK 测试截图。包包含原生程序、D-Bus/Polkit/systemd 配置、桌面入口及更新工具；安装服务不自动发起连接。必须保留正常桌面会话的 Polkit 认证代理。

普通测试覆盖：加密与损坏拒绝、目录/URL 校验、真实内嵌核心 HTTP 出口和策略持久化、无效更新恢复、私有 D-Bus 越权拒绝与调用者消失清理、真实 Secret Service 锁定行为、GNOME 代理恢复、实际 GTK 控件点击，以及托管 enrollment / ETag / 状态 / 解绑。测试使用临时目录、随机 loopback 端口和私有 D-Bus，不操作系统 TUN。

独立 APT 验收仅在新容器运行，使用明确标注的临时测试密钥及容器内 CA：

```sh
docker build -f linux/packaging/Dockerfile --target dependencies -t sb-easy-linux-deps:0.1.0 .
docker run --rm --network none -e SBL_APT_FIXTURE=disposable-container \
  -v "$PWD:/src:ro" sb-easy-linux-deps:0.1.0 python3 /src/linux/tests/apt_fixture.py
```

测试实际调用 APT，覆盖 Signed-By、错误指纹、metadata/payload 篡改、升级、固定版本、拒绝意外降级、失败安装恢复、离线回退和回退缓存完整性。它不会生成或发布正式签名密钥。

实际 DEB 安装/卸载和真实内核 TUN 验收也可在一次性容器中运行：

```sh
docker build -f linux/packaging/Dockerfile --target build -t sb-easy-linux-tested:0.1.0 .
docker build -f linux/tests/Package.Dockerfile -t sb-easy-linux-package-test:0.1.0 .
docker run --rm --network none --user root --cap-add NET_ADMIN --device /dev/net/tun \
  -e SBL_TUN_FIXTURE=disposable-container sb-easy-linux-tested:0.1.0 \
  python3 /src/linux/tests/tun_fixture.py /src/build/linux-desktop/linux_tun_test
```

TUN fixture 拒绝任何带外部网络接口的容器，只在自己的网络命名空间创建临时 dummy 接口。它验证既有规则/路由表冲突不被覆盖、UID 1000 的 IPv4/IPv6 HTTP 通过真实 TUN 进入代理、停止后接口及策略规则恢复。安装测试验证实际依赖解析、安装文件权限、systemd unit、生产程序加载/权限拒绝，以及卸载保留用户数据。这些测试已在开发环境通过；它们不等价于桌面 Polkit 对话框、systemd-resolved DNS 或真实网络切换验收。

## 可信更新、固定与回退

只支持管理员配置的 HTTPS APT 仓库；正式仓库 URL、公钥和完整指纹必须由发行方通过独立可信渠道提供。不能把与安装包同站下载的未知公钥直接当作已验证信任根。普通 DEB 本身不提供发布者身份验证；线上发行依赖 APT 的签名 Release → Packages hash → DEB hash 链路。

使用已独立核对指纹的公钥配置仓库，示例参数需替换为真实发行值：

```sh
sudo /usr/libexec/sb-easy-desktop/configure-repository.py \
  --repository https://packages.example.org/sb-easy --suite stable \
  --key ./verified-archive-public.asc --fingerprint FULL_VERIFIED_FINGERPRINT
sudo /usr/libexec/sb-easy-desktop/update.py --check
sudo /usr/libexec/sb-easy-desktop/update.py
```

配置工具拒绝私钥、错误完整指纹、多主公钥及不安全目的路径。生成单独的 Deb822 `Signed-By` 源、公钥 keyring 和管理员拥有的信任记录。更新工具仅使用该仓库解析桌面包，拒绝 insecure/unauthenticated 模式，再校验包名、版本和架构；系统依赖仍由正常受信任的 OS 软件源提供。

```sh
sudo /usr/libexec/sb-easy-desktop/update.py --pin 0.1.0
sudo /usr/libexec/sb-easy-desktop/update.py --unpin
sudo /usr/libexec/sb-easy-desktop/update.py --rollback PREVIOUS_VERSION
```

固定写入 APT preference 并设置 dpkg hold；正常更新拒绝意外降级。已验证 DEB 缓存位于 `/var/cache/sb-easy-desktop/<version>/`，带 SHA-256 收据，回退先校验缓存，不必连接仓库；成功回退后固定该版本。安装失败时如旧版本已通过本工具缓存，则尝试恢复它。直接安装的旧 DEB 没有缓存时不宣称可自动回退，需先从受信任仓库保留旧包。回退不是文件系统快照，不能撤销第三方依赖或任意 maintainer script 的外部副作用。用户配置在用户目录中，卸载包不会删除 vault。

发行者在受控环境提供外部 GPG 密钥，可生成本地签名仓库：

```sh
python3 linux/scripts/publish-apt.py --packages ./reviewed-debs --output ./apt-repository \
  --gpg-key FULL_MAINTAINER_FINGERPRINT --gnupghome /secure/external-signing-home
```

该工具生成 Packages、SHA-256/SHA-512、带有效期的 Release、InRelease 和 Release.gpg，不上传文件。应保留旧版 DEB、完成对应源码/许可证归档、核对每个架构、通过 HTTPS 原子发布目录，并在到期前重新签名。不要将测试密钥纳入正式发行。

## 发布前桌面 / TUN 验收

在隔离 Debian 12 / Ubuntu 24.04 虚拟机完成：原生桌面安装、密钥环登录/锁定、真实 Polkit 拒绝及授权、非所有者 D-Bus 请求、IPv4/IPv6 TUN 出口、DNS 与 WireGuard/内网保护、进程规则、睡眠/恢复、网络切换、连接时杀死 UI/服务以及重启恢复。记录连接前后 `ip rule`、路由表 42041、`resolvectl status` 与 GNOME 代理设置；停止后应无 sbeasy0/残留路由或已接管代理。验证与另一个代理程序共存及包升级/卸载时服务清理。

Linux 上的普通构建、私有总线和 GTK 测试不代表这些桌面授权、真实 TUN/DNS 与硬件网络验收已通过。CI 会提供可检查的构建产物；发布状态仍以中心版本清单为准。
