# Tailscale 内网试用

服务端和 Linux Agent 的实现位于 `c/`，Windows 原生实现位于 `windows/`，
均使用 C11。Tailscale 数据通道由已有 sing-box 引擎的 `tailscale` endpoint
提供，不需要在 sb-easy 进程旁额外启动 `tailscaled`。

## 先更新运行程序

更新面板和参与测试的 Agent。Linux 内嵌引擎必须重新构建，构建标签中需要
`with_tailscale`；仅更新前端或数据库不足以启用此功能。当前项目固定的核心
版本见 `config/runtime-versions.json`。使用独立 sing-box 时，运行
`sing-box version` 确认包含 `with_tailscale`。

```sh
# 面板
docker compose build sb-easy
# 统一 Linux Agent 镜像：构建后按现有部署流程更新相应节点
docker build -f c/Dockerfile.unified --target runtime -t sb-easy:tailscale-agent .
```

构建不会自动部署，也不会自动注册到你的 Tailnet。

## 按主机启用

1. 在 Tailscale 管理后台创建用于设备注册的 Auth key。为每台设备使用单独的
   key，或在明确需要多设备注册时使用 reusable key。不要把 key 写进共享
   Profile、脚本、截图或工单。
2. 在面板的主机新增或编辑窗口启用 **Tailscale**，填写 Auth key 和便于
   识别的节点名。默认使用 Tailscale 官方控制服务器；使用 Headscale 时填写
   自己的控制服务器地址。
3. 先选择两台测试主机，并分别启用。等待 Agent 拉取配置并重载，再到 Tailscale
   管理后台确认这两台设备在线，并取得各自的 `100.x.y.z` 地址。
4. 用对方的 Tailscale 地址访问服务。旧的 `10.59.32.x` WireGuard 地址不会
   自动改成 Tailscale 链路；继续访问旧地址不能验证这次切换。

Auth key 在主机列表和编辑响应中不会回显。编辑时留空表示保留原 key，明确
选择清除才会删除保存的 key。注册成功后的节点身份由本机状态目录保存；
日常重载无需重新注册。不要在设备之间复制该状态目录，否则会复制设备身份。
清除或替换 Auth key 不会注销已注册的节点；已有节点身份仍以本机状态为准。

内嵌 Linux 引擎把状态放在配置文件旁的 `tailscale/<标签摘要>/`，默认 Docker
部署位于挂载的 `/app/data` 中。Windows 使用受保护的 `core-work`，Android
和 Apple 使用应用私有数据目录。Linux 桌面代理使用用户数据目录下的 `core`，
其系统隧道服务使用 `/var/lib/sb-easy-desktop`，不会把身份仅存在重启即丢失的
`/run` 中。独立运行 sing-box 时，请确保配置中的状态目录也位于持久磁盘。

默认只把 `100.64.0.0/10` 和 `fd7a:115c:a1e0::/48` 的目的流量送入 Tailscale，
公网代理策略仍由现有 Profile 决定。端点收到的连接直接访问本机或其可达的
内网服务。Tailnet 的访问权限仍由 Tailscale 的 ACL/grants 控制。

这是 sing-box 内嵌端点，不会额外安装系统 Tailscale 网卡。普通应用需要经
sb-easy 的 TUN 或现有 HTTP/SOCKS 代理访问这些地址。首轮测试请用 IP，
本功能不会自动配置系统 MagicDNS。

## 访问节点背后的 LAN

例如通过家里的节点访问 `192.168.50.0/24`：

- 在家中节点的 **发布子网** 中填入 `192.168.50.0/24`。
- 在 Tailscale 管理后台批准该路由，并确认访问策略允许测试设备访问它。
- 在访问端启用 **接收子网路由**；核心会按 Tailnet 公告的可用路由匹配。
  **额外路由网段** 可用于明确指定需要送入 Tailscale 的目的网段。

不要把本机已经直连的 LAN、管理入口或全部公网范围随意加入额外路由。
发布出口节点仅向 Tailnet 公告本机的出口能力；本功能不自动把其他主机的
默认出口切到该节点。

## 与 WireGuard 对比和回退

Tailscale 仍使用 WireGuard 加密。它的潜在收益来自自动穿透、节点直连和
中继路径选择，不能保证比现有自建 WireGuard 更快。测试时让两种方式连接
同一对设备，使用同一个服务和相近时间段，分别记录吞吐、延迟和丢包。

可以在目标主机临时启动 iperf3，再分别用旧 WG 地址和 Tailscale 地址测试：

```sh
# 接收端
iperf3 -s
# 发送端：在 TUN 生效的环境运行，替换为同一接收端的两个真实地址
iperf3 -c <WireGuard-IP> -t 20
iperf3 -c <Tailscale-IP> -t 20
iperf3 -c <Tailscale-IP> -t 20 -R
```

没有 TUN 时，iperf3 不会使用 HTTP/SOCKS 代理，不能以此判断内嵌端点是否
可用；可以先通过已配置的代理下载同一个较大的测试文件。单次 ping 也不能
代表应用吞吐。

用 Tailscale 管理后台、核心日志或同一 Tailnet 中官方客户端的
`tailscale ping <peer>` / `tailscale status` 区分直连与中继。官方 CLI
查看的是它自己的 daemon，不能直接查询 sb-easy 的内嵌端点；旁路设备的
结果也不能证明两个 sb-easy 端点之间一定直连。

启用 Tailscale 后，托管客户端不再注入内嵌 WireGuard 端点。已有主机的
WG 成员配置仍然保留；Linux 独立 WG 网卡也不会被此开关自动关闭。
关闭 Tailscale、保留原 WG 成员配置并等待配置重新下发即可回退。确认全部
设备迁移完成后，再单独决定是否关闭服务端 WG hub。

## 参考

- [sing-box Tailscale endpoint](https://sing-box.sagernet.org/configuration/endpoint/tailscale/)
- [Tailscale 连接类型与直连/中继](https://tailscale.com/docs/reference/connection-types)
- [Tailscale Auth keys](https://tailscale.com/kb/1085/auth-keys)

## 本次验证范围

已通过前端类型检查、构建和设备配置界面的浏览器检查；C 核心在 MSYS2/GCC
下以警告视为错误完成编译，`store_test`、`http_hosts_test`、`tailscale_test`、
`config_renderer_test`、`agent_core_test` 五组测试通过。测试实际生成的配置
通过固定版本 sing-box 1.14.3 的 `check`。Windows 三组相关原生测试、
Apple/Linux 共用 C 核心测试和 Go 状态目录测试通过。

Android 测试因本机 Gradle 建立回环连接失败而未进入编译；Linux 原生镜像、
ASan/UBSan 和移动设备上的实际连接仍需相应环境验证。本次没有部署、使用
真实 Auth key 登录 Tailnet 或进行线上性能测试。
