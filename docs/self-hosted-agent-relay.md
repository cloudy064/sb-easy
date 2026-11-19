# GCP Oregon Agent 出口退役记录

2026-11-13 部署并验证了 Oregon 出口。2026-11-14 已删除 GCP 实例、20 GB 启动盘及专用防火墙、子网和网络。管理中心也已移除对应的受管主机、出口配置和 WireGuard 对端。

退役时，两台客户端均已应用移除节点后的配置。本机撤下了专用的 7892 入口，Claude 分流恢复为原有的自动选择，通过 7890 的连通检查返回 204。Windows 客户端保留了自定义分流规则。删除前的配置备份保存在管理中心。

## 退役前的节点

| 项目 | 部署值 |
| --- | --- |
| 客户端节点名 | `GCP Oregon · us-west1` |
| 区域 | `us-west1-a`（Oregon） |
| 规格 | e2-micro，20 GB pd-standard，Debian 12 |
| 代理入口 | WireGuard 内网的 17890 端口，带认证的 HTTP/SOCKS 混合入站 |

GCP 防火墙仅允许通过 IAP 连接 SSH。客户端通过 WireGuard 内网使用代理。

## 退役前的流量路径

本机应用 → 本机 Agent → 管理中心的 WireGuard 中转 → Oregon Agent → 互联网。目标网站看到的是 Oregon VM 的出口 IP。

Linux 客户端将 `anthropic.com`、`claude.ai`、`claude.com` 的域名后缀规则指向 Oregon 节点。本机 7890 按分流规则运行，专用的 `http://127.0.0.1:7892` 和 `socks5h://127.0.0.1:7892` 固定走 Oregon。部署时通过 7890 验证了 Claude 的出口地址。

```sh
curl --noproxy '' -x http://127.0.0.1:7890 https://claude.ai/cdn-cgi/trace
```

返回结果包含 Oregon 出口 IP、`loc=US` 和 `colo=SEA`。`colo` 是请求经过的 Cloudflare 机房，实例地区由 GCP zone 确认。

Windows 客户端同步了节点名称、目标地址和认证信息。在节点页选择“全部节点”或“其他 / 未知来源”可找到该节点。其余流量沿用各设备的分流配置和本地选择。

## Agent 与内网

Oregon VM 使用 `/usr/local/bin/sb-easy-agent`，sing-box 引擎内嵌在 Agent 进程中。WireGuard 内网接口由 `wg-quick@wg-sbe.service` 管理，只路由隧道子网。VM 的默认路由和 DNS 继续使用 GCP 出网，代理流量经 Agent 的 `direct` 出站发送。

- Linux 客户端沿用既有的 WireGuard 身份。本机 Agent 会删除字面值为 `wg-internal` 的出站 detour，因此使用 `wg-agent-transport` 标签保留显式内网拨号路径。
- Windows 客户端使用独立的 WireGuard 对端，`wg-agent-relay` 只允许访问 Oregon 节点的单个内网地址（`/32`）。Tailscale endpoint 和 `sb-easy-tailscale-direct` 由中心自动注入。
- Oregon 节点使用独立的 WireGuard 身份。

Windows 客户端当时使用完整配置，保留切换时的订阅节点快照。订阅节点或共享模板后续有变更时，需要同步到这份配置。

## 当时的运维配置

`sb-easy-agent.service` 依赖 `wg-quick@wg-sbe.service`。两个服务均已启用开机启动，安装用的 startup-script 元数据在部署完成后移除。Agent 环境文件和 WireGuard 配置含凭据，保存在部署环境中。

部署过程中也撤下了早期误建在管理中心的中继容器、受管主机、专用服务、出口配置和 nft 表。中心原有的 `sing-box.service` 和 TUN 继续运行。

## 退役前的验证结果

- Oregon Agent 实际运行的进程为 `sb-easy-agent`，二进制校验值与部署来源一致。
- 两台客户端的已应用配置版本（ETag）分别与管理中心下发给该设备的版本一致，两端运行正常。
- 本机通过 7890 请求 Claude trace，通过 7892 请求 api.ipify.org，两次均返回 Oregon 的出口 IP。
- 通过 7892 请求 OpenAI 的 `/v1/models` 时，未携带凭据的请求返回 401。Anthropic 的同类请求也返回 401，错误为 `x-api-key header is required`。
- 使用 curl 请求 Claude 登录页时收到 Cloudflare 验证页，状态码为 403。浏览器登录和对话情况未验证。
- 已在 Agent 服务重启后再次验证出口。VM 整机重启和 UDP 转发未做验收。
