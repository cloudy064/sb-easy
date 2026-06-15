# sb-easy 概念与功能说明

> 目标读者：使用者 / 维护者。回答"左边这些菜单到底是干什么的"，并指出当前设计的
> 结构性问题（为什么 Nodes 是空的、Proxies 报错），作为下一步重构的依据。
> 写于 2026-06-15，对照当前 `master` 实测。

---

## 1. 一分钟心智模型

sb-easy 同时管三件事，目前在 UI 里被拆成了 12 个菜单，彼此关系并不直观：

```
                 ┌─────────────────────────────────────────────┐
   你（管理员）── │  面板 (sb-easy)                              │
                 │                                              │
                 │  A. 谁能连进来（WireGuard）                   │
                 │     · Clients   = WG 终端（手机/笔记本）       │
                 │     · Hosts     = 受管机器（跑 sing-box 的节点）│
                 │                                              │
                 │  B. 往哪里代理（sing-box 出站）                │
                 │     · Nodes         = 手动加的上游代理节点      │
                 │     · Subscriptions = 订阅链接（批量拉节点）     │
                 │     · Profiles      = 配置画像（dns/入站/规则）  │
                 │     · Config        = 最终生成的 config.json    │
                 │                                              │
                 │  C. 实时观测与控制（Clash API）                │
                 │     · Monitor   = 流量/连接/内存（实时）        │
                 │     · Proxies   = 代理组，切节点（实时）        │
                 │     · Logs      = 日志流（实时）               │
                 └─────────────────────────────────────────────┘
```

A 和 B 是**配置**（写进数据库 → 生成 config）；C 是**运行态**（直接问正在跑的 sing-box）。

---

## 2. 每个菜单到底是什么

| 菜单 | 数据来源 | 是什么 | 现状（本机实测） |
|------|----------|--------|------------------|
| **Dashboard** | 汇总 | 概览：客户端数、节点数、流量 | — |
| **Monitor** | Clash API（实时 WS） | 实时流量曲线 / 连接列表（可断开）/ 内存 | 依赖能连上 sing-box |
| **Logs** | Clash API（实时 WS） | sing-box 日志流 | 同上 |
| **Hosts** | `hosts` 表 | **受管机器**：跑 sing-box 的节点（服务器自己 = `self`，外加 agent 机器）。每台分配 Profile + 出站 | 仅 1 台 `self` |
| **Profiles** | `config_profiles` 表 | **配置画像**：一份 sing-box 配置模板（log/dns/inbounds/route），代理节点会被注入成 outbounds | 2 个：`Default`、`Imported (config.d)` |
| **Clients** | `wireguard_peers` 表 | **WG 终端**：手机/笔记本，下载 `.conf`/扫码连进内网 | 1 个 |
| **Nodes** | `proxy_nodes` 表 | **上游代理节点**：手动添加的 SS/VMess/Trojan/VLESS/Hysteria2/TUIC | **0 个** ⚠️ |
| **Proxies** | Clash API（实时） | **代理组**：读正在跑的 sing-box 的 selector/urltest 组，点一下切换当前节点 | 实时显示 68 个 |
| **Subscriptions** | `subscriptions` 表 | **订阅**：粘贴机场订阅链接，定时拉取节点 | **0 个** ⚠️ |
| **Config** | 渲染生成 | 预览/下载最终 `config.json` | — |
| **Users** | `users` 表 | 后台账号（仅 admin 可见） | — |
| **Settings** | env / 设置 | Clash API 地址、密钥等 | — |

---

## 3. ⚠️ 核心问题：两套"代理"互不相通

这是目前最大的困惑来源。

**现状**：这台机器正在跑的 68 个节点（香港 Z01… / IEPL …）来自一份**整体导入的配置 blob** —— Profile 里的 `Imported (config.d)`，当初把手工写的 `/etc/sing-box/config.d/` 合并进来直接塞进了 Profile 的原始 JSON。

于是：

- **Proxies（实时）** 能看到这 68 个组/节点 ✅ —— 因为它直接问正在跑的 sing-box。
- **Nodes（结构化）** 是空的 ❌ —— 这些节点从没进过 `proxy_nodes` 表。
- **Subscriptions** 也是空的 ❌ —— 它们不是从订阅拉的，是手写 blob。

**结果**：实际在跑的代理，面板的结构化模型（Nodes / Subscriptions / 规则）完全不知道它们的存在；
你在 Nodes 里看不到、改不了、加不了规则。Clash 那种"订阅 + 手动节点 + 规则 = 一份配置，可视化编辑"的体验，目前**断在这里**。

**要的方向**（下一步重构）：让**结构化模型成为唯一事实来源**——节点（手动 + 订阅拉取）、代理组、规则都在面板里管，由面板生成 `config.json` 下发；原始 JSON 仅作为高级逃生口保留。

---

## 4. "Proxy Groups 报错 Could not reach the sing-box Clash API"

**结论：不是代码 bug，Clash API 本身是好的。** 本机实测：

```
$ curl -H "Authorization: Bearer <secret>" http://127.0.0.1:9090/version
{"meta":true,"premium":true,"version":"sing-box 1.13.12"}   # 200 ✅
```

后端 `/api/sing-box/proxies` 会把请求转发到"解析出来的 Clash 目标"。报 "Could not reach" 只可能是后端那一跳 `reqwest.send()` 失败，常见两种：

1. **你访问的面板实例旁边没有可达的 sing-box**（例如开发实例 / 另一台没跑 sing-box 的机器）。
2. **顶部 Host 选择器选了某台远程 Host**，而它的 Clash 要走 WG 内网回程——但本机 `WG_ENABLED=false`，回程不通 → `send()` 失败 → 报错。

**待修**：
- 错误信息要可操作（区分"未配置 Clash API" / "目标不可达 <url>" / "401 密钥错误"），而不是笼统一句。
- Host 选择器缺省回落到 `self`，远程不可达时降级提示而非直接红屏。

---

## 5. 待重构清单（与本文对应）

1. **合并 Hosts + Clients** → 一个统一的"设备/端点"视图（WG 终端 vs sing-box 节点用类型区分）。
2. **代理配置 Clash 化** → Nodes（手动）+ Subscriptions（订阅拉取）+ Rules（规则）三段式，面板为事实来源并生成配置。
3. **每个端点可引入代理** → 端点级选择用哪些节点/组/规则（per-device profile）。
4. **修 Clash API 报错** → 可操作错误 + 缺省回落 self。
5. **左侧菜单按功能分组** → 见下。

---

## 6. 建议的菜单重组（按功能分组）

当前 12 个平铺项 → 3 组：

```
概览
  · Dashboard

网络 / 设备
  · Devices        (合并 Hosts + Clients)

代理
  · Nodes          (手动节点 + 订阅，合并 Subscriptions)
  · Rules          (规则，新增)
  · Proxy Groups   (原 Proxies，实时切换)
  · Config         (生成的配置)
  · Profiles       (高级：配置画像)

观测
  · Monitor
  · Logs

系统
  · Users
  · Settings
```

> 具体分组与命名在重构定稿后会回填到本文与 `deployment.md`。
</content>
</invoke>
