# sb-easy 多节点中心化架构改造方案

> 状态：设计草案（2026-06-13）。本文只做架构设计，不含实现代码。
> 目标读者：项目维护者。决策点集中在末尾「待确认」一节。

## 实施状态（2026-06-13 起）

| 项 | 状态 | 说明 |
|----|------|------|
| 迁移 003 | ✅ | `hosts` / `host_outbounds` / `config_profiles` 表；`wireguard_peers.host_id`；seed `default` profile + `self` 内置主机 |
| Host 模型 + 渲染重构 | ✅ | `generate_full_config` → `render_host_config(template, nodes)`；inbound/route 下沉为 profile 模板；有代理时输出与旧逻辑一致（已验证）|
| Hosts CRUD API | ✅ | `/api/hosts` 增删改查、`/profiles`、`/{id}/token`、`/rotate-token`、`/{id}/outbounds`（出站分配）|
| Agent 协议 | ✅ | per-host token 识别身份、按机渲染专属配置（ETag/304）、`/api/agent/status` 心跳；旧全局 `AGENT_TOKEN`→self 向后兼容；agent 二进制补 bearer 鉴权 + 状态上报 |
| 每机 Clash 路由 | ✅ | `singbox_proxy`/`singbox_ws` 支持 `?host=<id>` 路由到各机 Clash API（含 secret），缺省走本地 |
| 前端 Hosts 视图 | ✅ | 主机列表/在线状态/能力徽章/安装命令+token/出站分配/增删/WG 配置下载；Monitor·Proxies·Logs 加 Host 选择器；Nodes 文案改 Proxies |
| WG peer 自动配置 | ✅ | WG 成员 Host 自动 provision 一条 /32 peer（精确路由 reachback）、回填 `wg_address`/`wg_public_key`/默认 `clash_api`；`GET /hosts/{id}/wg-config` 下发主机 WG 配置；删除/切换成员自动 de/provision；Clients 列表排除 host-peer |
| 配置变更感知 | ✅ | 决策：不引入长连，保持轮询、缩短间隔（用户选择）。agent 默认间隔 30s→**10s**、可配、2s 下限；`agent/.env.example` 文档化该旋钮 |

构建验证：`cargo build`（backend+agent）通过；前端 `vue-tsc` + `vite build` 通过。运行时冒烟：迁移/seed、per-host 配置渲染、ETag 304、按机出站分配、agent 鉴权（401/200）、状态上报、全局 token 向后兼容、`?host=` 路由解析、WG host-peer provision/deprovision 全生命周期（含 update 切换成员）、wg-config 下发，均无 panic。

**阶段1 + 阶段2 全部落地。** 配置变更感知按用户决策用短间隔轮询（10s）解决，不做长连 push。

### 阶段3（2026-06-14 全部完成）

| 项 | 状态 | 说明 |
|----|------|------|
| #1 下行命令通道 | ✅ | `host_commands` 队列（migration 004）；面板入队 reload/restart，agent 轮询拉取执行 + ack 回报（含跨主机 ack 守卫、self 拒绝、命令白名单）；UI Reload/Restart 按钮 |
| #2 Profile 可视化编辑 | ✅ | `config_profiles` CRUD（模板 JSON 对象校验、default 保护、删除回退）；前端 Profiles 视图 + JSON 编辑器 |
| #3 配置漂移检测 | ✅ | 抽出共享 `config_etag()`；对比 agent 上报的运行 etag 与服务器当前期望 etag，主机列表标 `config_drift` + UI 徽标 |
| #4 多 hub / 站点互联 | ✅ | hub 中转的 site-to-site 本已可用；新增 **mesh 直连**：有公网 `wg_endpoint` 的 host 互相生成直接 `[Peer]`（/32 比 hub /24 更具体，WireGuard 自动选直连），对称配对（O 有 endpoint 或本机有 endpoint 才配），NAT 双方回退 hub；公网 host 自动加 `ListenPort`；UI 可填公网端点 + MESH 徽标 |

阶段3 验证：命令通道全生命周期 + 守卫、Profile CRUD + 渲染、漂移三态（同步/改配置/重拉）、mesh 配置生成（公网+NAT 混合拓扑对称性），均 `cargo build`+前端构建通过、运行时无 panic。

**至此阶段1+2+3 全部完成。**

### self 主机进程内自管理（2026-06-14 完成）
内置 agent：`services/self_agent.rs` 一个进程内循环，与远程 agent 同构（轮询 + ETag + 写文件 + reload），但无 HTTP。opt-in——设 `SELF_SINGBOX_CONFIG_PATH` 才启用：周期性渲染 self 配置，ETag 变化才写本地文件并跑 `SELF_RELOAD_CMD`（默认 `sudo systemctl reload sing-box`），间隔 `SELF_SINGBOX_INTERVAL`（默认 10s、2s 下限）。验证：启动即写、加代理后自动重渲染、ETag 去重使 reload 只在变更时触发、无 panic。

**第 9 节"服务器即客户端"的内置 agent 至此落地。**

### 单一二进制 + 托管 sing-box（2026-06-14，路线 A）
用户要求："不要单独的 sb-easy-agent、面板调角色、服务器即客户端、完全不用额外跑 sing-box（但手机等仍走配置接入）"。决策路线 A：sb-easy 托管 sing-box 子进程（不重写 sing-box）。已落地：
- **sing-box 监督器**（`services/singbox_supervisor.rs`，`Singbox` 句柄）：`SINGBOX_MANAGED=true` 时 sb-easy 自己 spawn `sing-box run -c`、改配置 SIGHUP 重载、崩溃重生。运维上只管 sb-easy。验证：spawn/写配置/重载/重生四项 + `sing-box check` 通过。
- **clash_api 注入**：渲染配置注入 `experimental.clash_api`（self 取 SINGBOX_API_URL/secret；远程取 host.clash_api/secret，缺省 0.0.0.0:9090），使被托管的 sing-box 暴露面板监控所需 API。统一到 `render_host_served`（agent 端点 + 漂移检测同源，etag 一致）。
- **agent 折叠进主二进制**：`sb-easy agent`（`agent_mode.rs`）——受管节点跑同一个二进制，连面板拉配置 + 进程内托管 sing-box + 跑命令 + 上报状态。standalone `sb-easy-agent` crate 标记弃用。验证：端到端拉配置/起 sing-box/上报在线/ack restart。
- **镜像捆绑 sing-box**：Dockerfile 新增 sing-box 下载 stage，镜像内含 sing-box 二进制 → 真·单产物部署。
- **手机兼容保留**：手机不跑 sb-easy，继续走 WG 配置/二维码或 sing-box 订阅导入。
- **面板调角色**：沿用 Host 能力位 + 编辑模态；远程节点角色在中心面板改、节点拉取应用。

剩余可选：把 SINGBOX_API_URL 这类连接设置也纳入面板/profile 可视化；以及给 host 增加"WG 内网 IP 作 clash 监听"的更细控制。

**架构方案全部目标完成（含单一二进制 + 托管 sing-box 路线 A）。**

下方为原始设计。

---

## 1. 背景与目标

### 1.1 现状定位
sb-easy 目前是一个**"单台 sing-box 的配置管理器"**，思路源自 wg-easy：

- `proxy_nodes` 表 = **出站上游代理**（sing-box 往外拨的 ss/vmess/trojan… 目标），不是"被管理的机器"。
- `services/proxy_config.rs::generate_full_config(&nodes)` 把所有启用的出站代理塞进**全局唯一一份** sing-box 配置（固定的 tun+mixed inbound、固定 DNS、固定 route）。整个系统只有这一份 config。
- `agent`（独立 crate）是一个**无身份**的配置拉取器：`GET /api/agent/config` 不论谁来、带不带机器标识，返回的都是那同一份全局配置（仅靠 `AGENT_TOKEN` 共享密钥准入 + ETag 增量）。
- WireGuard 仅在中心服务器上做 hub-and-spoke，`wireguard_peers` = 连进来的终端客户端。

### 1.2 目标形态（你的设想）
一个类似 wg-easy 的**中心服务器**，集中管理**多台机器**上的代理、配置与客户端：

- 天然分**客户端**与**服务器端**；服务器端本身也可以是一个被管理的客户端（自管理）。
- 通过 WireGuard 把这些机器组成内网（intranet），既是数据面也可作控制面。
- 中心统一下发/编排每台机器的 sing-box 配置、出站代理分配、WG 成员关系。

### 1.3 核心差距（一句话）
当前**没有"受管机器"这个一等公民实体**。要做中心管多机，必须先把"机器"建模出来，再把"全局唯一配置"拆成"每机一份配置"，并给 agent 一个身份与双向通道。

---

## 2. 问题诊断（改造前必须澄清的四点）

| # | 问题 | 现状 | 影响 |
|---|------|------|------|
| D1 | **术语混淆** | UI 的 "Nodes" 指出站代理（`proxy_nodes`），但用户语义里的"节点"是受管机器 | 没有机器实体，无从下手做多机 |
| D2 | **全局唯一配置** | `generate_full_config` 一份配置喂给所有 agent | 无法做到"A 机走这些代理、B 机走那些"，无法按机器定制 inbound/route |
| D3 | **agent 无身份** | `/api/agent/config` 不区分调用方 | 无法识别哪台机器在线、各自该拿什么配置、上报什么状态 |
| D4 | **WG 仅 hub** | 只有"中心 ← 终端客户端"一种关系 | 受管机器之间、中心 ↔ 受管机器之间没有内网可达性，控制面只能靠 agent 反向轮询 |

---

## 3. 目标架构：控制面 / 数据面分离

引入清晰的两层与三类实体。

### 3.1 领域模型（实体重命名 + 新增）

```
┌─────────────────────────────────────────────────────────────┐
│                    Control Plane（中心服务器）                 │
│   Web UI + REST/WS API + DB + 编排器(Orchestrator)            │
│   + WireGuard Hub + 自管理 sing-box(可选)                     │
└───────────────┬─────────────────────────────┬───────────────┘
                │ 控制通道                      │ 控制通道
       ┌────────▼────────┐            ┌────────▼────────┐
       │   Host A (agent) │            │  Host B (agent) │   ← 受管机器
       │   sing-box 运行   │            │  sing-box 运行   │
       │   WG member      │            │  WG member      │
       └────────┬────────┘            └────────┬────────┘
                │ 数据面(代理出站)              │
                ▼                              ▼
        上游代理 Outbounds（ss/vmess/...）  ←  全局代理库，按需分配给各 Host
```

三类一等实体，**术语必须先定清楚**（见决策点 Q1）：

| 新概念 | 含义 | 对应现状 |
|--------|------|----------|
| **Host / 受管主机**（新增） | 一台运行 agent 的机器（VPS、软路由、家里的盒子…），可同时是 sing-box 运行者 + WG 成员 | 当前完全缺失 |
| **Outbound / 上游代理**（重命名） | sing-box 往外拨的代理目标，属于全局代理库，可被分配到多台 Host | 现 `proxy_nodes`（UI 现叫 "Nodes"） |
| **Client / 终端客户端** | 连入 WG 内网的终端设备（手机、笔记本） | 现 `wireguard_peers`（UI 叫 "Clients"） |

> 推荐：把 UI 里现在的 "Nodes" 改叫 **"Proxies / 代理库"**，把新的受管机器叫 **"Hosts / 主机"** 或 **"Nodes（新义）"**。命名是地基，详见 Q1。

### 3.2 Host 实体的关键属性
- 身份：`id`、`name`、独立 `enroll_token` / per-host `agent_token`。
- 能力位（capabilities）：`runs_singbox`、`is_wg_member`、`is_wg_hub`、`is_self`(自管理)。
- 角色/画像（profile）：决定它的 inbound（tun / mixed / 仅出站中转）、route 策略。
- 出站分配：与 Outbound 多对多关联（哪台机器该有哪些代理）。
- WG 成员信息：内网地址、公钥、它在 mesh 里的可达 endpoint。
- 运行态：`last_seen`、sing-box 版本/运行状态、Clash API 是否可达、配置当前 ETag。

---

## 4. 拓扑与控制通道（最关键的设计选择）

中心服务器如何"控制"一台可能在 NAT 后的受管机器？两种通道，**建议二者结合**：

### 4.1 通道一：Agent 拨号回家（Pull，保留并增强）
- agent 主动轮询/长连中心（现有模式，天然穿透 NAT，零额外开放端口）。
- 增强为带身份：`GET /api/agent/{host_id}/config`（或用 per-host token 识别），返回**该机专属**配置；agent 同时 `POST /api/agent/{host_id}/status` 上报心跳、sing-box 状态、WG 握手、流量。
- 实时性升级：把 30s 轮询升级为 **WebSocket/SSE 长连**，中心可主动 push "配置已变更，请 reload"，去掉轮询延迟（解决 improvement-plan 里"配置变更后自动 reload"的遗留项）。

### 4.2 通道二：经 WG 内网反向可达（Reachback，新增，强力）
- 你本来就要用 WG 建内网——**让这张内网同时成为控制面**。
- 每台 Host 作为 WG member 加入后，中心服务器（WG hub）可经内网地址直接访问该 Host 上 sing-box 的 **Clash API**（`http://<host-wg-ip>:9090`）。
- 于是 improvement-plan 已实现的 B1/B2（实时流量/连接/日志 WS、代理组切换）可以**逐 Host** 复用：现有 `singbox_proxy.rs` / `singbox_ws.rs` 只需把目标地址从"本机固定"改成"按 Host 的 WG 内网地址路由"。
- 好处：无需每台机器对公网开放 Clash API，控制流量全程走 WG 加密隧道。

### 4.3 推荐组合
- **配置下发 + 心跳** 走通道一（拨号回家，适配 NAT 后的机器）。
- **实时观测/动态控制（Clash API 透传）** 走通道二（经 WG 内网），Host 不在 WG 内网时降级为"仅配置管理、无实时控制"。

---

## 5. 数据模型变更

新增/调整表（SQLite migration `003_multi_host.sql` 草图）：

```sql
-- 受管主机
CREATE TABLE hosts (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  agent_token   TEXT NOT NULL,          -- per-host bearer，替代全局 AGENT_TOKEN
  capabilities  TEXT NOT NULL DEFAULT '{}', -- JSON: runs_singbox/is_wg_member/is_wg_hub/is_self
  profile_id    TEXT,                   -- 引用 config_profiles
  wg_address    TEXT,                   -- 内网地址，如 10.59.32.10/32
  wg_public_key TEXT,
  wg_endpoint   TEXT,                   -- 该机对外可达地址(若作为 hub/可入站)
  clash_api     TEXT,                   -- 该机 Clash API 监听(默认 9090)，经 WG 访问
  last_seen     TEXT,
  singbox_state TEXT,                   -- JSON: version/running/etag
  enabled       INTEGER NOT NULL DEFAULT 1,
  created_at    TEXT, updated_at TEXT
);

-- Host ↔ Outbound 多对多分配（哪台机器有哪些上游代理）
CREATE TABLE host_outbounds (
  host_id    TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  node_id    TEXT NOT NULL REFERENCES proxy_nodes(id) ON DELETE CASCADE,
  PRIMARY KEY (host_id, node_id)
);

-- 配置画像：决定一台机器的 inbound/route/dns 模板
CREATE TABLE config_profiles (
  id        TEXT PRIMARY KEY,
  name      TEXT NOT NULL,
  template  TEXT NOT NULL,   -- JSON: inbound 集合、route 规则、dns、tun 参数
  created_at TEXT, updated_at TEXT
);
```

兼容性：
- `proxy_nodes` 保留（语义不变，仅 UI 改称"代理/Outbound"）。
- `wireguard_peers` 增加可选 `host_id`，把"WG 成员"与"受管主机"打通（一个 Host 在 WG 视角就是一个特殊 peer）。
- 现有单机部署可建一条 `is_self=true` 的内置 Host（见第 9 节），零迁移成本。

---

## 6. Agent 协议升级

把 agent 从"配置拉取器"升级为"有身份的受管代理"。

### 6.1 注册（Enrollment）
- 中心生成一次性 `enroll_token`（或在 UI 点"添加主机"得到一行安装命令）。
- agent 首次启动携带 enroll_token 调 `POST /api/agent/enroll`，换取**永久 per-host `agent_token` + host_id**，落到本地。
- 解决现状"全局共享 AGENT_TOKEN，一泄全泄"的问题。

### 6.2 配置同步（每机一份）
- `GET /api/agent/config`（用 per-host token 识别身份）→ 返回**该 Host 专属**配置（ETag/304 保留）。
- 渲染逻辑见第 7 节。

### 6.3 状态上报
- `POST /api/agent/status`：sing-box 运行态/版本、reload 结果、本机 WG 握手、网卡/资源（可选）。
- 中心据此在 UI 显示每台机器**在线/离线/配置漂移**。

### 6.4 命令通道（可选，渐进）
- 长连下行少量命令：`reload` / `restart` / `run-latency-test` / `rotate-token`。
- MVP 阶段可不做下行命令，仅靠"配置变更 → push 通知 → agent reload"覆盖 90% 需求。

### 6.5 agent 安全收敛
- 沿用现有"未配置 token 则禁用该端点"的防御姿态，但改为 per-host。
- enroll/config/status 全部要求 per-host bearer；reachback(Clash API) 走 WG 内网，不额外暴露公网。

---

## 7. 配置渲染重构：从"全局一份"到"每机一份"

把 `generate_full_config(nodes)` 重构为 `render_host_config(host, assigned_outbounds, profile)`：

```
render_host_config(host):
  outbounds = host_outbounds(host) 解析出的上游代理       # 第5节关联表
            + urltest("Auto") + selector("Proxy")        # 沿用现有逻辑
  inbounds  = profile.template.inbounds                  # 按画像：tun / mixed / 仅中转
  route/dns = profile.template.route / dns               # 按画像可定制
  → 组装成该 Host 的 config.json
```

关键变化：
- 现 `generate_outbounds_array` 几乎可直接复用，只是输入从"全部启用节点"变成"分配给本 Host 的节点"。
- 现在硬编码在 `generate_full_config` 里的 inbound（`tun-in` 固定 172.20.0.1/30、`mixed-in` 7890、固定 `exclude_interface`、固定 route 规则）下沉为 **config_profile 模板**，不同机器可用不同画像（如"出口机=仅 mixed 中转、无 tun"、"客户端机=tun 全局代理"）。
- 与 improvement-plan 的 B3（配置可视化/编辑）天然衔接：profile 模板就是可视化编辑的对象。

---

## 8. WireGuard：内网既是数据面也是控制面

现状 WG 只有 hub-and-spoke + 终端 peer。扩展为三类成员：

1. **Hub**：中心服务器（或指定的有公网 IP 的 Host），所有人连它。
2. **Host-peer**：受管机器。加入内网后，① 机器之间可互访（intranet 落地），② 中心可经内网反向访问其 Clash API（第 4.2 节控制面）。
3. **Client-peer**：终端设备（现 `wireguard_peers`，语义不变）。

实现要点：
- 复用现有 WG 服务（密钥生成、IP 分配——注意 improvement-plan A2 已修的精确 octet 比较、配额/到期）。
- Host 入网时自动在 hub 的 `AllowedIPs` 里加入该 Host 的内网段，使 reachback 可达。
- 多 hub / 站点互联（site-to-site）作为后续增强，MVP 单 hub 足够。

---

## 9. "服务器端也是客户端"：自管理节点

满足"尽量服务器端和客户端做到一起"的诉求：

- 中心服务器启动时自动建一条 `is_self = true` 的内置 Host。
- 这台 Host 的 sing-box 由**进程内逻辑直接管理**（写本地 config + 本地 reload），无需跑独立 agent 进程——等价于"内置 agent"。
- 对编排器而言，自管理 Host 和远程 Host 走同一套抽象（同样有出站分配、profile、配置渲染），只是下发动作一个是"本地写文件"、一个是"经 agent 通道"。
- 现有单机部署因此平滑过渡：升级后自动成为"1 台自管理 Host"，行为不变。

---

## 10. 前端信息架构调整

| 现有视图 | 调整 |
|----------|------|
| Dashboard | 增加"主机总览"：每台 Host 在线状态、sing-box 运行态、各自连接/流量小卡片 |
| Nodes（代理） | 改称 **Proxies / 代理库**；增加"分配到哪些主机"的多选 |
| **Hosts（新增）** | 主机列表/详情：能力、画像、出站分配、WG 内网地址、心跳、per-host token、安装命令 |
| Monitor / Proxies / Logs（B1/B2） | 增加 **Host 选择器**：选哪台机器，就经 WG reachback 看那台的实时数据 |
| Clients（WG） | 语义不变；增加"这是不是某台 Host 的 peer"的关联展示 |
| Config（B3） | 从"看全局一份" → "按 Host/Profile 预览与编辑" |

---

## 11. 迁移路径（向后兼容、分阶段）

> 原则：每个阶段都能独立交付、不破坏现有单机部署。

**阶段 0 — 术语与地基（不改行为）**
- 定术语（Q1），UI 把 "Nodes" 文案改为 "Proxies/代理"。
- 加 `hosts` / `host_outbounds` / `config_profiles` 表与 `is_self` 内置 Host；现有逻辑作为"默认 Host + 默认 Profile"接入，行为零变化。

**阶段 1 — Host 实体 + per-host 配置**
- 配置渲染重构为 `render_host_config`（第 7 节）。
- agent 升级 enroll + per-host token + 带身份拉配置（第 6 节）。
- UI 增加 Hosts 视图、出站分配。
- ✅ 里程碑：能"中心管 2 台机器，各跑各自代理集"。

**阶段 2 — 内网控制面 + 实时观测逐机化**
- WG 扩展 Host-peer + reachback（第 8 节）。
- B1/B2 实时观测/代理组切换接 Host 选择器（第 4.2 节）。
- 配置变更 push → agent 即时 reload（去掉轮询延迟）。
- ✅ 里程碑：能对每台机器实时观测/切节点。

**阶段 3 — 编排与平台化增强**
- 命令通道（reload/restart/测速下行）、配置漂移检测、批量操作。
- Profile 可视化编辑（接 B3）、多 hub/站点互联、健康告警。

---

## 12. 安全考量

- **per-host token 取代全局 AGENT_TOKEN**：单机泄露不波及全网；支持 rotate。
- **凭据下发面收敛**：每台 Host 只能拿到**分配给它的**出站代理凭据，不再"一个端点吐全量机密"（修正现状 agent 端点返回所有节点密码的问题）。
- **控制面走 WG 加密内网**：Clash API 不对公网暴露。
- **enroll 一次性 token + 过期**：防止任意机器自注册。
- **RBAC 延续**：Host 管理、出站分配、配置编辑纳入现有 admin/viewer 权限与审计日志（B6 已有）。

---

## 13. 决策点

> Q1、Q2 已拍板（2026-06-13）；Q3–Q5 待定但已给出倾向。

- **Q1 术语命名 — ✅ 已定：Hosts + Proxies**
  - 受管机器 = **Hosts / 主机**（新表 `hosts`，API `/api/hosts`）。
  - 现 proxy_nodes 语义不变，UI/文案改称 **Proxies / 代理**（API 可保留 `/api/proxy` 或改 `/api/proxies`）。
  - 终端设备 = **Clients / 客户端**（现 `wireguard_peers`）。
  - 全文已按此术语书写。
- **Q2 第一里程碑范围 — ✅ 已定：阶段 1 + 阶段 2 一起做**
  - 即一次做到「per-host 配置下发骨架」**＋**「WG 内网 reachback 实时观测/切节点 + 配置变更 push reload」。
  - 推论：实时控制依赖 Host 入 WG 内网，故 **Q3 倾向"reachback 机器必须入网"**（见下）。
- **Q3 内网约束 — 倾向：分配实时控制的 Host 必须入 WG 内网**
  - 既然 Q2 把 reachback 纳入首个里程碑，控制面统一走 WG 最简单。
  - 折中：允许"仅配置管理、不入网"的 Host 存在，但这类机器**实时观测/切节点降级为不可用**（UI 明确标注）。建议默认引导入网。
- **Q4 自管理形态 — 倾向：进程内"内置 agent"**（第 9 节）。部署最简单，单机用户零额外进程；远程 Host 与自管理 Host 共用同一编排抽象。
- **Q5 配置画像粒度 — 倾向：预设 Profile + 每机覆盖少量字段**。先给 2–3 个预设（如"客户端机/tun 全局"、"出口机/仅 mixed 中转"），高级用户可逐机覆盖 inbound/route，接 B3 可视化编辑。

### 首个里程碑（Q1+Q2 落定后的工作清单）
1. migration `003_multi_host.sql`：`hosts` / `host_outbounds` / `config_profiles`；`wireguard_peers` 加 `host_id`；建 `is_self` 内置 Host。
2. `render_host_config(host)` 取代 `generate_full_config`；inbound/route 下沉为 Profile 模板。
3. agent：enroll + per-host token + 带身份拉专属配置 + 状态上报；长连 push reload。
4. WG：Host-peer 入网 + hub AllowedIPs 自动放通 → reachback 可达。
5. 后端：`singbox_proxy.rs`/`singbox_ws.rs` 增加"按 Host 的 WG 内网地址路由"维度。
6. 前端：新增 **Hosts** 视图（含安装命令/出站分配）；Monitor/Proxies/Logs 加 **Host 选择器**；Nodes 文案改 **Proxies**。

---

## 附：与现有 improvement-plan 的关系
- 本方案是 improvement-plan 之上的**结构性升级**：那份解决了"单机能力完善"（实时观测 B1/B2、配置可视化 B3、节点字段 B4、平台化 B6）；本方案解决"从单机到多机"的**拓扑与编排**问题。
- 已落地的 B1/B2/B3/B6 大多可复用：实时观测/代理组切换接 Host 选择器即可逐机化；配置可视化的编辑对象变为 Profile 模板；RBAC/审计直接覆盖新增的 Host 管理动作。
</content>
</invoke>
