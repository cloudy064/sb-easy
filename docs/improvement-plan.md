# sb-easy 改进计划 / Improvement Plan

> 本文档汇总 2026-06-13 代码与界面评估的结论，分为两部分：
> **A. 待修复问题**（安全 / bug / 技术债）与 **B. 功能缺口**（对标 metacubexd 等成熟面板需补充的能力）。
> 用作后续工作排期与功能推荐的依据。条目标注优先级：🔴 紧急 / 🟠 高 / 🟡 中 / ⚪ 低。

## 实施状态（2026-06-13 已落地）

| 项 | 状态 | 说明 |
|----|------|------|
| A1 agent 鉴权 | ✅ 完成 | `AGENT_TOKEN` bearer 校验；未设置时该端点直接禁用。运行时验证：无/错 token→401，正确→200 |
| A2 IP 分配 bug | ✅ 完成 | 改为精确 octet 集合比较 |
| A3 post_up/down RCE | ✅ 完成 | 移除任意 shell 执行；NAT 改为**内部固定 iptables 规则**（egress 自动探测 / `WG_EGRESS` 覆盖），功能不丢失 |
| A4 错误脱敏 | ✅ 完成 | 5xx 仅返回通用消息，细节进日志 |
| A5 CORS/默认值 | ✅ 完成 | `CORS_ORIGINS` 可配置；硬编码 IP 改占位符；`.env.example` 重写 |
| A6 URL 编码 | ✅ 完成 | 统一 `util::encode_query_component` 正确百分号编码 |
| A7 工程化 | ✅ 完成 | git 取消跟踪 `dist`/`data`；前端补类型 |
| B1 实时观测 | ✅ 完成 | 后端 WS 代理 `/api/sing-box/ws/{traffic,logs,connections,memory}`；前端 **Monitor** 页（流量曲线/连接表+断开/日志流） |
| B2 代理组切换 | ✅ 完成 | 后端 `PUT /proxies/{group}` 透传；前端 **Proxies** 页（组/选中/切换/组测速） |
| B3 配置可视化 | ✅ 完成 | 前端 **Config** 页（预览/复制/下载，full + outbounds） |
| B4 节点高级字段 | ✅ 完成 | 节点表单新增 TLS / Reality / uTLS / transport(ws/grpc/http) / ALPN |
| B5 WG 增强 | ✅ 完成 | 到期 peer 不写入 live 配置 + Expired 徽标；**在线状态**（基于 latest_handshake）；**流量配额**（peer quota_bytes，超额自动剔除 live 配置 + 用量进度条）。已验证 |
| B6 平台化 | ✅ 完成 | **备份/恢复**（已验证往返）；**多用户 + RBAC**（用户名登录、用户 CRUD、admin/viewer、viewer 只读 403、保护最后一个 admin）；**审计日志**（中间件记录所有变更，Users 页查看）；**深色模式**；**i18n 中英文**。已验证 |
| A8 界面一致性 | ✅ 完成 | 深色模式（CSS 变量主题 + 切换持久化）；响应式（窄屏侧栏抽屉）；i18n 切换；硬编码浅色 hex 收敛为变量 |

构建验证：后端 `cargo build` 通过；前端 `vue-tsc` + `vite build` 通过；运行时冒烟测试覆盖 agent 鉴权、JWT 登录、RBAC（viewer 403）、审计记录、配额持久化、到期/在线字段、自动 IP 分配、备份恢复往返、WS 鉴权。

数据库新增 migration `002_quota_audit_roles.sql`（WG 配额列、用户 role 列、audit_log 表）。新增环境变量：`AGENT_TOKEN`、`CORS_ORIGINS`、`WG_EGRESS`。

**全部 A1–A8 与 B1–B6 已落地。** 后续可继续打磨的非阻塞项：节点高级字段的编辑（目前仅创建时可填）、表单级深度 i18n、自动 reload sing-box（当前 agent 轮询 ETag 已能感知变更）。

---

---

## A. 待修复问题

### A1. 🔴 `/api/agent/config` 未鉴权（安全）
- **现状**：`backend/src/api/router.rs` 把 `agent::router()` 挂在 `public`（免鉴权）分组下。该接口返回**完整 sing-box 配置，含所有代理节点的密码 / UUID 等凭据**。
- **风险**：任何能访问该端口者可直接拉走全部节点机密。
- **建议**：为 agent 增加共享密钥 / 专用 token / mTLS；或将其移入受保护分组并让 agent 携带凭据。

### A2. 🟠 IP 分配存在前缀碰撞 bug（功能正确性）
- **位置**：`backend/src/services/wireguard.rs` → `next_available_ip`。
- **问题**：用 `address.starts_with("10.59.32.2")` 判断占用，`10.59.32.20` 会被误判为占用了 `.2`，导致可用 IP 被错误跳过。
- **建议**：解析为精确 octet 后比较，而非字符串前缀匹配。

### A3. 🟠 `post_up` / `post_down` 仍会执行任意 shell（安全）
- **位置**：`wireguard.rs` 的 `startup` / `shutdown`，仍从 DB/env 读取 `post_up`/`post_down` 并 `sh -c` 执行。
- **问题**：UI 已移除该配置项，但代码路径仍在，构成潜在 RCE 面（若 `app_settings` 可被写入）。
- **建议**：彻底删除该执行路径，或限制为固定白名单命令。

### A4. 🟡 错误信息向客户端泄露内部细节
- **位置**：`backend/src/error.rs`，`Database` / `Io` / `Serde` 分支直接返回 `e.to_string()`。
- **建议**：5xx 对外返回通用消息，详细错误只写日志。

### A5. 🟡 CORS 全开 + 弱默认值
- `main.rs` 使用 `CorsLayer::permissive()`。
- 默认 `ADMIN_PASSWORD=admin`；`config.rs` 与 migration seed 硬编码了真实样子的 IP（`39.108.98.208` / `10.168.1.5`）。
- **建议**：收紧 CORS；首启强制改密；示例值改为占位符。

### A6. 🟡 URL 编码实现不完整
- `singbox_proxy.rs` 的 `urlencoding()` 只转义 `%`；`proxy_nodes.rs` 另有一个只转义 空格 / `/` / `+`。
- **建议**：统一改用 `urlencoding` 或 `url` crate。

### A7. 🟡 工程化缺失
- 无测试、无 README。
- `frontend/dist/` 与 `data/*.db` 被提交进 git（构建产物与数据库不应入库）。
- 前端 Pinia store 的请求体类型全部为 `any`，丢失 TS 类型保护。
- **建议**：加 `.gitignore` 排除产物/DB；补关键路径测试；store 请求体定义类型。

### A8. ⚪ 界面一致性
- 大量内联 `style="..."` 散落在各视图，破坏已有设计系统（`main.css` 的 token 体系）。
- 无响应式 / 移动端适配，无深色模式，全英文文案。
- **建议**：内联样式收敛为工具类；补响应式、深色模式、中文 i18n。

---

## B. 功能缺口（对标 metacubexd / mihomo 面板）

> **差异本质**：sb-easy 当前是"配置管理器"（源自 wg-easy 思路——增删改、生成配置、下发）；
> metacubexd 等是"运行时控制台"（假设代理在跑，重点是实时观测与动态控制）。
> sb-easy 几乎缺失"运行时"这一层：对 sing-box 仅做 REST 透传，无 WebSocket、无可视化、无策略切换。

### B1. 🔴 实时可观测性（最大差距）
- **实时流量曲线**：上/下行速率（sing-box `/traffic` WS）、内存占用（`/memory` WS）。
- **活跃连接表**：列出全部连接，可按域名/规则/出站链筛选，支持单条与批量断开。
  - 后端 `singbox_proxy.rs` 已有 connections 的 GET/DELETE，但前端无页面消费，且为轮询而非 WS。
- **实时日志流**：`/logs` WebSocket，按级别（info/warning/error）过滤。
- **落地要点**：后端新增 WebSocket 代理路由（axum 支持），转发 sing-box 的 WS 端点至前端。

### B2. 🔴 代理组与策略切换
- 展示代理组及组内节点、**当前选中节点**，点击切换（`PUT /proxies/{group}`）。
- 组级一键测速（`/group/{name}/delay`，后端已透传、前端未用）。
- 这是日常"切节点"的核心操作，目前完全无法在 UI 完成。

### B3. 🟠 路由 / 规则与配置可视化
- 规则查看与分流编辑（domain / geosite / geoip / 进程）、rule-set 规则集管理、DNS 配置。
- **配置可视化**：完整 config 现由 `services/proxy_config.rs` 代码模板生成，用户**看不到也改不了**；需支持预览 / 导出 / JSON 校验，以及 inbound（tun/mixed/http/socks）管理。
- 原始 JSON 编辑器（带 schema 校验）作为高级逃生口。

### B4. 🟠 节点能力补全
- **高级传输字段**：Reality、TLS（SNI/ALPN/指纹）、transport（ws/grpc/h2 的 path/host）、多路复用（mux/brutal）。
  - 现表单只有最基础字段（server/port/password/uuid），很多订阅节点导入后无法运行。
- 批量测速、批量启用/禁用、批量导入导出。
- 解析订阅返回头的流量用量 / 到期时间并展示。
- 节点分组标签、按地区排序。

### B5. 🟡 WireGuard 增强
- 在线状态轮询、到期自动禁用、流量配额。
- （实时握手/流量、二维码、一次性链接已具备。）

### B6. 🟡 平台化与体验
- 配置变更后**自动 reload sing-box**（现依赖 agent ETag 轮询拉取，缺主动推送/即时生效）。
- 多用户 / RBAC、操作审计日志。
- 备份 / 恢复（全量配置导出导入）、健康检查与告警。
- 深色模式、中文 i18n、移动端响应式（与 A8 重叠）。

---

## C. 推荐推进顺序

1. **先修 A1（agent 鉴权）与 A2（IP 分配 bug）** —— 一个是安全、一个是会真实触发的功能缺陷，成本低、收益明确。
2. **P0 功能阶段**：B1（实时连接表 + 日志流 + 流量曲线）+ B2（代理组切换）。
   让 sb-easy 从"配置工具"升级为"可用的控制台"，是用户每天会打开的能力；后端仅需补一层 WebSocket 透传，改动可控。
3. **P1 功能阶段**：B3（配置可视化）+ B4（节点高级字段）。
   决定"能否真正替代手写 sing-box config"。
4. **清理与平台化**：A3–A8 技术债 + B5/B6 增强，穿插进行。
