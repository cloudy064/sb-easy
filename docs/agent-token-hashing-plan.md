# agent_token 哈希存储与兑换轮换方案

> 历史分支记录：本文的实施状态和验证结果对应下述分支及提交，不代表这些改动已合入当前 `master`。迁移编号与接口行为应以当前源码为准。

对象：`c/`（基线 8486f0b，分支 fix/agent-ui-hardening）。状态：阶段 1 已实施；阶段 2 与兑换时轮换已实施（commit 0846020、4ff43bf，全量 ctest 28/28，ASan 11/11）；阶段 3 暂缓。

实施记录：`GET /api/hosts/{id}/token` 不再返回 `agent_token`，改返回 `has_token` 与 `server`；明文只在 `rotate-token` 和兑换响应中出现。兑换注册码时无条件轮换令牌（同一事务内写入明文与哈希），同一主机其他设备持有的旧令牌随即失效。未加 `rotate_on_enroll` 开关，因为没有发现任何依赖多设备共用令牌的代码或测试。阶段 3（迁移 020 清空明文列）暂缓：这是不可逆的数据变更，且回滚基线（Rust 后端）仍读明文列，需确认 Rust 后端已下线后再做。

## 1. 现状（均已读代码确认）

- `hosts.agent_token` 以明文存储（migrations/003_multi_host.sql:29）。
- 查找：`sb_store_find_enabled_host_by_token` 用 SQL 等值匹配（store.c:2409）。
- 生成：`new_agent_token`，两个 UUID v4 去连字符拼接，64 位十六进制，约 244 位熵（store.c:725）。
- 展示明文：`GET /api/hosts/{id}/token`（http_routes_hosts.c:802）、`POST /api/hosts/{id}/rotate-token`（820）、兑换响应（951）。
- 兑换不轮换：`sb_store_redeem_agent_enrollment` 直接返回 `hosts.agent_token`（store.c:2345）。
- 对照：注册码只存 SHA-256（`agent_enrollments.code_hash`），`proxy_devices.token_hash` 也已是哈希，可复用同一写法。

## 2. 目标

1. 数据库泄露后，令牌不能直接冒用。
2. 兑换注册码时可选轮换，避免重装设备后旧设备仍持有同一长期令牌。
3. 已发放的 64 位十六进制令牌继续有效，Agent 与 Android/Windows 客户端不需要同时升级。

## 3. 分阶段实施

### 阶段 1：双读，新增哈希列（兼容，可回滚）

- 迁移 019：`ALTER TABLE hosts ADD COLUMN agent_token_hash TEXT NOT NULL DEFAULT ''`，并建索引 `hosts_agent_token_hash`。SQLite 没有内置 SHA-256，不能在 SQL 里回填。
- 回填放在 C 里：服务启动时对 `agent_token != '' AND agent_token_hash = ''` 的行逐行计算 `sb_sha256_hex` 并写入，单事务完成。
- 写路径：创建主机、`rotate`、兑换时同时写明文和哈希。
- 读路径：先按哈希查，哈希未命中再按明文查（兜底，覆盖回填前的窗口）。比较前先校验令牌格式（长度 64、十六进制）。
- 明文列保留，这一阶段只增加防护，不改变任何对外响应。

### 阶段 2：停止回显明文（契约变更，需前端同步）

- `GET /api/hosts/{id}/token` 不再返回 `agent_token`，只返回 `has_token`（`store.c:270` 已有该字段）和 `server`；明文只在 `rotate-token` 和兑换响应里出现一次。
- 前端 `frontend/src/types/index.ts` 与对应页面改为“轮换后显示一次”。
- 此阶段需要你确认：现有的“查看令牌”入口会消失。

### 阶段 3：清除明文

- 阶段 2 稳定后，迁移 020 把 `agent_token` 置空，查找只走哈希；删除明文兜底分支。
- 回滚基线（Rust 后端）仍依赖明文列，所以必须在确定 Rust 下线或同步改造后才做；否则回滚会令所有 Agent 认证失败。

## 4. 兑换时轮换

- 默认行为改为：兑换成功时生成新令牌，写入哈希（及阶段 1–2 的明文），返回新令牌。
- 影响：同一主机的其他设备所持旧令牌立即失效。当前设计里“一个主机多个设备共用令牌”是否被依赖，需要你确认；如有依赖，保持默认不轮换，加 `rotate_on_enroll` 设置项。

## 5. 兼容约束与风险

- 不得改变令牌格式（64 位十六进制），已发放令牌必须可校验。
- 遗留全局 `AGENT_TOKEN` 不在本方案内，仍走 `sb_consttime_streq`（已改）。
- 数据库查找本身仍是等值查询，但查的是哈希，时间侧信道不再泄露令牌前缀。
- 回填失败的行会留在兜底路径，不会锁死认证；启动日志需打印回填计数。

## 6. 测试计划（实施前先补）

1. 迁移后旧明文令牌仍能通过 `/api/agent/config`。
2. 回填后哈希列非空且与 `sb_sha256_hex(token)` 一致。
3. `rotate-token` 后旧令牌 401、新令牌 200，数据库不含新令牌明文（阶段 3）。
4. 兑换轮换：兑换前后令牌不同，旧令牌 401。
5. 禁用主机、空令牌、长度不符、非十六进制令牌均返回 401。
6. `control_plane_e2e`、`http_hosts_test`、`store_test`、`proxy_users_test` 全部通过，并在 ASan 下复验。

## 7. 需要你决定的两点

1. 阶段 2 是否接受“令牌只在轮换时显示一次”。
2. 兑换是否默认轮换，或保持默认不轮换并提供开关。

阶段 1 不依赖这两个决定，我先实施阶段 1。
