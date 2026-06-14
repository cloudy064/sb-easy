# sb-easy Go 重写方案（feat/go-rewrite）

> 目标：把后端从 Rust 切换到 Go，从而**把 sing-box 作为库原生内嵌进同一进程**——
> 真正单进程单二进制、无需独立 sing-box、无 FFI。前端 Vue 与迁移 SQL 复用。

## 为什么切 Go
sing-box 是 Go 项目。Rust 内嵌它只能走脆弱的 cgo/FFI（libbox）。用 Go 可直接
`import` sing-box 包，在进程内构建/启动/重载实例，并复用其 Clash API。

## 已验证（PoC，2026-06-14）
Go 1.26 下内嵌 sing-box 编译并运行成功：进程内启动 + Clash API 200 + 干净关闭。
- 依赖：`github.com/sagernet/sing-box v1.13.12`
- 构建 tags：`with_clash_api,with_gvisor,with_quic,with_wireguard,with_utls,with_dhcp`
  （注意：`with_reality_server` 已并入 `with_utls`，不要再加）
- 内嵌 API：
  ```go
  ctx := box.Context(context.Background(),
      include.InboundRegistry(), include.OutboundRegistry(), include.EndpointRegistry(),
      include.DNSTransportRegistry(), include.ServiceRegistry())
  opts, _ := json.UnmarshalExtendedContext[option.Options](ctx, configBytes)
  inst, _ := box.New(box.Options{Context: ctx, Options: opts})
  inst.Start() ; ... ; inst.Close()
  ```

## 架构（Go）
- HTTP：`go-chi/chi`（sing-box 已传递依赖 go-chi）。
- DB：`modernc.org/sqlite`（纯 Go，无 cgo，易交叉编译），`database/sql`。
- 迁移：复用现有 `migrations/*.sql`；Go 迁移器兼容现有 sqlx 库（首次从 `_sqlx_migrations`
  导入已应用版本，避免重复执行）。
- 鉴权：`golang-jwt/jwt`；密码 argon2id（PHC 串，兼容现有用户哈希）。
- sing-box：`internal/singbox` 内嵌管理器（start/reload/close + 渲染配置）。
- WireGuard：沿用现思路（密钥生成 + `ip`/`wg` CLI）；后续可评估用 sing-box endpoints。

## 目录布局
```
go.mod  (module github.com/cloudy064/sb-easy)
cmd/sb-easy/main.go        # 入口：server 模式 / `agent` 子命令
internal/config            # 环境配置
internal/db                # sqlite 打开 + 迁移
internal/singbox           # 进程内 sing-box 管理器（内嵌）
internal/server            # chi 路由 + 中间件 + 静态前端
internal/api/...           # 各端点（从 Rust 逐个移植）
internal/render            # 配置渲染（profile/outbounds/clash 注入）
Makefile                   # 统一 build tags
```

## 与 Rust 版的能力映射（逐个移植）
auth / hosts(+profiles/commands/outbounds) / proxy nodes / subscriptions /
wireguard(peers) / sing-box 透传(+WS) / settings / users(+audit) / agent / system。
多主机模型（hosts/host_outbounds/config_profiles + profile mode full/managed）、
per-host token、WG host-peer/mesh、漂移检测、命令通道——schema 已在 migrations 中，
逻辑按 Rust 版等价移植。

## 关键差异（相对 Rust 版）
- 托管 sing-box 不再是"spawn 子进程"，而是**进程内内嵌实例**（supervisor → 内嵌管理器）。
- `sb-easy agent` 仍为同一二进制子命令；受管节点也内嵌 sing-box。
- Clash API：内嵌实例自带，监控透传直接指向它。

## 阶段
1. ✅ PoC：内嵌 sing-box 编译运行（本文上方）。
2. 骨架：module + config + db(迁移兼容) + server(serve 前端 + status + login) + 内嵌管理器。
3. 移植核心 API（hosts/proxies/wireguard/auth/users/settings）。
4. 移植实时透传(WS)/agent/订阅/审计。
5. 内嵌 sing-box 接管渲染配置 + reload；agent 模式。
6. Docker（纯 Go 二进制 + 前端，单镜像，无需再带 sing-box 二进制）。
7. 与 Rust 版对拍验证后切主。

## 备注
- 纯 Go + modernc sqlite → 静态二进制，Docker 镜像极小、无需捆绑 sing-box 二进制。
- 现有 Rust 后端（backend/、agent/）保留在分支上直到 Go 达到对等，再移除。
