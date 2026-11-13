# 服务端配置与设备 patch 同步

本协议实现 [产品理念](concepts.md)。生产服务端与无界面 Agent 的实现位于 `c/`；桌面和移动客户端通过相同设备身份访问服务器。

## 数据归属

共享基础配置继续使用 `config_profiles` 中的 `default`，不再创建另一份默认配置副本。服务端结合设备能力、管理连接参数和该设备获准使用的节点生成 `base`。`device_config_sync` 保存设备的 `patch`、`agent_settings`、版本和迁移标记。

```text
config = MergePatch(base, patch)
runtime = 平台适配(config, agent_settings)
```

`agent_settings` 也由服务端保存：它承载 C Agent 的出站调整、规则和选择器选择，以及各平台原生设置。客户端原有设置文件或安全存储在迁移后充当缓存与待提交队列。凭据、运行日志、统计、临时连接状态不属于共享基础配置；授权节点投影仍由服务端控制。

Windows 的自动连接、重连、轮询与遥测开关等持久管理设置也随设备同步，仍经原有本机校验和应用流程；OS 权限与临时断开意图留在本机。Android 同步路由、节点选择与采集模板，实际启用采集或自动上传的会话授权仍在本机。服务端设置重置后，客户端会纠正内核缓存中的旧节点选择。

## Patch 语义

使用 [JSON Merge Patch（RFC 7396）](https://www.rfc-editor.org/rfc/rfc7396)，根节点必须为对象：

```json
{
  "log": {"level": "debug"},
  "dns": {"strategy": null},
  "route": {"rules": [{"domain_suffix": ["example.org"], "outbound": "direct"}]}
}
```

这会修改日志级别、删除 DNS strategy，并替换整份 route.rules。未出现的对象字段继续继承基础配置。

两种删除必须区分：`"strategy": null` 表示从有效配置删除该字段；从 patch 中去掉 `strategy` 表示取消覆盖、重新继承。`patch: {}` 清除 JSON 配置差异；同时保存 `agent_settings: {}` 才会清除原生设备设置。

数组是原子值。可通过提交修改后的数组增删、调整规则/节点，但该数组随后整体覆盖默认数组，不自动合并默认数组中的后续新增项。这避免默认列表重排后按旧下标误删其他规则。要恢复默认列表，需要从 patch 中移除对应数组字段。对象属性中的字面 `null` 不能通过此协议表达为普通值；迁移若不能无损往返，会拒绝迁移并提示处理，而不是丢失配置。

上述数组规则也适用于服务端生成的 Tailscale endpoints、outbounds 和路由规则：覆盖这些数组后，相关网络设置也会固定在设备 patch 中；移除覆盖后才会重新跟随服务端生成结果。

## 版本与冲突

- `base_version`：服务端共享源的单调毫秒时间戳。默认配置、节点、设备生成参数和节点分配的变化会推进它；设备心跳与延迟数据不应推进它。该版本覆盖共享渲染依赖，其他设备源更新也可能使一次提交需要重新核对。
- `patch_version`：该设备的单调毫秒时间戳；从未保存差异时可为 `0`。新的值取服务器当前时间与前一版本加一的较大值。
- 清空 patch 保留版本行，不删除版本记录，防止离线旧配置重新出现。
- PUT 必须携带两个已读版本，服务器在数据库事务中检查。版本过期返回 `409`，不写入。
- 同内容重试不会重复改变配置。客户端若丢失上传响应，下一次 GET 看到内容已经一致就确认同步完成。
- 本地正在上传时又发生编辑，确认前一个请求不能删除后一个尚未提交的修改。

## 接口

| 接口 | 访问身份 | 用途 |
| --- | --- | --- |
| `GET /api/config/default` | 管理员 | 读取 `{base_version, profile}` |
| `PUT /api/config/default` | 管理员 | 提交 `{base_version, profile}`；`profile.template` 为 JSON 对象 |
| `GET /api/hosts/{id}/config-state` | 管理员 | 读取、初始化设备同步状态 |
| `PUT /api/hosts/{id}/config-state` | 管理员 | 编辑设备 patch 与设备运行设置 |
| `GET /api/agent/config-state` | 本设备 Agent 凭据 | 获取基础、差异与合成结果 |
| `PUT /api/agent/config-state` | 本设备 Agent 凭据 | 上传本设备的个性化修改 |

设备 GET 和成功 PUT 返回以下字段（另有渲染 ETag、规则来源等元数据）：

```json
{
  "base_version": 1805000000000,
  "patch_version": 1805000000001,
  "base": {},
  "patch": {},
  "config": {},
  "agent_settings": {},
  "agent_settings_initialized": true
}
```

上例中的空配置仅展示字段结构。PUT 请求体为：

```json
{
  "base_version": 1805000000000,
  "patch_version": 1805000000001,
  "patch": {"log": {"level": "debug"}},
  "agent_settings": {}
}
```

这是**替换该设备的完整 patch 文档和运行设置**，不是在已保存 patch 上继续做 merge。修改一个设置时，需要保留已读取的其他设置命名空间。响应和磁盘缓存可能含节点凭据，不应放入公开日志。

原 `GET /api/agent/config` 和设备配置预览在设备启用新协议后返回合成结果。尚未启用协议的旧设备继续使用原 Profile 路径。旧 Profile CRUD 保持兼容；新版默认编辑入口使用带版本条件的新接口。

服务器内置的 `self` 引擎支持同一份 JSON patch；客户端专属 `agent_settings` 不在 self 引擎执行，因此面板对 self 只显示 patch 编辑。服务端检查 JSON 结构、大小、权限和版本，完整的 sing-box 配置校验由实际运行客户端完成。

## 客户端流程与迁移

1. GET 获取服务端快照；默认设备保持空 patch 和空设备设置。
2. 用户编辑先持久保存待提交意图及其已读版本。
3. 定时 GET/PUT 完成双向同步。离线与超时保留缓存和待提交记录。
4. 发生冲突保留两份内容，明确选择采用服务器或基于最新版本重试本地修改；重新提交仍会检查版本。
5. 验证合成配置、执行平台适配并加载；失败保留上一份可用配置。

首次读取设备同步状态时，服务器把非默认 Profile 渲染结果与默认基础的差异保存为 patch。`agent_settings_initialized=false` 允许客户端一次性导入明确设置过的旧本地设置。首次保存（包括恢复默认）后该标记为 true，后续启动不能把旧文件重新导入。

C Agent 将缓存与待提交队列绑定到服务器和设备凭据，使用原子文件写入。其本地 `GET /api/config-state` 还返回 `pending`、`conflict`、`local_version`、`server_patch` 和 `server_agent_settings`。本地 PUT 需携带当前 `base_version`、`patch_version` 和 `local_version`；冲突解决使用 `resolve: "use_server"` 或 `"retry_local"`。

原生客户端将同步状态写入各自的私有存储：Android 的原子配置缓存、Windows 的设备身份存储、Linux 与 Apple 的加密配置库。未连接服务器的独立配置仍可运行。Apple 的轮询受前台应用和 VPN 扩展生命周期约束，不能保证系统暂停应用时仍按固定间隔同步。

服务端备份应使用完整 SQLite 数据库备份，包含共享默认配置与 `device_config_sync`。旧的选择性导出接口只导出其原有资源，不包含完整配置同步状态。

## 验证

核心回归包含 Merge Patch 增删、数组替换、时间戳/CAS、授权隔离、旧 Profile 迁移、清空版本、离线队列恢复、丢失响应和上传期间继续编辑。`config_sync_e2e` 用独立数据库和两个真实 Agent 进程验证默认更新、设备覆盖、双向同步、离线重启及冲突解决；不修改本机运行中的容器或代理路由。

原生平台测试和实际安装验收应分别记录。Linux 上的 Apple C 核心检查不等价于 Xcode 编译或 macOS/iOS/tvOS 真机验收。

2026-11-13 本地验证：C 全套 30 个测试目标通过，后续同步/HTTP/Agent 改动的定向回归通过；服务端和 Agent 新增同步用例通过 ASan/UBSan。Vue 与 Svelte 检查/构建通过，真实浏览器覆盖设备 patch 保存、冲突保留、恢复默认及 Default 编辑版本检查。Android 完成 JVM 测试和 Kotlin 编译，Windows 完成 MinGW 编译与 Wine 回归，Linux 完成 GTK 构建与隔离 HTTP/控制器测试。Apple 同步代码和 XCTest 已补齐，本环境缺少 Swift/Xcode 工具链，尚未完成原生编译与 XCTest 执行。

2026-11-14 整合远端 Tailscale 与 Windows 本地网页更新后：保留已发布的 `019_tailscale.sql`，配置同步新增迁移编号改为 `020`；C 全量编译和 31 个测试目标全部通过，包含旧库升级、Tailscale 更新版本和身份隔离回归。Windows 托盘入口补齐 `config.resolve` 并通过 MinGW/Wine 回归，Windows UI 64 项测试与构建通过。管理面板重新构建，真实浏览器验证共享 Default 与 Tailscale 注册/编辑、patch 保存/冲突/重置和 Default 乐观版本检查。此次验证使用隔离数据库和测试进程，未部署或修改运行中的代理。
