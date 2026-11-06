# sb-easy 代码设计与质量评估

> 历史评审：本文针对下述日期的 `rewrite/cpp-quickjs` 分支。当前原生实现为 C11，历史 C++ 源码与 Windows WebView2 桌面窗口已移除；本文不描述当前架构。

评估日期：2026-10-27　分支：`rewrite/cpp-quickjs`

> **评估方式与局限**：本文基于阅读代码、CMake、CI 配置和文档得出，**没有执行构建和测试**，因此“测试是否通过”“运行时行为是否正确”不在结论范围内。我完整阅读了 `agent_runtime.hpp/.cpp` 的前 300 行、`platform_adapters.hpp`、`cpp/CMakeLists.txt`、`script_engine.cpp`，部分阅读了 `http_server.cpp`（前 300/2925 行）、`store.cpp`（前 200/2090 行）、`windows/service_main.cpp`（前 300/1597 行）、`windows/ipc.cpp`（前 250/395 行）；其余文件只统计了行数，没有逐行阅读。

## 1. 项目概览

sb-easy 是自托管的 WireGuard + sing-box 控制面板，正在从 Rust 后端整体重写为 C++20，同时新增 Windows 客户端。

| 组件 | 技术 | 状态 |
| --- | --- | --- |
| 管理服务 | C++20 + Drogon + SQLite + QuickJS-NG | 重写中，与 Rust 版保持 API/DB 兼容 |
| Agent（Linux） | C++，POSIX 适配器 | 已拆出可移植运行时 |
| Windows 客户端 | MSVC，Service + Win32/WebView2 + WiX | 开发中（W2–W4 基本落地，W5 验收未完成） |
| 前端 | Vue 3 + TS + Pinia | 已有 |
| 回滚基线 | Rust（`backend/`、`agent/`） | 保留，CI 中继续测试 |

C++ 代码约 2.6 万行，其中最大的几个文件是 `http_server.cpp`（2925）、`store.cpp`（2090）、`windows/service_main.cpp`（1597）、`tests/http_server_test.cpp`（1500）。

## 2. 架构设计

### 2.1 分层

```
sb_easy_agent_runtime   可移植 Agent 状态机（仅依赖 nlohmann_json）
   ▲
   ├── sb_easy_agent          Linux：POSIX 适配器 + Drogon
   └── sb_easy_windows_platform  Windows：WinHTTP / DPAPI / Job Object / 命名管道

sb_easy_core            渲染器、QuickJS、SQLite 仓储、认证、WireGuard、解析器
sb_easy_http            Drogon 传输适配层
```

### 2.2 值得肯定的设计

1. **平台边界清晰（最大亮点）**。`AgentRuntime` 通过 `AgentRuntimeDependencies` 注入 `AgentHttp / PlatformProcess / PlatformStorage / PlatformClock / PlatformMetadata / AgentCore / AgentLocalRuntime`，类内无任何 POSIX/Windows 类型。`SB_EASY_PORTABLE_ONLY` 构建选项能在 CI 中强制验证这条边界，`agent_runtime_test.cpp` 用内存替身测试状态机。这是教科书式的端口-适配器做法，也是 Windows 客户端能低成本复用逻辑的原因。
2. **框架隔离**。README 声明“Drogon 仅限传输适配器”，CMake 里 `sb_easy_core` 不链接 Drogon，这一点从构建图上可以证实。
3. **QuickJS 沙箱设计谨慎**（`script_engine.cpp`）：每次执行新建 Runtime；内存/栈/源码/输出/超时五类限制；`Date` 与 `Math.random` 被禁用以保证配置和 ETag 确定性；不链接 std/os 与模块加载器；RAII 包装 `JSRuntime/JSContext/JSValue`。204 行，职责单一，质量很高。
4. **配置变更的安全流程**：先校验（`sing-box check`）→ 原子替换 → reload，失败则恢复上一份配置（`agent_runtime.cpp: apply_config`）；ETag 只在成功后保存。设计文档里的 candidate / active / last-good 与“失败默认放行（fail open）”原则都有对应实现思路。
5. **安全意识**：命名管道 SDDL 先拒绝 Network 再授权（`ipc.cpp`）；每次敏感调用重新校验客户端 PID/会话/管理员令牌；IPC 返回的配置递归脱敏（键名片段 + URL query）；嵌入的 sing-box/Wintun 做 SHA-256 校验；所有第三方依赖版本 + 哈希固定；子进程以参数向量执行，不经 shell。
6. **工程纪律**：`-Wall -Wextra -Wpedantic -Wconversion -Wshadow` / MSVC `/W4 /permissive-`，CI 开启 warnings-as-errors；广泛使用 `[[nodiscard]]`、指定初始化、RAII、`std::from_chars` 做严格数字解析；Drogon 头文件的告警被局部抑制而不是全局放宽。
7. **文档质量高**。`windows-client-design.md` 有决策理由、状态机、IPC 契约、验收标准、延期项，`cpp/README.md` 能指导构建和运行。

## 3. 主要问题

按影响从高到低排列。

### 3.1 巨型文件（可维护性风险，高）

- `http_server.cpp` 2925 行：路由、请求校验辅助函数、CORS、日志缓冲、错误映射、各业务处理器都在一个匿名命名空间里。前 300 行里已经出现 `ServerLogBuffer`、`CorsPolicy`、`trim`、`assign_*` 等本应独立的组件。
- `store.cpp` 2090 行：所有实体（用户、Profile、Host、命令、WG peer、代理、订阅……）的 SQL 都在一个文件里。
- `windows/service_main.cpp` 1597 行：除 SCM 入口外，还包含路由测试（URL 解析、手写 base64、套接字收发、CONNECT 隧道、Clash 连接关联）、RAII 句柄、网络事件等。设计文档里规划的 `windows_service.cpp / windows_network.cpp / named_pipe_server.cpp` 拆分没有体现。

建议：按资源拆分（`routes/hosts.cpp`、`routes/wireguard.cpp`…；`store/hosts.cpp`…；`service/route_test.cpp`、`service/network_events.cpp`…）。

### 3.2 重复的底层工具代码（中）

- `Handle`（Win32 句柄 RAII）在 `service_main.cpp` 与 `ipc.cpp` 中各写了一份，实现还不一致（后者多了 `release/reset`）；`Socket`、`ServiceHandle` 同理只存在于单个文件。
- `trim`、`lowercase` 在 `http_server.cpp`、`service_main.cpp`、`ipc.cpp` 中各自实现，写法也不同（`ranges` vs 迭代器）。
- 手写 `base64`（`service_main.cpp`）；项目已依赖 OpenSSL（Linux 侧）/ Bcrypt/Crypt32（Windows 侧），自写编码增加了需要测试的面。
- 手写 URL 解析（`parse_route_target`）逻辑细致但脆弱，建议抽成带单测的独立单元。

建议：新增 `sbeasy/win/handle.hpp`、`sbeasy/util/strings.hpp` 等公共头。

### 3.3 持久层使用位置索引（中）

`store.cpp` 的 `read_host`、`read_wireguard_peer` 等用 `statement.text(0..15)` 按列序号读取，必须和每条 `SELECT` 的列顺序手工保持一致；`Host` 有 16 列，新增列时极易错位且不会在编译期报错。建议集中定义列清单常量，或按列名取值。

### 3.4 日志与可观测性不统一（中）

`AgentRuntime` 直接使用 `std::cerr/std::cout`；HTTP 层用 Drogon 的 `LOG_ERROR`；Windows 侧有自己的 `log.cpp`。“可移植”的运行时却把输出硬编码到标准流，这与它的依赖注入风格不一致。建议增加 `PlatformLogger` 接口并注入。

### 3.5 `AgentRuntime` 内部小瑕疵（低–中）

- 状态用 5 个独立 `bool`（`refresh/start/stop/reload/restart_requested_`）加 `QueuedActions` 结构重复表达，可合并。
- `apply_config` 里 `options_.transform_options` 在锁内拷贝，而 `options_` 的其他字段无锁读取，锁的保护范围语义不明确（要么整体不可变，要么整体加锁）。
- `apply_config` 同时承担“受管核心”和“外部管理”两种分支，约 45 行，可拆成两个私有函数。
- 受管模式下 `stop` 与 `desired_running_` 的关系：我读到的前 300 行里 `desired_running_` 由哪里置位未能确认，需要读后半部分验证。

### 3.6 CMake 重复与体量（低–中）

`cpp/CMakeLists.txt` 613 行，`MSVC_RUNTIME_LIBRARY` 的设置在近 10 个目标上复制粘贴；Windows、可移植、POSIX 三种构建用多个 `return()` 提前退出，阅读顺序不直观。建议用 `sb_easy_configure_target()` 之类的函数收敛，或把 Windows 部分移入 `windows/` 子目录的 CMakeLists（设计文档本来就规划了 `windows/CMakeLists.txt`）。

### 3.7 双实现并存的负担（中，战略性）

Rust 后端/Agent 作为回滚基线仍在 CI 中构建测试，并靠 `scripts/check-cpp-parity.sh` 做对拍。这在迁移期是合理的，但两套实现要同时跟进新功能（如 Windows 能力字段、迁移 012），成本会持续上升。应当定出明确的 Rust 下线时间点。

### 3.8 仓库与流程卫生（中）

- **大量未提交改动**：16 个已修改文件 + 约 25 个未跟踪路径（整个 `windows/`、`cpp/src/windows/`、`cpp/src/platform/`、`agent_runtime.*`、Windows CI 工作流、迁移 `012`、5 个 PowerShell 脚本）。关键工作只存在于本地工作区，没有历史保护，也无法被评审。`agent_main.cpp` 单文件 diff 为 771 行变动。建议尽快按主题拆分提交（运行时抽取 / Windows 平台 / 安装器 / 迁移）。
- 仓库根目录有 `target/`（Rust 构建产物，上千个文件）；请确认已被 `.gitignore` 覆盖。`windows/ui` 下出现 `node_modules`、`dist`、`tsconfig.tsbuildinfo`，同样需确认忽略。
- 行尾：Git 提示多个文件 LF 将被转换为 CRLF，建议加 `.gitattributes` 统一。
- 文档与实际目录不一致：设计文档“规划布局”写 `windows/service`、`windows/ui-host`，实际源码在 `cpp/src/windows/`；`windows/core/` 是空目录。

### 3.9 测试

- 优点：测试覆盖面广——渲染器、脚本引擎限制、迁移与仓储、HTTP 契约、Agent 客户端/UI、可移植运行时、Windows 平台、带真实 sing-box/Wintun 的集成测试；测试代码量约占 C++ 总量的 15–20%。
- 风险：`http_server_test.cpp` 1500 行同样偏大；Windows 的网络切换、休眠恢复等需要 VM 验收，文档已诚实声明这属于 W5 未完成项；单元测试不能替代这些验收。覆盖率没有度量，本次也无法给出数字。

## 4. 评分（主观，基于阅读）

| 维度 | 评分（10 分） | 说明 |
| --- | --- | --- |
| 架构与分层 | 8.5 | 平台边界、依赖注入、框架隔离做得好 |
| 安全设计 | 8 | 威胁模型清晰，沙箱与脱敏完整；未做渗透验证 |
| 单文件可读性与模块化 | 5.5 | 多个 2000+ 行文件、重复工具代码 |
| 代码风格与现代 C++ | 8 | RAII、nodiscard、严格警告；少量手写轮子 |
| 测试 | 7.5（未运行） | 广度好，覆盖率未知，端到端依赖 VM |
| 构建与依赖管理 | 7.5 | 版本/哈希固定；CMake 重复较多 |
| 文档 | 8.5 | 设计决策、验收标准、运行说明俱全；局部与实现脱节 |
| 工程流程 | 5 | 大量未提交成果、双实现并存 |

**总体：约 7 / 10。** 设计层面（边界、安全、可测试性）明显优于平均水平；扣分主要来自“还没有拆开的大文件”和“尚未入库的大批改动”，这些都属于整理成本，而非根本性缺陷。

## 5. 建议的优先级

1. **立即**：按主题分批提交当前工作区，并确认 `.gitignore`/`.gitattributes` 覆盖 `target/`、`node_modules/`、`dist/`、行尾。
2. **短期**：抽出 Win32 `Handle`/字符串/base64 等公共工具；拆分 `service_main.cpp`（路由测试、网络事件）。
3. **短期**：给 `AgentRuntime` 注入日志接口，去掉直接的 `std::cout/cerr`。
4. **中期**：拆分 `http_server.cpp` 与 `store.cpp`，持久层改为按列名/常量列清单读取。
5. **中期**：收敛 CMake 中重复的目标配置；对齐设计文档中的目录规划与实际布局。
6. **战略**：确定 Rust 回滚基线的退出条件与日期，减少双份维护。
7. **验证**：在 CI 中引入覆盖率统计，并完成 W5 的 Windows 10/11 VM 验收矩阵。

## 6. 未验证项（需要进一步确认）

- 全量构建与 `ctest` 是否通过（`cpp`、`cpp-portable`、`cpp-windows`）。
- `http_server.cpp`、`store.cpp`、`service_main.cpp` 的后半部分是否存在更深的问题（如长函数、错误处理遗漏、并发问题）。
- `windows/ui`、`frontend`、`android` 代码质量（本次未审阅）。
- `.github/workflows/windows-client.yml` 的具体内容与 `.gitignore` 的实际规则。
