# C 实现代码坏味道整改方案

> 历史整改记录：本文保留当时基线及 `fix/agent-ui-hardening` 分支的实施、测试与运行状态；其中“已完成”不代表已合入当前 `master`，本机安装状态也可能已变化。当前行为以源码和运行检查为准。

对象：`origin/master`（8486f0b）下的 `c/`（`src/` 约 2.85 万行，26 个 `*_test.c`）。

> 重要更正：我之前输出的 `docs/code-quality-review.md` 评估的是 `cpp/`（C++20），不是 C 实现，结论不适用于本文对象。

## 0. 方法与可信度

- 读过的内容（初始阶段）：`CONVENTIONS.md`、`PROGRESS.md`、`README.md`、`c/CMakeLists.txt`、`util.c` 前 120 行、`http_internal.h` 前 120 行、`proxy_users.c` 的 `sb_proxy_lease_exchange` 开头、`store.c` 的若干 goto 清理段和 `upsert_one` 开头、`clash_websocket.c` 中 atoi 所在位置。后续补读的函数、文件和结论见第 7–17 节，每节都标明了已读范围，第 13 节汇总并发结论与未覆盖项。
- 只做了扫描、没有读内容的内容：全部 `c/src/*.c` 的 malloc/free、goto、不安全 libc 调用、静态全局、长函数（用 awk 启发式，可能漏报或误测）、重复的静态辅助函数。
- `apple/`、`windows/` 下的 C11 代码已在第 5 节补充扫描，只精读了其中少数函数（见第 5、7 节）；`ci.yml` 的 C 任务已读，`linux.yml` 只读了前 40 行，其他工作流未读；前端与 Android 不在范围内。
- 没有编译、没有运行任何测试。
- 因此本文不能保证“全部坏味道”都已列出，只覆盖上述扫描和阅读能证明的问题。整改后需要重新扫描一次。

## 1. 坏味道清单（按优先级）

### S1 超长函数（高）

扫描到 80 行以上的函数共 20 多个，最长的：

| 行数 | 位置 |
| --- | --- |
| 183 | proxy_users.c:945 sb_proxy_lease_exchange |
| 148 | agent_config.c:197 sb_prepare_agent_config |
| 144 | auth_oidc.c:730 sb_auth_oidc_finish |
| 124 | proxy_users.c:220 sb_proxy_user_save |
| 119 | proxy_users.c:825 lease_locked |
| 115 | script_engine.c:101 build_rules_n |
| 114 | store.c:2834 upsert_one |
| 112 | json.c:830 parse_value；auth_oidc.c:293 sb_auth_oidc_configure |
| 108 | proxy_parser.c:1989 clash_proxy；auth_oidc.c:612 verify_id_token |

以 `sb_proxy_lease_exchange` 为例，一个函数里串着：请求校验、报告项校验、重复 ID 检测（qsort）、哈希、加锁、事务、查询会话、重放判断。

整改：按阶段拆成纯函数，主函数只剩流程。

```c
static int lease_validate_request(const sbj *request, int64_t now, sb_err *err);
static int lease_validate_reports(const sbj *reports, sb_err *err);
static bool lease_has_duplicate_ids(const sbj *reports);   /* 内含 qsort，自己释放 ids */
static int lease_check_host(sqlite3 *db, const char *host, sb_err *err);
static int lease_load_session(sqlite3 *db, ..., lease_session *out, sb_err *err);

sbj *sb_proxy_lease_exchange(...) {
    if (lease_validate_request(request, now, err) != 0) return NULL;
    if (lease_validate_reports(sbj_get(request, "reports"), err) != 0) return NULL;
    ...
}
```

验收：单个函数不超过 80 行（认知复杂度高的不超过 50 行）；每个新函数有独立测试用例，覆盖原来的各个错误消息（错误消息是客户端可见契约，必须保持一字不差）。

### S2 goto 清理密度过高，且 prepare/bind/step/finalize 样板重复（高）

`goto` 计数：store.c 101、http_routes_hosts.c 76、proxy_users.c 73、http_routes_admin.c 59、auth_oidc.c 42。`store.c` 里 `sqlite3_prepare/finalize` 共 81 处，`UNLOCK` 宏与 `done:` 标签反复出现。

已观察到的具体风险：`sbq_bind_text_n` 失败后必须手工 `sqlite3_finalize(st)` 再 `goto done`（见 `upsert_one`、`sb_store_create_user`）。漏写一处就泄漏语句句柄。

整改：

1. 绑定错误改为粘滞错误，不在每次绑定后立刻检查：

```c
typedef struct { sqlite3_stmt *st; int rc; } sbq_stmt;
void sbq_stmt_bind_text_n(sbq_stmt *q, int idx, const char *s, size_t n); /* 失败时记 rc */
int  sbq_stmt_step_row(sbq_stmt *q, sb_err *err);   /* 若 rc 已失败则直接返回 -1 */
void sbq_stmt_done(sbq_stmt *q);                      /* finalize，可重复调用 */
```

2. 利用已开启的 GNU 扩展（`CMAKE_C_EXTENSIONS ON`，且 `_GNU_SOURCE` 已定义）提供作用域清理：

```c
static inline void sbq_stmt_cleanup(sbq_stmt *q) { sbq_stmt_done(q); }
#define SBQ_AUTO __attribute__((cleanup(sbq_stmt_cleanup))) sbq_stmt
```

   这样语句在任何 return 路径上都会被 finalize，`goto done` 只需要处理锁和堆内存。注意：`CONVENTIONS.md` 禁止 GNU nested functions，没有禁止 `cleanup` 属性，但要在约定文档里明确允许，否则会和现有规则冲突。

   已核实：`c/` 中目前没有任何 `__attribute__((cleanup` 用法；`sbq_*` 辅助函数定义在 `c/src/sqlite_internal.h`（全是 `static inline`），`LOCK/UNLOCK` 只是 `sb_database_lock/unlock`（单个 `pthread_mutex`）的宏封装，所以 `sbq_stmt` 可以直接加在该头文件里。另外 `sbq_bind_text`、`sbq_bind_int` 等不检查 `sqlite3_bind_*` 的返回值，只有 `sbq_bind_text_n` 返回错误，这是第二处隐患，粘滞错误方案可以一并解决。

3. 常见的“单行查询”收敛成辅助函数：`sbq_exists(db, sql, ...)`、`sbq_scalar_int(db, sql, ...)`。`sb_store_delete_user` 中的 `SELECT COUNT(*)` 就是典型用法。

4. 锁用 RAII 风格的宏包住（`SB_LOCKED(s) { ... }`），或让每个公开函数拆成“加锁外壳 + `_locked` 内核”，内核里不再有 `UNLOCK`。

验收：`store.c` 中 `goto` 总数下降一半以上；新增“语句泄漏”测试，用 `sqlite3_next_stmt()` 在每个公开函数返回后断言没有未 finalize 的语句（可放入测试辅助，ASan 无法发现这类泄漏）。

### S3 重复的静态辅助函数（中）

- `json_value_string`：`http_routes_admin.c:84` 与 `http_routes_hosts.c:62`，签名不同（一个输出 `const char **`，一个输出 `const sbj **`）。
- `json_string_is`：同样在两个路由文件各一份。
- `hexval`（`util.c:328`）与 `hex_value`（`proxy_parser.c:86`）重复。
- `json_empty`、`json_equals_string`（`agent_config.c`）、`json_text`（`auth_device_policy.c`）是 JSON 层的通用判断。

整改：

1. 先为每对函数补一个特征测试，固定它们的当前行为，特别是对 NUL 字节、缺失字段、null 的处理（`PROGRESS.md` 显示这是项目反复修过的兼容边界）。
2. 统一搬进 `sb/json.h`（`sbj_str_equals`、`sbj_is_empty`）和 `sb/util.h`（`sb_hex_value`）。
3. 两个签名不同的 `json_value_string` 不要硬合并，先改名为 `req_field_string` / `req_field_node`，再看是否能收敛。

### S4 `atoi` 不检查错误（中）

`clash_websocket.c:215`、`:224` 解析端口，`:574` 解析 HTTP 状态码。`atoi` 对 `8080abc` 返回 8080，对溢出是未定义行为，且无法区分 0 与失败。

整改：在 `util.c` 增加：

```c
/* 全部字符都必须是数字，范围 [min,max]，否则返回 -1 */
int sb_parse_int_range(const char *s, size_t len, long min, long max, long *out);
```

端口用 `sb_parse_int_range(p, n, 1, 65535, &v)`，状态码要求恰好三位数字且在 100–599。行为变化（以前宽松接受尾随垃圾）需要在 PR 里说明，并补对应的回归测试。

### S5 过大的文件（中）

| 文件 | 行数 | 拆分建议 |
| --- | --- | --- |
| store.c | 3626 | store_users.c、store_hosts.c、store_proxy.c、store_wireguard.c、store_enrollment.c，共享 `store_internal.h` |
| http_server.c | 2547 | 日志环、自管 sing-box 循环（`self_singbox_main`）、静态文件/SPA、遥测存储各自成文件 |
| proxy_parser.c | 2532 | 按协议拆：uri 解析、clash yaml、sing-box JSON |
| agent_main.c | 1463 | enroll、主循环、CLI 参数 |
| wireguard.c | 1325 | 密钥/配置生成与系统接口调用分开 |

测试文件同样偏大（`wireguard_test.c` 1830 行、`http_hosts_test.c` 1732 行），随被测模块一起拆。

`CONVENTIONS.md` 已规定共享私有头放 `c/src/<module>_internal.h`，并且 CMake 会自动 glob `src/*.c`，因此拆分不需要改 `CMakeLists.txt`。拆分必须是纯移动，不改逻辑，一次只拆一个文件，每次都跑完整 ctest。

### S6 长参数列表与“指针 + 长度”成对出现（中）

因为要保留嵌入 NUL 的字符串，接口大量采用 `(ptr, len)` 成对传参：`validate_proxy` 一次传 8 个参数，`sbq_bind_text_n`、`sb_json_assign_string_n` 等重复出现。

整改：引入值类型，替代成对参数。

```c
typedef struct { const char *p; size_t len; } sb_str;   /* 借用，不拥有 */
int validate_proxy(const sb_parsed_node *node, sb_err *err);
```

`validate_proxy` 与 `fingerprint_of` 已经有 `sb_parsed_node` 可用，应当直接传结构体。先改内部静态函数，不动公开头文件，降低兼容风险。

### S7 魔法数字（中）

示例：`proxy_users.c` 中 `4102444740LL`（约为 2100 年的时间戳）、`4096`、`128`、`4`；`http_server.c` 中扫描到约 126 处三位数以上的数字字面量（含 HTTP 状态码等合理用法，需人工筛）。

整改：数值上限、超时、缓冲区大小统一命名为 `enum` 或 `#define`，放在模块的 `_internal.h` 中，并写明单位和来源。HTTP 状态码使用命名常量或保持 civetweb 约定，不必强改。

### S8 全局可变状态（低到中）

`http_server.c`：`g_sink_owner`、`g_signal_pipe`；`proxy_runtime.c`：`native_owned`；`proxy_clock.c`：`registry`；`clash_websocket.c`：`bridges`；`util.c`：日志级别和 sink。

多数有互斥保护，也有明显的单例理由（信号管道、嵌入引擎只能有一个所有者）。整改只做两件事：

1. 每个全局旁边写明保护它的锁和生命周期。
2. 日志 sink 与 `g_sink_owner` 的“所有者”关系写进头文件注释，并增加“重复注册”测试。

不建议为了去全局而重构单例。

### S9 编译与静态检查的覆盖不一致（中）

来自 `c/CMakeLists.txt`：

- `sb_core` 开启 `-Wall -Wextra -Wshadow`，并且是唯一受 `-Werror` 约束的目标；
- 可执行程序只有 `-Wall -Wextra`，没有 `-Wshadow`，也没有 `-Werror`；
- 测试只有 `-Wall`；
- 全部目标都带 `-Wno-unused-parameter`，会掩盖真正漏用的参数；
- 没有在 `c/` 内发现 clang-tidy / cppcheck 配置（根目录有 `.clang-format`；已读取 `ci.yml` 的 C 任务：release 与 sanitizers 两档矩阵、`SB_EASY_WARNINGS_AS_ERRORS=ON`、ASan/UBSan 且 `detect_leaks=1`，没有 clang-tidy、cppcheck、覆盖率步骤；`linux.yml` 只看了前 40 行，未发现相关步骤）。

整改：

1. 把 `sb_enable_warnings(target)` 做成一个 CMake 函数，对 core、程序、测试统一应用 `-Wall -Wextra -Wshadow -Wformat=2 -Wconversion`（先用 `-Wno-error=conversion` 启动，逐文件清零后再转为错误），`SB_EASY_WARNINGS_AS_ERRORS` 对全部目标生效。
2. 去掉 `-Wno-unused-parameter`，确实不用的参数用 `(void)x` 或属性标注。
3. 增加 clang-tidy（至少 `bugprone-*`、`clang-analyzer-*`、`readability-function-size`）和 cppcheck 的 CI 步骤，先以报告模式运行，建立基线后再强制。
4. 把现有的 ASan/UBSan 命令固化为 CI 任务（`CONVENTIONS.md` 已要求无报告，但我没有确认 CI 是否每次执行）。

### S10 文档与注释的历史包袱（低）

- `http_internal.h` 头注释写着“port of cpp/src/http_server.cpp”“Drogon behaviours the C++ server relied on”，而 `CONVENTIONS.md` 已声明 `cpp/` 只是历史参考。头文件应描述当前契约，不应指向历史实现。
- `PROGRESS.md` 是按时间堆叠的发布与部署流水账，包含生产回滚容器名、备份路径、主机状态。它与代码版本无关，且持续变长，建议迁出到运维记录，仓库内只保留“当前状态 + 已知限制”。

## 2. 实施顺序

| 阶段 | 内容 | 风险 |
| --- | --- | --- |
| P0 | 先补测试：重复辅助函数的特征测试、语句泄漏检查、端口/状态码解析边界测试 | 低 |
| P1 | S9 统一编译告警（仅警告，不转错误）+ 静态分析基线 | 低 |
| P2 | S3 合并重复辅助函数、S4 替换 atoi、S7 命名常量 | 低 |
| P3 | S2 引入 `sbq_stmt` 与清理属性，先迁移 `store.c` 的用户相关函数，再逐步推广 | 中 |
| P4 | S1 拆分超长函数，一次一个，从 `sb_proxy_lease_exchange` 开始 | 中 |
| P5 | S5 拆文件（纯移动）、S6 引入 `sb_str` | 中 |
| P6 | S8、S10 文档与注释清理，告警转错误 | 低 |

## 3. 通用验收标准

每个步骤合入前必须满足：

1. `cmake --build` 无新增告警；
2. 26 个单元测试和 `control_plane_e2e` 全部通过；
3. ASan/UBSan 构建下全部通过，无泄漏报告；
4. HTTP 路径、状态码、错误消息、SQLite 模式、生成的 sing-box JSON 与 ETag 不变（`CONVENTIONS.md` 的兼容约定）；
5. 单次变更只做一类整改，保持可回滚。

目标度量（整改完成后重新扫描）：函数长度 ≤ 80 行、源文件 ≤ 1500 行、`atoi/strcpy/sprintf` 为 0、`store.c` 的 `goto` 数量下降 50% 以上、重复静态辅助函数为 0。

## 4. 协作约束

`CONVENTIONS.md` 规定多个 agent 并行编辑 `c/`，各自只改自己负责的文件，且不得自行 `git commit/stash/checkout/reset/clean`。执行本方案时需要先确认文件归属；拆分 `store.c`、`http_server.c` 这类共享热点文件时，要先和负责人约定冻结窗口。

## 5. 补充：windows/ 与 apple/ 的坏味道

范围：`windows/`（service 39 个、tests 36 个、ui-host 6 个 .c，约 1.4 万行）与 `apple/`（约 1300 行）。已读：`sbw_controller_dispatch` 的开头约 115 行和结尾约 40 行、`sba_build_runtime` 前 110 行、`capture.c` 的 `atoi` 所在段。其余只做了扫描（长函数、`goto`、`atoi`、重复辅助函数、长行）。

### W1 492 行的分发函数（高）

`windows/service/controller.c:1445` 的 `sbw_controller_dispatch` 有 492 行，文件内有 74 处 `strcmp/sb_streq(method, ...)`。已读部分的问题：

- 用 `if` 链按方法名分支，前缀匹配（`updates.`、`extensions.`、`capture.`）与全名匹配混用；
- “是否要求授权”“是否要求对象参数”“是否抢 `mutation_lock`”这些前置规则在每个分支里各写一遍，参数校验里有一行拼了约 20 个 `!sb_streq`；
- `TryAcquireSRWLockExclusive` 失败返回 BUSY、结尾 `ReleaseSRWLockExclusive` 的配对在十多处手写，任何一条新增的提前 return 都可能漏释放；
- 末段用 `goto done` 统一收尾，前段却是各分支内联释放，两种风格并存。

整改：改为方法表加统一前置检查。

```c
typedef struct {
    const char *method;
    sbw_handler handler;      /* sbj *(*)(sbw_controller *, const sbj *params, sbw_error *) */
    unsigned flags;           /* SBW_NEEDS_AUTH | SBW_NEEDS_MUTATION_LOCK | SBW_ALLOW_WHILE_UPDATING | SBW_EMPTY_PARAMS */
    const char *auth_message; /* 保持各自原有的 FORBIDDEN 文案 */
} sbw_method;
```

`sbw_controller_dispatch` 只做：查表、检查 `UPDATE_BUSY`、检查授权、检查参数形状、按 flags 加锁、调用 handler、解锁。每个 handler 独立成函数，放到 `controller_extensions.c`、`controller_capture.c`、`controller_enrollment.c` 等文件。

验收：分发函数不超过 60 行；锁的获取与释放只出现在分发函数中一处；每个方法的错误码和文案不变（先为现有分支补特征测试，再迁移）。前缀匹配规则（`updates.` 在 UPDATE_BUSY 白名单中、`capture.`/`preferences.` 等不要求对象参数的例外）要逐条保留，迁移时用方法清单对照。

### W2 单行多语句与超长行（中）

- 一行出现多个分号的行数：`capture.c` 78、`plugin_storage.c` 62、`controller.c` 62、`extension_store.c` 49、`extension_sandbox.c` 38。
- 超过 160 列的行数：`plugin_storage.c` 53、`controller.c` 39、`extension_sandbox.c` 27、`capture.c` 27；`c/src/observability.c` 也有 18 行。
- `capture.c` 的 `sbw_capture_observe` 把 `memset`、解析地址、`atoi`、拷贝字符串压在同一行，调试和 diff 都很困难。

整改：在仓库根 `.clang-format` 上设置 `ColumnLimit: 100`、`AllowShortIfStatementsOnASingleLine: Never`、`AllowShortBlocksOnASingleLine: Never`，对 `windows/` 一次性格式化，作为**单独一个只改格式的提交**（便于 `git blame --ignore-rev`），之后在 CI 里加 `clang-format --dry-run -Werror`。这一步必须先于 W1 的重构，否则 diff 无法评审。

### W3 `atoi` 与静默截断（中）

`capture.c:365` 用 `atoi` 解析端口并强转 `unsigned short`，`70000` 会被截成 `4464`。同一函数里 `strlen(base) < sizeof flow->app` 不满足时直接跳过拷贝，字段保持空串，没有任何日志。

整改：复用 S4 的 `sb_parse_int_range(...,1,65535,...)`，解析失败时丢弃该条流并计数；字符串过长时用截断拷贝并打一条限频日志。需要回归测试覆盖 `0`、`65536`、`abc`、空串。

### W4 重复的辅助函数（中）

- `wide_copy`：`windows/service/secure_store.c:41` 与 `windows/ui-host/main.c:51`；
- `base64`：`plugin_catalog.c:61`（解码）与 `preferences.c:23`（编码）名字相同、方向相反，`c/src/proxy_parser.c` 另有 `decode_base64`；
- `hexval/hex_value/hex`：`c/src/util.c`、`proxy_parser.c` 及 windows 侧各一份。

整改：`wide_copy`、UTF-8 与宽字符转换放进 `windows/common.c` 并导出；base64 编码、解码统一使用 `c/src/util.c` 的版本，名字按方向区分为 `sb_base64_encode/sb_base64_decode`，补齐尾部填充与非法字符的测试后再替换。URL 解析在 `windows/service/control_plane.c:105`（`parse_server`）、`route_probe.c:25`（`parse_url`）、`c/src/agent_clash.c:821`（`parse_url`）、`clash_websocket.c` 中各有一份，从函数名和长度判断是同类逻辑，是否能合并需要逐个对比后再定，先抽出 `sb_url_parse` 并让新代码使用，旧代码在有测试保护后迁移。

### W5 apple 的 273 行函数与重复清理（高）

`apple/Core/core.c:411` 的 `sba_build_runtime` 有 273 行，已读部分的问题：

- 失败时 `goto bad`，但每个失败点前要手写 `free(tun_tag)`、`sb_strvec_free(&names)`、`sbj_free(leafs)` 的不同组合，已读 110 行内至少有 6 处，漏掉一处就泄漏；
- 魔法数字 `32`、`512`、`256`、`64`、`128` 散落在校验中；
- 校验、改写、拼装混在一起。

整改：

```c
typedef struct { sbj *root, *subs, *prefs, *leafs; char *tun_tag; sb_strvec names; } build_ctx;
static void build_ctx_free(build_ctx *ctx);            /* 唯一清理点，可重复调用 */
static int validate_inputs(build_ctx *ctx);
static int collect_tun_tag(build_ctx *ctx);
static int validate_endpoints(const build_ctx *ctx);
static int merge_subscription_nodes(build_ctx *ctx);
static int apply_route(build_ctx *ctx);
```

所有失败路径统一为 `goto bad`，`bad:` 只调用 `build_ctx_free`。上限常量命名为 `SBA_MAX_SUBSCRIPTIONS`、`SBA_MAX_OUTBOUNDS`、`SBA_MAX_NODES_PER_SUBSCRIPTION`、`SBA_MAX_TAG_BYTES`。该函数是 Core 层对外边界，`error` 文案和输出 JSON 必须保持不变；`apple/Tests/core_test.c` 的 `main` 本身有 114 行，要同时拆成独立用例。

### W6 其他长函数（中）

扫描结果（awk 启发式，需要人工复核）：

| 行数 | 位置 |
| --- | --- |
| 211 | `update_transaction.c` 的 `sbw_update_helper_main`（约 133 行，文件内 37 处 goto） |
| 183 | `route_probe.c:327` `sbw_route_probe` |
| 138 | `subscription_parser.c:141` `sbw_subscription_parse` |
| 129 | `subscriptions.c:410` `fetch_run` |
| 122 | `controller.c:1094` `sbw_controller_background_tick` |
| 96 | `controller.c:561` `connection_activate`；`control_plane.c:105` `parse_server` |

处理方式同 S1：按阶段拆成静态函数，主函数只留流程，每次只拆一个并保持错误码不变。`control_plane.c` 有 82 处 `goto`，应在 W1 完成后用同样的上下文结构加单一清理点收敛。

### W7 测试入口过长（低）

`core_process_test.c` 的 `wmain` 283 行，`connection_test.c` 126 行，`runtime_config_test.c` 120 行，`secure_store_test.c` 114 行，`routing_groups_test.c` 108 行。整改：每个场景一个 `static void test_xxx(void)`，`main` 只负责顺序调用和汇总，并让失败信息包含用例名。

### W8 构建检查（中）

- `windows/CMakeLists.txt` 使用 `/W4 /utf-8`，`/WX` 只在选项开启时生效（第 71、77 行）；`apple/CMakeLists.txt` 已有 `-Wall -Wextra -Wshadow -Werror`。
- 我 grep 了 `windows/`、`apple/` 的构建文件和 `ci.yml`，没有找到 `/analyze`、clang-tidy 或 cppcheck。
- 整改：Windows 构建加 `/analyze`（先报告模式），并把 CI 的 `/WX` 设为必选；Windows CI 作业里加入 W2 的格式检查。

## 6. 更新后的实施顺序

在第 2 节的 P0–P6 基础上插入：

| 阶段 | 内容 |
| --- | --- |
| P1.5 | W2：`windows/` 格式化，单独提交，不含逻辑改动 |
| P2.5 | W3、W4：`atoi`、重复辅助函数 |
| P4.5 | W1：分发表重构（先补方法清单对照测试）、W5：`sba_build_runtime` 拆分 |
| P5.5 | W6、W7：其余长函数和测试入口 |
| P6.5 | W8：Windows `/analyze` 与格式检查进 CI |

## 7. 补读结果：controller.c 中段、sba_build_runtime 后半段、support.c

### 7.1 `sbw_controller_dispatch` 中段（controller.c:1560–1760，已读）

- 同一个函数里有三种收尾风格：早退时就地 `ReleaseSRWLock*` 后 return（`traffic.*` 分支）、`goto done` 统一收尾（可变更方法）、直接 return（只读方法）。`done:` 要同时释放 `mutation_lock` 和 `user_operation_lock`，而 `traffic.*` 分支只释放 `mutation_lock`，两套锁的释放规则散落在不同分支，新增分支很容易漏。W1 的方法表要把「持有哪些锁」做成 flags，由分发函数统一加锁、解锁。
- `updates.health` 分支约 40 行，嵌套 4 层，把核心版本检查、配置适配、配置检查、恢复连接、记录健康状态串在一起，应拆成 `update_health_check()`。
- `routing.set` 分支约 60 行，内联了参数校验、查找分组、改写 identity、重建配置、选择器切换，应拆成独立 handler。其中查找分组的循环找到后没有 `break`，会遍历全部分组，这属于行为细节，拆分时需用测试固定下来，不要顺手改。
- `subscriptions.fetch` 的按 ID 查找 URL 的循环同样没有 `break`，多个同 ID 时最后一个生效；同一行里塞了 for 循环加 if 加赋值，属于 W2 的单行多语句问题。
- 方法名前缀匹配（`strncmp(method, "updates.", 8)` 等）里的魔法长度 `8/12/14/11/10` 是手写字符串长度，改前缀时很容易算错。方法表落地后可以消掉，过渡期可用 `sizeof("updates.") - 1`。
- 好的一面：`sprintf_s` 带缓冲区大小，没有使用无界 `sprintf`。

### 7.2 `sba_build_runtime` 后半段（core.c:520–690，已读）

- 全函数内 `free(tun_tag); goto bad;` 的组合我数到约 14 处，另有 `names`、`leafs` 的不同组合。W5 的 `build_ctx` 方案可以直接把这些收敛为一个清理点。
- 失败原因靠先给 `message` 赋值再 `goto bad` 传递，没赋值时使用默认文案，容易出现「忘了设置 message」而给出笼统错误。建议改为每个校验函数返回具体原因枚举。
- 魔法数字：`1500`（MTU）、`172.19.0.1/30`、`fdfe:dcba:9876::1/126`、`"gvisor"`、`"cache.db"` 应放到命名常量。
- 函数后半段混合了 DNS 服务构造、规则前缀保护、本地分组、控制主机直连、TUN 入站、日志、缓存，共 6 个独立阶段，对应 W5 里的拆分函数，另需补 `apply_local_groups()`、`apply_control_host()`、`apply_tun_inbound()`。
- `if (!found && sb_starts_with(selected, "local-")) { push; found = true; }` 会在选择器里悄悄加入未校验的节点，属于需要业务确认的行为，不应在重构中改变。

### 7.3 `apple/Core/support.c` 与 `c/src/util.c` 重复（已读前 140 行）

`support.c` 的 `sb_fail`、`sb_err_clear`、`oom`、`sb_xmalloc/xcalloc/xrealloc`、`sb_strdup/strndup`、`sb_vasprintf/asprintf`、`sb_strn_eq/streq/starts_with/ends_with/str_empty`、`sb_trim_dup`、`sb_lower_dup`、`sb_str_set/setn` 与 `c/src/util.c` 的同名函数几乎逐行一致，只有格式不同（`support.c` 每个 `if` 都换行）。这是同一份实现的两个副本，修一处 bug 要改两处。

整改：确认 `apple/` 为什么不能直接链接 `c/src/util.c`（头文件注释写着 portable utility boundary，可能是为了避开 OpenSSL 依赖，`util.c` 包含了 `openssl/*`）。若原因是 OpenSSL，则把 `util.c` 拆成 `util_base.c`（字符串、内存、错误，无外部依赖）与 `util_crypto.c`，让 `apple/` 与 `c/` 共用 `util_base.c`，并在 CMake 里加一个「两份实现不得再出现」的检查。拆分前先对 `support.c` 余下部分（本次未读）做比对。

## 8. 再次补读：controller.c 末段、control_plane.c、extension_sandbox.c

### 8.1 `sbw_controller_dispatch` 末段（controller.c:1760–1900，已读）

- `routing.set` 与 `routing.gpt_default/server/node` 各自内联了一套「轮询核心 → 读取 `/proxies` 得到 previous → 切换 → `save_state` → 失败则回滚并报 `LIVE_ROUTING_UNCERTAIN`」，两份约 40 行，逻辑几乎相同，只有选择器名称和切换函数不同。`previous`、`selected` 在每个退出路径上手工 `free`，每段至少 5 处。
  整改：抽出 `live_switch(controller, selector_kind, selected, new_identity, error)`，把 previous 的获取、切换、保存和回滚封装在一处，调用方只传「选择器标识 + 目标」。回滚失败时写入 `runtime_error` 的三行代码也只保留一份。
- `enrollment.apply` 与 `enrollment.forget` 都有一段重复的「清空 candidate/last_good/runtime_error/checked_etag/checked_valid/core_error」序列，且都在持有 `state_lock` 时手写。整改：抽出 `reset_device_state_locked(controller)`，新增字段时只改一处。
- 好的一面：这一段里 `effective`、`next`、`groups`、`cfg`、`proxies` 在我读到的出口路径上都有对应释放，没有发现明显泄漏；这只是阅读结论，没有用 ASan 验证。

### 8.2 `parse_server`（control_plane.c:105–200，已读）

- 约 96 行，同时负责：scheme 判断、IPv6 与域名主机校验、端口解析、路径逐段百分号解码与规范化、拼接 origin。持有 `storage`、`path_storage`、`host`、`wide`、两个 `sb_buf` 共 6 个需释放资源，靠 `invalid:` / `done:` 两个标签收尾，是文件内 82 处 `goto` 的典型。
- 魔法数字 `253`、`63`、`16`（`sbeasy://enroll?` 前缀长度）、`4`（`URL:` 前缀长度）散落在代码里，前缀长度是手写字面量，改前缀时容易算错。
- 路径循环里临时把 `/` 改写成 `\0` 再恢复（`*next = '/'`），原地修改输入缓冲区，不易推理。
  整改：拆成 `parse_scheme`、`parse_authority`（IPv6 与域名各一个函数）、`parse_port`、`canonicalize_path` 四个静态函数，各自带单元测试（含 `[::1]:0`、`host..name`、`%2e%2e`、超长标签）；前缀长度改用 `sizeof("sbeasy://enroll?") - 1`；与 `route_probe.c` 的 `parse_url`、`c/src/agent_clash.c` 的 `parse_url` 对照后再决定是否合并，不要先合并。

### 8.3 `extension_sandbox.c` 开头（已读约 90 行）

- 整个文件基本是「一行多语句」风格（如 `token_info`、`grant_package`、`environment`），`grant_path` 在 11 行里串了 12 个资源和 8 个步骤，是 W2 的最严重样本。
- 好的一面：用 `step` 字符串记录失败阶段，并在关闭句柄前保存错误码（文件内注释已说明原因），这个模式值得保留。
- 小问题：`token_info` 中 `n > 65536` 是魔法数字；`grant_package` 的循环写 `i < 2` 而不是数组长度；`loopback_config` 每次调用都 `LoadLibraryExW` 再 `FreeLibrary`；手写 `CloseHandle` 配对在 `grant_path` 的 `done:` 里有 5 处。
  整改：格式化后再看；引入 `sbw_auto_handle` 清理宏（同 S2 的 `cleanup` 属性思路，Windows 侧用 MSVC 不支持 `cleanup`，应改用统一的 `close_all(&ctx)` 单一清理点）。注意 MSVC 不支持 `__attribute__((cleanup))`，S2 的方案只适用于 `c/` 与 `apple/`，Windows 代码要用上下文结构体加单一清理函数。

## 9. 补读：capture.c、plugin_storage.c、extension_store.c 开头

范围：`capture.c` 1–110 行、`plugin_storage.c` 1–90 行、`extension_store.c` 1–80 行。以下均为阅读结论，未编译、未用 ASan 验证。

### 9.1 潜在越界隐患（已核实当前安全，低优先级）

- `plugin_storage.c` 的 `package_layout` 声明了 `offsets[10]` 和 `sizes[10]`，`inspect_package` 却按 `known->file_count` 循环写入 `layout->offsets[i]`，函数内没有检查 `file_count <= 10`。如果某个插件的文件数超过 10，就会栈内越界写。已核实 `store_catalog.h` 的 `releases` 表：capture 为 10 个文件、statistics 为 8、http-debug 为 6、network-tools 为 4，当前没有越界。`sbw_extension_release.files` 本身也是 `files[10]`，初始化列表超过 10 项会在编译期报错。所以现状安全，风险是耦合：capture 恰好等于上限，`package_layout` 的 10 与 `files[10]` 的 10 是两个独立字面量，任何一处单独修改都会让另一处失效。结论：这是『隐患』而不是『缺陷』，降级为低优先级。
  整改：用 `_Static_assert` 或初始化时断言 `file_count <= SBW_PACKAGE_FILES_MAX`，并把 `10` 命名为常量，数组大小与检查共用同一个常量；补一个 `file_count = 11` 的负面测试。

### 9.2 重复实现

- SHA-256 十六进制摘要：`capture.c` 的 `sbw_capture_hash` 与 `plugin_storage.c` 的 `hash_bytes` 都是 BCrypt 打开算法、`BCryptHash`、关闭、循环 `sprintf_s`，只是限制不同（一个限制 `ULONG_MAX`，一个限制 `PACKAGE_MAX`）。`c/src/util.c` 里还有 OpenSSL 版 `sb_sha256_hex`。整改：Windows 侧在 `secure_store.h` 或 `common.c` 提供一个 `sbw_sha256_hex(bytes, len, out)`，限制由调用方先检查。
- 摘要格式校验：`sbw_capture_digest_valid` 与 `cache_path` 里的 `strspn(hash, "0123456789abcdef") != 64` 是同一件事，`prune_cache` 里又手写了一遍循环。整改：统一为 `sbw_hex_digest_valid()`。
- 读文件加“不是目录、不是重解析点”检查：`capture.c` 的 `regular()` + `read_path`、`plugin_storage.c` 的 `read_file`、`extension_sandbox.c` 的 `grant_path` 各写了一份 `FILE_ATTRIBUTE_TAG_INFO` 检查。整改：抽成 `sbw_open_regular_file()`，这类安全检查只应有一处实现，否则修一个漏洞要改三处。
- `directory()` / `present()` / `create_directory()` 与别处的路径辅助函数重复，需与 `windows/common.c`、`secure_store.c` 对照后合并。

### 9.3 隐藏的默认值与魔法数字

- `plugin_storage.c` 在缺少编译定义时回退到版本 `0.6.9` 和核心版本 `"1.14.3"`。这两个值会参与插件兼容性判断（`sbw_plugin_catalog_compatible`），而 `c/CMakeLists.txt` 里服务版本来自 `config/client-releases.json`，两处可能不一致，且回退是静默的。已核实：`windows/CMakeLists.txt` 第 68–69 行总会传入 `SB_EASY_VERSION_MAJOR/MINOR/PATCH` 和 `SB_EASY_CORE_VERSION`（核心版本在第 18 行还做了 `x.y.z` 格式校验），所以正常 Windows 构建里这段回退是死代码，当前不会产生版本不一致。残留风险只是：若该文件被其他目标（如测试）在不带这些定义的情况下编译，会静默使用 `0.6.9` / `1.14.3`。整改：去掉 `#ifndef` 回退，缺少定义就 `#error`，降为低优先级。已核实同源：`windows/CMakeLists.txt` 读取 `config/client-releases.json` 的 `development.windows.version`（当前 0.7.0），`c/CMakeLists.txt` 读取同一文件的 `development.service.version`（当前 1.1.0），核心版本来自 `config/runtime-versions.json` 的 `sing_box.version`。所以不存在两份版本来源不一致的问题。但 `plugin_storage.c` 里写死的回退版本 `0.6.9` 已经落后于当前的 0.7.0，说明这段死代码已经过期，正好印证了应当删除回退、缺定义时直接 `#error`。
- 魔法数字：`FILE_MAX 768U*1024U`、`PACKETS_MAX 128`、`FLOWS_MAX 4096`、`PACKAGE_MAX 160MB`、`layout->sizes[0] > 4096`、`wcslen(...) != 68`（64 位摘要加 `.sbe`）、`length < 8` 与 `memcmp(bytes, "SBECP001", 8)`、`32768`、`count > 4096`。整改：命名常量；包头魔数和长度用 `sizeof` 推导，比如 `wcslen(...) != 64 + sizeof(".sbe") - 1`。

### 9.4 结构与风格

- `struct sbw_capture` 内嵌 `attribution flows[4096]`（每项约 390 字节，合计约 1.6 MB）和 `pending[128]`。如果实例在栈上或被按值拷贝会出问题；目前看是堆上句柄，但没有任何注释说明。整改：在头文件注明只能 `sbw_capture_new` 创建，必要时把大数组改为按需分配。
- 整个文件是一行多个 `typedef`、一行多个语句的风格，属于 W2；先格式化，再重构。
- `allowed_key` 每次调用都在栈上构造名字数组并线性比较，应为 `static const`。

### 9.5 `extension_store.c` 的全局状态与加锁样板

- 文件级可变全局共 11 个：`lock`、`storage_lock`、`download_release`、`pending_bytes`、`pending_length`、`thread`、`stopping`、`busy`、`phase`、`received`、`failure`、`active_release`。两把锁分别保护哪些变量没有文档，`phase` 是 `const char *` 被其他线程读取。整改：收进一个 `static struct store_state`，并在其上方注明每个字段由哪把锁保护；这是本项目“单例 + 全局”风格里最值得先记录的一处。
- `sbw_store_status`、`sbw_store_verified`、`sbw_store_allowed`、`sbw_store_catalog_update`、`sbw_store_rollback` 全是“获取 `storage_lock` → `open_storage` → 调用 → `close` → 释放”的同一段样板。整改：抽 `with_storage(callback, ctx, error)`，加锁和关闭只写一次。
- `sbw_store_status` 用 `open_storage(NULL)` 吞掉错误，打开失败时返回空对象，调用方无法区分“没有状态”和“存储不可用”。整改：返回带 `available` 字段的对象，或把错误传出去。
- `sbw_store_catalog` 在持有 `storage_lock` 独占锁时构造整个 JSON，持锁时间偏长；应在锁内只复制所需状态，解锁后再构造。

### 9.6 `plugin_storage.c` 的错误处理

- `inspect_package` 有 8 个以上不同的失败条件，全部返回同一个 `bad(e)`，错误信息是固定的“插件包或已安装文件与受信任版本不匹配”，排查时无法知道是长度、魔数、摘要、清单还是版本不符。整改：保留对外统一文案，但在日志里写入具体阶段（沿用 `extension_sandbox.c` 里 `step` 字符串的做法，注意不能写入路径和密钥）。
- `receipt_release` 末尾 `if (!out && !e) bad(e); else if (...)`：当 `e == NULL` 时调用 `bad(e)`，传入的是空指针，这个分支没有任何作用，已核实 `common.c:104` 的 `sbw_fail` 对 `error == NULL` 直接跳过写入并返回 -1，所以 `bad(e)` 传空指针是安全的空操作，不是逻辑写反。真正的问题是这个 `if (!out && !e) bad(e);` 分支没有任何效果，属于多余代码，可删除；删除时保持 `else if` 分支行为不变。
- `safe_root` 在栈上放 `wchar_t full[32768]`（64 KB），在工作线程里调用时有栈溢出风险；整改：改为堆分配，或使用 `GetFullPathNameW` 先查询长度。

### 9.6.1 值得保留的做法

- `grant_path`、`write_new` 都在失败路径上清理了半成品（`DeleteFileW`），`write_new` 使用 `FILE_FLAG_WRITE_THROUGH` 并 `FlushFileBuffers`；`read_file` 拒绝重解析点。这些防护应在 9.2 的合并中完整保留。

## 10. 补读：self_singbox_main、sb_auth_oidc_finish、support.c 后半、upsert_one 后半

以下均为阅读结论，未编译、未跑 ASan。

### 10.1 `self_singbox_main`（http_server.c:2351，约 90 行，已读全）

- 一个线程函数混了五件事：监督器创建、配置渲染与重启循环、错误去重日志、Clash 流量采样与速率计算、状态上报。应拆成 `self_singbox_cycle()`、`self_singbox_sample_traffic()`、`self_singbox_report_status()`，主函数只保留循环与等待。
- 速率计算对 up、down 各写了一遍几乎相同的三元表达式，一行超过 200 列；应抽成 `rate_per_second(current, previous, elapsed_ms)`。
- 魔法数字：`1500`（超时）、`1024 * 1024`、`9007199254740991`（JS 安全整数，在 `/connections` 校验中出现 4 次，proxy_users.c 里也有 `SAFE_INTEGER`，应统一命名常量）、`2`（最小间隔秒）、`128`（版本字符串长度）。
- 采样失败、`sb_observability_sample` 失败、`sb_store_update_agent_status` 失败全部传 `NULL` err 静默忽略，运行中无法知道遥测已停止写入。建议至少对连续失败计数并限频记录日志。
- 注释写着 C++ would terminate here，属于对历史实现的引用，应改为描述当前行为（创建失败则该线程退出，托管 sing-box 不再运行，仅记录日志）。该行为本身值得确认：面板仍在运行但托管核心已死，状态是否会被上报为错误。
- 好的一面：停止通过条件变量加 `pthread_cond_timedwait`，不是睡眠轮询；退出路径上 `last_etag`、`logged_error`、`core_version`、`observation`、`config_path` 都有释放。

### 10.2 `sb_auth_oidc_finish`（auth_oidc.c:730，约 144 行，已读全）

- 三段式流程写在一个函数里：事务内消费一次性 flow、无锁网络交换 code 并校验 id_token、再加锁查用户链接。应拆成 `oidc_consume_flow()`、`oidc_exchange_code()`、`oidc_lookup_user()`，每段各自持有自己的资源，清理点从 13 个变量缩到各函数内。
- `st = !rc ? sbq_prepare(...) : NULL;` 这种用三元表达式串联错误状态的写法难读，且 `sbq_step_row(st, NULL)`、`sbq_prepare(..., NULL)` 把底层错误全吞掉，数据库故障与流程不存在在外部都表现为 OIDC authentication failed。对外统一文案是对的，但内部应记录区分原因的日志（不含 state、code、token）。
- 12 个 `char *` 局部变量加 3 个 `sbj *`，靠 `done:` 统一释放，且 `purpose` 在中途被重复赋值释放，容易出错；用上下文结构体可以收敛。
- 好的一面：绑定比较用 `sb_consttime_streq`；敏感串用 `sb_auth_sec_secret_free` 与 `OPENSSL_cleanse` 清除；网络请求在释放数据库锁之后进行；二次加锁后重新比对配置，防止交换期间被禁用。这些都应在重构中原样保留，并写成注释。

### 10.3 `apple/Core/support.c` 后半（已读全，纠正第 7.3 节）

- 第 7.3 节说 `support.c` 与 `util.c` 几乎逐行一致，读完后需要收窄：前 140 行（错误、内存、字符串）确实是同一份；后半的缓冲区、字符串向量、base64、hex、URL 编码我没有逐行比对 `util.c`。`sb_sha256_hex` 在 `support.c` 里有 Apple 的 CommonCrypto 分支，而 `util.c` 用 OpenSSL，所以这份副本至少部分是有意为之，不能简单判定为坏味道。整改前提改为：先逐函数对比 `util.c` 后半，把无平台差异的部分合并，平台相关的哈希单独留在各自文件。
- `b64_decode` 用 `int mode`（0 宽松、1 标准、2 URL）传模式，应改成枚举；函数内有 7 处 `goto bad`，结构清晰，但判定条件交织，建议各模式的补位与尾部比特校验拆成小函数并补测试（含 `=` 后接数据、尾部非零比特、长度模 4 余 1）。
- `sb_buf_append` 计算 `b->len + n + 1` 与 `cap *= 2` 没有溢出检查，当前调用都在受限输入下，风险低，但这是项目里所有缓冲区的底座，建议加 `SIZE_MAX` 检查并 abort，与 OOM 的处理一致。
- `sb_url_encode` 使用 `isalnum`，受 locale 影响；应改成 ASCII 范围判断。`hexval` 与 `c/src/proxy_parser.c` 的 `hex_value` 再次重复。

### 10.4 `upsert_one` 后半（store.c:2880–2950，已读全）

- UPDATE 与 INSERT 两个分支各有三段完全相同的 `if (sbq_bind_text_n(...) != 0) { finalize; goto done; }`，共 6 处；这正是 S2 的粘滞错误方案要解决的样板。
- 两条语句的占位符编号含义不同：UPDATE 里 `?8` 是 id、`?9` 是显示标签，INSERT 里 `?1` 是 id、`?9` 仍是标签，`?2` 是 source_tag 的来源。编号靠人脑对照，改任何一条 SQL 都容易错位。建议改用命名参数（`:tag`、`:id` 等）加 `sqlite3_bind_parameter_index`，或在 SQL 旁边用注释逐项列出编号。
- `UPDATE` 里 `CASE WHEN ?7 IS NOT NULL AND source_tag IS NOT NULL AND tag != source_tag THEN tag ELSE ?9 END` 表达了「用户手改过的标签不被订阅刷新覆盖」的业务规则，只存在于 SQL 字符串里，没有注释和对应的测试名；重构前应先补一条该规则的回归测试。
- 函数 114 行中，指纹计算、已有记录匹配、显示标签生成、UPDATE、INSERT 各占一块，可拆成 `upsert_find_existing()`、`upsert_update()`、`upsert_insert()`。

## 11. 补读：proxy_users.c 的三个长函数

以下为阅读结论，未编译、未跑 ASan，也没有读 `devices_locked`、`report_locked`、`runtime_ready`、`sb_proxy_clock_wait_ms` 的实现。

### 11.1 `sb_proxy_lease_exchange`（已读全，约 183 行）

- 一个函数里依次做：请求校验、报告校验、重复 ID 检测、会话重放与序号冲突判定、逐条处理报告、构造响应、遍历用户逐个续租、写会话。应拆成 `lease_validate_request`、`lease_load_session`（返回 replay/conflict 状态）、`lease_apply_reports`、`lease_build_users`、`lease_store_session`。
- 清理分三个出口：`done`、`rollback`、以及就地 `sbj_free(out); out=NULL; goto rollback`，`encoded` 变量被先 `free` 后重新赋值复用。阅读上没有发现泄漏，但这种复用很容易在改动时出错，应改成每段自己的局部变量。
- 持有数据库锁时调用 `sb_proxy_clock_wait_ms(database, ...)`，而 `proxy_clock.c` 有自己的 `registry_mutex`。锁顺序是否一致没有验证，需要读 `proxy_clock.c` 后确认，这是并发方面最值得查的一处。
- 魔法数字：`4102444740LL`、`4096`、`128`、`4`（请求字段个数）。同一文件的 `sb_proxy_user_save` 用的是 `4102444800LL`，两个时间上限相差 60 秒，来源和意图都没有注释，应统一为一个命名常量。

### 11.2 `lease_locked`（已读全，约 119 行）

- 一次调用做 5 条 SQL，并在 `lease_exchange` 的用户循环内逐用户执行，用户数上限 256，属于 N+1 查询。其中“可用 ingress 节点数”的查询只依赖用户绑定，可以与分配总量合并，或在循环外按用户分组一次取出。是否会成为瓶颈要看实际数据量，这里没有测量。
- 可能的错误路径缺陷（需写测试确认）：`hosts < 1` 时 `goto done`，此时 `out == NULL` 且没有调用 `sb_fail`。调用方把 `!u` 当作失败，会回滚整次交换并返回 NULL，而 `err` 没有被填充，HTTP 层会拿到空错误信息。由于外层已校验过该主机是已启用、运行时就绪的 ingress 节点，这条路径大概率不可达，但只要时间窗口判定不一致就会触发，应在此处显式 `sb_fail`，或改为返回“跳过该用户”。
- 隐式约定：`quota == 0` 表示不限额（`quota ? quota : SAFE_INTEGER`）、`expiry == 0` 表示不过期、`hosts` 默认值 1、向上取整的均分额度计算，都没有注释。应在函数头写清楚，并为 `grant==0`、`grant==used`、`available<=0` 三个边界补测试。
- `if (!id) goto done;` 紧跟在 `id = sb_uuid_v4()` 之后，如果 `sb_uuid_v4` 失败即 abort，则这是死代码，需要确认其契约。
- 返回值混用三种语义：NULL 表示错误、`sbj_null()` 表示跳过、对象表示成功。调用方还要再判断 `sbj_is_null`，建议改成 `int` 返回码加输出参数。

### 11.3 `sb_proxy_user_save`（已读全，约 124 行）

- 校验、旧记录比对、容量检查、绑定主机检查、UPSERT、重写绑定关系都在一个函数里，建议拆成 `user_validate_body`、`user_check_update_limits`、`user_check_capacity`、`user_check_hosts`、`user_write`。
- 魔法数字：`6`（字段数）、`128`、`32`（设备数与主机数上限，两处含义不同但同值）、`256`（用户上限）、`4102444800LL`。
- 主机绑定检查对每个 host 执行一次 `SELECT`，是小规模 N+1；统一用 `IN` 查询或预先取出集合即可。
- 统计有效设备数的循环里，对同一个字段连续调用 `sbj_get_int` 两次，可读性差，应取局部变量。
- 冲突文案把两种原因（额度低于已分配、设备数超限）合成一句，客户端看不出具体是哪个，但文案是对外契约，不能随意修改。如需区分，应新增错误码而不是改文案。
- 好的一面：整个函数在同一个事务里，失败统一 `rollback`，`generated` 在所有出口释放。

## 12. 补读：proxy_clock.c 与 sb_uuid_v4（更正第 11 节的两处未验证项）

以下为阅读结论，未编译、未跑 ASan/TSan。

### 12.1 锁顺序（更正 11.1）

- `proxy_clock.c` 有两把锁：`registry_mutex`（全局注册表）与 `clock->mutex`（每个时钟）。在已读代码里没有嵌套持有这两把锁：`attach`/`detach` 只持 `registry_mutex`，且在 `initialize_snapshot` 与 `destroy_clock` 之前释放。
- `sb_proxy_clock_set_source` 的顺序是 `database lock → clock->mutex`；`sb_proxy_clock_wait_ms` 只取 `clock->mutex`，其调用点 `proxy_users.c:1079`（位于 `lease_exchange` 内，已持数据库锁）顺序一致，没有发现反向（先 clock 后 database）的路径。
- 本节写作时尚未验证的三点（`proxy_users.c:163` 处 `wait_ms` 是否持库锁、`sb_proxy_clock_reset_epoch` 的调用点、`sb_database_proxy_clock` 的实现）已在 13.1 核实，顺序均为 database → clock。仍只能说“已读路径上顺序一致”，不能说“无死锁”。
- 整改：在 `proxy_clock_internal.h` 写明锁层级（database → clock → registry，且 registry 不与另两把嵌套），并用 TSan 构建在 CI 里跑 `proxy_users_test` 与 `proxy_runtime_test`；目前 CI 只有 ASan/UBSan，没有 TSan。

### 12.2 `sb_uuid_v4` 失败即 abort（更正 11.2）

- `util.c:383` 的 `sb_uuid_v4` 在随机数失败时直接 `abort()`，永远不返回 NULL。所以 `lease_locked` 里 `if (!id) goto done;`（紧跟 `id = sb_uuid_v4()`）是死代码，应删除；`store.c` 的 `upsert_one` 等处如有同样的 NULL 检查也一并清理。
- 同时这说明项目有两套失败风格：`sb_x*`/`sb_uuid_v4`/`sb_random_hex` 失败即 abort，而 `sb_random_bytes` 返回错误码。整改：在 `util.h` 注释里明确“不会返回 NULL”，避免调用方再写无效检查。

### 12.3 `proxy_clock.c` 自身的坏味道

- 魔法数字：`999`、`1000`、`1000000000`（时间换算）、`128`（用户名长度，与 `proxy_users.c` 的 128 是同一约束却各自写死），应命名为常量。
- `epoch` 链表线性查找且只增不删：用户数上限 256，规模可接受，但删除用户后条目不会回收，应在注释里写明上界，或在用户删除时清理。
- `initialize_snapshot` 在 `tables == 0` 时提前 `return sbq_commit`，其余失败走 `failed:` 回滚，两种出口风格并存；`"Monotonic clock is unavailable"` 分支在提交之后 return，行为正确但不易看出，建议加注释。
- 全项目 `pthread_mutex_lock/unlock` 返回值均未检查，属于全局约定，建议在 `CONVENTIONS.md` 写明“不检查”或封装成 `sb_mutex_lock`。
- 好的一面：注释清楚解释了 fence 与快照的意图；时钟源以注入方式提供便于测试；检测到时钟回退时返回 -1 而不是继续使用。

## 13. 并发结论与未覆盖项（整理版）

### 13.1 并发与锁顺序（仅限已读路径）

- 数据库锁：`LOCK/UNLOCK` 是 `sb_database_lock/unlock` 的薄封装，全局单一互斥锁。
- `proxy_clock.c`：已读全。锁序为 database → clock，registry_mutex 不与其他锁嵌套（见 12.1）。`wait_ms`（proxy_users.c:163，位于 `user_locked` 内，调用方已持库锁）和 `reset_epoch`（proxy_users.c:406，位于 `sb_proxy_user_reset` 内，已持库锁）都符合该顺序。`reset_epoch` 在 `sbq_commit` 之前调用，提交失败时内存 fence 已推进，只会让租约等待更久（偏保守），应在注释中写明。
- 日志：已读路径上的锁序为 `g_sink_owner_mutex -> g_log_mutex -> srv->log_mutex`，未发现反向依赖。坏味道：sink 在 `g_log_mutex` 内同步回调，sink 内若再调用日志宏会死锁（当前不会），应在 `sb_log_set_sink` 的头文件注释写明“sink 不得调用日志宏、不得阻塞”。`g_level` 是普通写入，唯一调用点 `http_server.c:2162`（启动阶段），当前没有并发写的证据，属隐患；整改：改为 `_Atomic` 或注明只能在启动阶段调用。结论限于对 `c/src`、`c/include` 的 grep。
- WebSocket：`bridges_mutex` 与 `b->mutex` 在已读代码中没有嵌套，`relay_pump` 全程不持锁。坏味道：`browser_send` 与 `close_with_error` 持有 `b->mutex` 时调用阻塞的 `mg_websocket_write`，慢客户端会卡住持锁线程以及 `bridge_browser_open`、`ws_close`。整改方向是锁内只改状态、锁外写，但 civetweb 连接在 `ws_close` 后可能被复用，改前必须先补“慢客户端 + 并发关闭”的测试。
- `self_singbox_running`：`self_singbox_request_stop` 无锁读取。已读 `self_singbox_start`/`self_singbox_join` 的函数体（写入点），但未读这三个函数的调用点，所以是“未发现竞争，也未证明没有”，需在字段旁注明线程归属并用 TSan 验证。
- `relay_pump`（95 行）：`goto out` 多出口、栈上 `char chunk[16384]`、魔法数字 5000 与 125，应命名常量并抽出 `relay_handle_frame()`。
- 未读：`store.c` 等文件的锁使用、`sb_log_set_level` 在测试和 agent 中的调用。全项目没有跑过 TSan。

### 13.2 其他未覆盖项

- `windows/`：`control_plane.c`（除 `parse_server`）、`extension_*.c`（除 `extension_sandbox.c` 开头约 90 行、`extension_store.c` 前 80 行）、`capture*.c`（除 `capture.c` 前 110 行）、`plugin_storage.c` 90 行以后只做了扫描；`controller.c` 已读 383–391、427–455、531–657、1094–1216、1445–1900 行（见第 7、8、17 节），其余部分未读。内存所有权与 Win32 句柄泄漏未用 ASan 验证。
- `apple/`：`support.c` 已读完（仅 `util.c` 后半未逐函数比对）；`core.c` 中 `sba_build_runtime` 之外未读；Swift 与 Tunnel 的非 C 代码不在范围内。
- 大型函数：已完整读过 `sbw_controller_dispatch`、`sba_build_runtime`、`parse_server`、`self_singbox_main`、`sb_auth_oidc_finish`、`upsert_one`、`sb_proxy_lease_exchange`、`sb_proxy_user_save`、`lease_locked`（其依赖的辅助函数未读）；`sb_prepare_agent_config` 读过全文但未深究所有权；`proxy_parser.c`、`wireguard.c` 的长函数、`route_probe.c`、`update_transaction.c` 只做了扫描。
- CI：`ci.yml` 的 C 任务已核实；`linux.yml` 只读了前 40 行；`windows-client.yml` 等未读。
- 没有编译，没有运行任何测试、ASan 或 TSan。

## 14. 补读：proxy_parser.c 两个长函数与 wireguard.c 的 provision_host

以下均为阅读结论，未编译、未跑 ASan，也没有读它们依赖的辅助函数（`string_value`、`sb_parse_outbound_config`、`take_peer`、`finish_node` 等）。

### 14.1 `clash_proxy`（proxy_parser.c:1989，约 108 行，已读全）

- 一个函数里做了：类型别名归一化、server/port 校验、tag 生成、六种协议的字段映射。类型归一化是一串 `if/else if` 加 `sv_eq`，应改成静态表（别名 -> 规范类型），每个协议一个 `clash_fill_<proto>()`，主函数只留校验、分发和清理。
- hysteria2 的密码回退（`password` -> `auth` -> `auth-str`）每一步都是「判空、`str_free`、重新取值」，同一模式手写了两遍。应抽出 `string_first_nonempty(proxy, keys, count)`。
- 默认值写成字面量：`bbr`、`native`、`xudp`、`5`、`auto`，应命名常量，并在测试里固定下来，因为它们决定生成的 sing-box 配置内容。
- 清理集中在 `done:`，我读到的路径上 `config`、`tag`、`server`、`raw_type` 都有释放，没有发现泄漏。`str obfs;`、`str pw;` 声明时未初始化，是否安全取决于 `string_value` 在返回 false 时是否保证不写入，这一点没读到，需要确认或直接初始化为 `{0}`。
- 类型不支持时（`!type`）要走完 server/port 校验和 tag 生成才退出，顺序可以调整为先判类型，纯性能与可读性问题，优先级低。

### 14.2 `sb_parse_subscription_report`（proxy_parser.c:2287，约 106 行，已读全）

- 三种输入格式（sing-box JSON、Clash YAML、URI 逐行）和一段后置过滤都在同一个函数里，JSON 分支内部又有四层嵌套。应拆为 `parse_json_entries()`、`parse_uri_lines()`，主函数只负责格式探测和后置过滤。
- Shadowsocks 的 `plugin` 检测在函数内手写了一个 query 解析循环，应抽成 `ss_uri_has_plugin()` 并单测（含 `plugin` 出现在 fragment 后、百分号编码的键名）。
- JSON 分支为 vmess/vless 补默认值的规则（`alter_id`、`security`、`flow`、`packet_encoding`）有注释说明原因（保留旧 API 的数组默认值怪癖，而订阅刷新要输出可运行的标量），这个意图值得保留，重构时原样带走并补回归测试。
- 局部变量 `sb_proxy_import parsed;`、`sb_parsed_node node;` 在声明时没有初始化，随后在失败路径上也会被 free。是否安全取决于 `sb_parse_outbound_config` 和 `sb_parse_proxy_uri_ex` 在失败时是否保证把对象置为可释放状态，这没有读到，应改为显式初始化，或在 ASan 下用失败输入验证。
- 末尾过滤无效节点用「逐个 `memmove` 前移」，最坏 O(n²)，且 skipped 信息固定为 Proxy entry，不带序号，排查时无法对应到哪一条。订阅规模通常不大，所以先补序号，性能不急。
- 错误选择：只保留第一个解析错误，其余被忽略；当没有任何可用节点时用它作为返回错误，行为合理，但应在函数头注释里写明，并为「首个错误 vs 通用校验错误」各补一条测试。

### 14.3 `sb_wireguard_provision_host`（wireguard.c:992，约 88 行，已读全）

- 三条路径混在一起：已有 host 绑定的 peer、复用同名且未绑定的旧 peer、新建 peer，之后再更新 host。应拆成 `find_or_adopt_peer()`、`create_host_peer()`、`apply_peer_to_host()`。
- 字符串与长度字段成对手写：`sb_str_set(...)` 之后再写 `xxx_len = strlen(...)`，出现多次（`wg_address`、`wg_public_key`、`clash_api`），名字拼接 `host: ` 还手工算长度并 `memcpy`。这是 S6 的典型，应提供 `sb_str_set_with_len()` 之类的辅助函数，一处同时维护指针和长度，避免漏更新长度。
- 魔法值：`6`（`host: ` 前缀长度）、`25`（keepalive）、`9090`（默认 Clash 端口）、`/32`，应命名常量，前缀长度用 `sizeof` 推导。
- 已读路径上，`preshared`、`allocated`、`ip` 都在使用后释放或转交，没有发现泄漏。复用同名旧 peer 的规则（精确同名、未绑定 host）有注释说明意图，但没有看到对应测试名，重构前应补一条回归测试。`keys` 私钥是否在释放时被清零取决于 `sb_wireguard_keypair_free`，没有读。
- `have_runtime` 标志只用于决定是否释放 `runtime`，如果改成在声明处用 `{0}` 初始化并让释放函数容忍零值，可去掉这个布尔变量。

### 14.4 对前文的更新

- 13.2 里「`proxy_parser.c`、`wireguard.c` 的长函数只做了扫描」应改为：`clash_proxy`、`sb_parse_subscription_report`、`sb_wireguard_provision_host` 已读全；这两个文件的其余长函数（例如 `yparse_node`、`sb_wireguard` 的其他函数）仍只做了扫描。
- 仍未读：`agent_clash.c` 的其余函数，以及各函数依赖的辅助函数。`subscription_parser.c` 的 `sbw_subscription_parse` 已在第 16 节读全。`route_probe.c`、`update_transaction.c`、`subscriptions.c` 的 `fetch_run`、`agent_clash.c` 的 `update_domain_route_stats` 已在第 15 节读全。

## 15. 补读：route_probe / update_transaction / fetch_run / update_domain_route_stats

以下均为阅读结论，未编译、未跑 ASan；依赖的辅助函数中，`request_callback`、`fetch_wait`、`request_release`、`fetch_release`、`add_domain_route`、`find_stat`、`find_observed`、`erase_stat`、`subtract_domain_route` 已在本节读过，`restore_previous`、`health_rpc`、`write_journal` 等未读。

### 15.1 `sbw_route_probe`（route_probe.c:327，约 183 行，已读全）

- 一个函数里做：参数校验、取消检查、所有权检查、基线连接快照、WinHTTP 会话/连接/请求建立、凭据设置、状态机轮询循环、结果与证据组装、清理。应拆成 `probe_open_request()`、`probe_wait_for_response()`、`probe_build_result()`，WinHTTP 三个句柄收进一个 `probe_http` 结构体加单一 `probe_http_close()`（MSVC 无 `cleanup` 属性，与 8.3 结论一致）。
- 取消检查 `cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0` 在本函数出现 3 次，应抽成 `is_cancelled(cancel)`。
- 十来处 `goto failed`，每处靠 `GetLastError()` 回读错误码；`failed:` 之前若某个失败的调用没有设置 last error，会落入 `ERROR_WINHTTP_INTERNAL_ERROR` 兜底，这个兜底是合理的，应保留。
- 魔法数字：`10000/15000`（超时默认与上限，与报错文案里的 “1000 and 15000” 各写一份，易不一致）、`150`（快照间隔）、`25`（轮询等待）、`64`、`"sb-easy-probe"`。
- 好的一面：口令用 `SecureZeroMemory` 清除；在发出首个带认证请求前再次校验代理归属；重定向被禁止；`state` 用引用计数处理回调与主线程的生命周期，`done:` 里对 `callback_owned`/`event` 的区分是有意的，重构时不能简化掉。
- 【已核实，结论：未发现句柄泄漏】已读 `request_release`（route_probe.c:174–179）与 `fetch_release`（subscriptions.c:365–371）：引用归零时都会 `CloseHandle(state->event)` 再 `free(state)`，`fetch_release` 还会 `SecureZeroMemory(state->bytes)`。因此 `done:` 里 `!callback_owned && !state->event` 只 `free`（事件创建失败）与其余情况走 `request_release`（事件已创建）的区分是正确的：回调未接管时引用数为 1，释放即归零并关闭事件；回调已接管时引用数为 2，回调在 `WINHTTP_CALLBACK_FLAG_HANDLES` 关闭通知里释放一次，`done:` 释放一次。该判断仅基于阅读，`request_callback`（route_probe.c:180–195）与 `fetch_callback`（subscriptions.c:372–396）已读：两者在 `WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING` 时各调用一次 `*_release`，其余状态只更新 `stage`/`win_error`/`read_length` 并 `SetEvent`，与“初始 1、接管回调时 +1、由 HANDLE_CLOSING 与 done 各释放一次”的模型一致，未发现重复释放。`request_callback` 我只读到第 195 行（`SENDREQUEST_COMPLETE` 分支之后被截断），其后续分支未读；两处结论都未用 ASan 验证。顺带发现的小问题：`fetch_state.bytes[8192]` 是未命名的魔法数字；`fetch_callback` 对 `REQUEST_ERROR` 只记 stage=-1，丢弃了具体 Win32 错误码，而 `request_callback` 保存了错误码，两处行为不一致，抽取 `winhttp_async_request` 共用模块时应统一为保存错误码；`fetch_wait` 的取消检查与 15.3 提到的重复检查同属一类，可一并收敛；`stage` 使用 0 表示“未就绪”，而 `fetch_run` 在每次读取前用 `InterlockedExchange(&state->stage, 0)` 复位，若回调恰在复位前完成会丢失一次完成通知，这个竞态窗口需要用 WinHTTP 异步读取的时序确认或加压力测试，目前不下结论。建议在两处引用计数结构旁注明“初始 1，接管回调时 +1，由 HANDLES 通知与 done 各释放一次”，并作为 15.1/15.3 抽取共用 `winhttp_async_request` 模块时必须保留的不变量。

### 15.2 `sbw_update_helper_main`（update_transaction.c:211，约 133 行，已读全）

- 这是整份代码里最需要谨慎对待的一处：它负责 MSI 升级事务、备份、回滚与恢复，两种模式（`--apply`、`--recover`）、7 个以上阶段（not_started、prepared、service_stopped、backed_up、installing、restoring、complete）全部挤在一个函数里，靠 37 处 `goto`、`terminal:`/`done:` 两个标签和 10 余个状态布尔量（`existed`、`backup`、`stopped`、`restore_attempted`…）推进。
- 整改方向：把阶段做成枚举加表，`apply_phase_*` 与 `recover_from_phase()` 各自独立，状态变量收进 `update_ctx`，清理只留一个 `update_ctx_free()`。**必须先补故障注入测试**（在每个阶段后杀进程，再跑 `--recover`），否则这类重构风险高于收益；现有测试是否覆盖未读。
- 返回值被忽略：`write_journal(..., "complete", ...)` 的结果在两处成功路径上被丢弃；`MsiEnableLogW(0, NULL, 0)` 同样。若日志写入失败，下次 `--recover` 会看到过期阶段。
- 魔法数字：`Sleep(2000)`、`600000`（等待安装器空闲）、`300`（job 有效期秒数）、`16U*1024U*1024U`、`sbj_obj_len(job) != 7`、`64`、`128`、返回码 `2/1/0` 无命名。
- 属性字符串 `INSTALLFOLDER=\"%ls\"` 没有转义引号；路径来自服务二进制所在位置，实际风险低，但应在注释中写明前提或拒绝含引号的路径。
- 好的一面：事务锁文件、签名清单校验、版本比较、journal 阶段持久化、`restore_attempted` 防止重复回滚、恢复前等待安装器空闲，设计是完整的，重构必须原样保留。

### 15.3 `fetch_run`（subscriptions.c:410，约 129 行，已读全）

- 所有失败都 `goto done`，只在末尾给出一个固定错误码，文案同时写着 “within 30 seconds (maximum 256 KB)”，所以 URL 非法、DNS 失败、非 200、响应过大、取消看到的是同一句话，只有“取消”被区分。应记录阶段（url/connect/send/status/read/body）到日志，对外文案可不变。
- 末尾对 `cancel` 调用了三次 `WaitForSingleObject`（清理前判断一次，清理后判断两次），取消事件在两次判断之间被置位会导致结果被丢弃但错误码是 FETCH_FAILED，或相反；应在入口读一次存成局部变量。
- `WinHttpSetTimeouts` 的返回值被忽略；`30000`、`5000`、`10000` 为字面量（`SUB_MAX_BYTES` 已命名，值得推广）。
- 与 `sbw_route_probe` 的 WinHTTP 异步样板（会话/连接/请求/引用计数状态/回调/等待）几乎重复，仅代理模式不同（此处 AUTOMATIC_PROXY，彼处 NAMED_PROXY，属有意区别）。应抽出 `winhttp_async_request` 小模块，两处共用，代理模式作参数。
- 好的一面：响应体在释放前 `SecureZeroMemory`，拒绝含 NUL 或非法 UTF-8 的内容，禁止 HTTPS 到 HTTP 的重定向，禁用认证与 Cookie，URL 带用户信息直接拒绝。

### 15.4 `update_domain_route_stats`（agent_clash.c:594，约 85 行，已读全）

- 一个函数里做：连接差分、新旧路由键比较、统计增减、清理已消失连接、排序、序列化。应拆成 `observe_connections()`、`prune_unseen()`、`export_stats()`。
- 所有权需核实：新连接分支里 `route_key` 同时传给 `add_domain_route(...)` 并存入 `added->route_key`，其它分支又 `free(route_key)`。如果 `add_domain_route` 内部也保存该指针，就是重复所有权，需要读该函数；如果它复制，则正确。【已核实，结论：无重复所有权】已读 `add_domain_route`（agent_clash.c:467–495）：它对 `route_key` 做 `sb_strdup`、对 `identity` 做 `sbj_clone`，不保存调用方传入的指针，所以 `update_domain_route_stats` 里各分支的 `free(route_key)` 与 `added->route_key = route_key` 的所有权划分是正确的。此项不是缺陷，仅建议在 `add_domain_route` 头注释写明“复制入参，不接管所有权”。
- 中途 `if (!identity) return NULL;` 时，前面连接已更新了 `seen` 与统计，但后面的剪枝没有执行，状态处于半更新；下一次调用会重置 `seen`，所以不会永久出错，但这个契约应写成注释并测试。
- 性能：每次轮询对 `stats` 全量分配、`qsort` 并克隆 `identity`；`find_observed` 是否线性扫描、`stats_len` 是否有上限（README 提到的 90 天、10 万行限制在 Windows 侧；已核实 C agent 侧有上限：`add_domain_route` 在 `stats_len >= 1000u` 时淘汰 `last_seen` 最旧的条目（线性扫描，规模下可接受），所以不会无界增长；但 `1000u` 是未命名的魔法数字，且淘汰是 O(n) 扫描，应命名常量并在注释说明；已读 `find_stat`（agent_clash.c:452–457）与 `find_observed`（575–581）：两者都是线性扫描，先比较 `fnv1a` 哈希再 `strcmp` 确认，哈希只是预过滤，不是哈希表，命中碰撞也不会出错。每轮轮询的代价约为 连接数 × `observed_len` 加上 连接数 × `stats_len`（上限 1000）。`observed` 数组每轮会剪掉未出现的连接（`kept` 压缩循环），所以长度受活跃连接数限制，不会无界增长；`clear_observed` 与 `sb_agent_clash_free` 都释放 `id` 与 `route_key`，已读路径上没有发现泄漏。坏味道：字段名 `hash` 容易让人误以为是哈希表，应在注释写明“仅作预过滤的线性扫描”；活跃连接上千时 O(n²) 才可能成为瓶颈，目前没有测量，不建议先改成哈希表。已读 `erase_stat`（459–465）与 `subtract_domain_route`（497–505）：`erase_stat` 释放 `key` 与 `identity` 后用 `memmove` 前移尾部并递减 `stats_len`；`subtract_domain_route` 先按路由键查找，找不到直接返回，找到后用 `max64(..., 0)` 钳制计数，三项都归零才擦除。已读路径上没有发现泄漏或重复释放。指针失效方面：`erase_stat` 的 `memmove` 会使指向 `stats` 数组的指针失效，但 `add_domain_route` 只在 `!stat` 时才淘汰最旧条目并随后重新取 `stat`，`update_domain_route_stats` 中 `subtract_domain_route` 之后不再使用旧的 `stat` 指针，所以未发现悬空指针。淘汰（`stats_len >= 1000`）可能删掉仍被活跃连接引用的路由键，之后对应连接的 `subtract_domain_route` 查不到条目而直接返回，不会出错，只是统计会少算，属于有意的有损行为，应在注释里写明。坏味道：`erase_stat` 的 `memmove` 与淘汰时的线性扫描都是 O(n)，规模上限 1000 下可接受；`(size_t)(stat - clash->stats)` 的指针差转下标写法容易出错，可让 `find_stat` 直接返回下标。以上均为阅读结论，未用 ASan 验证）。
- 魔法数字 `16`（初始容量）；容量翻倍无溢出检查，规模下可忽略。
- 好的一面：对计数器回退用 `max64(..., 0)` 防负值，连接路由变化时先 `subtract_domain_route` 再加，避免重复计数。

### 15.5 本节新增整改优先级

1. 先核实 15.4 的 `route_key` 所有权（已读 `add_domain_route` 确认不是缺陷（见 15.4），降为仅补注释；仍建议用 ASan 跑 `agent_clash_test` 做佐证）。
2. 15.2 补故障注入测试，之后再谈重构；在此之前只做低风险项（命名常量、检查被忽略的返回值）。
3. 15.1/15.3 的 WinHTTP 样板抽取，前提是先读 `request_callback`/`fetch_wait`。
4. 15.3 取消检查只读一次。

## 16. 补读：sbw_subscription_parse（subscription_parser.c:141，约 138 行，已读全）

以下均为阅读结论，未编译、未跑 ASan；依赖的 `base64_body`、`append_node`、`builtin`、`warning` 未读。

### 16.1 与 14.2 的关系：更正一处担忧

- 14.2 担心 `sb_proxy_import parsed;` 未初始化却在失败路径被 free。本函数里 `sb_proxy_import imported;` 同样先声明不初始化，但已读到 `sb_parse_subscription_report`（proxy_parser.c:2287）第一行就是 `sb_proxy_import_init(out)`，所以经由该函数调用时对象总是已初始化，这里不构成缺陷。仍建议声明时直接 `= {0}`，不依赖被调函数的隐含约定。`sb_parse_outbound_config` 那一处（14.2）仍未核实。

### 16.2 坏味道

- 三种输入格式（sing-box JSON、Clash YAML、URI 逐行）加 base64 预解码、结果组装、清理都在一个函数里，JSON 分支内有三层嵌套。应拆成 `parse_json_nodes()`、`parse_yaml_nodes()`、`parse_uri_lines()`，主函数只做格式探测与结果组装。
- 与 `c/src/proxy_parser.c` 的 `sb_parse_subscription_report` 在功能上重叠：后者也处理 JSON、YAML、URI 三种格式，本函数在 YAML 与 URI 分支里再调用它，只在 JSON 分支自己实现一遍。同一件事有两套 JSON 分支，行为（例如 vmess/vless 默认值补全，见 14.2）是否一致未核实，应先补对比测试，再决定是否让 Windows 侧直接复用 C 侧结果。
- URI 分支对每一行都调用一次完整的 `sb_parse_subscription_report`，其内部又会做 base64 探测、JSON/YAML 判断，开销与语义都比“解析单行 URI”大。应改为调用单行解析接口（如 `sb_parse_proxy_uri_ex`）。是否值得改要看订阅规模，这里没有测量。
- `sbj *node = NULL; if (!node) {` 中的条件恒为真，是多余分支，可去掉。
- 格式探测靠 `strstr(start, "proxies:")`，在整段文本任意位置出现该字样（例如某个节点备注）都会走 YAML 分支；探测顺序和判据应写成注释并补边界测试。
- 原地改写输入缓冲区（`*next++ = 0`、`line[--n] = 0`），行为依赖 `text` 是私有副本，应在注释里写明。
- 魔法数字：`256U * 1024U`（与 `subscriptions.c` 的 `SUB_MAX_BYTES` 各写一份，两处上限必须一致，应共用一个常量）、节点上限 `256` 在函数内出现 3 次、`32`（JSON 深度）、错误文案里的 “256 KB” 是第三份。
- 清理代码 `SecureZeroMemory(text)`、`free(text)`、`decoded` 的清零和释放在成功路径与 `parse_failed:` 各写一遍；`parse_failed:` 还会落入 `invalid:`，依赖标签顺序，没有注释。应收进一个 `cleanup`，并在标签处写明意图。
- 好的一面：入口拒绝含 NUL 或非法 UTF-8 的输入；订阅正文与解码结果在释放前清零；对节点数设上限；警告里用稳定的代码字符串，便于界面本地化。这些应在拆分中原样保留。

### 16.3 整改顺序

1. 先为三种格式、base64、NUL、非法 UTF-8、超过 256 个节点、`proxies:` 出现在备注里这些情况补特征测试。
2. 统一 256 KB 与 256 节点两个常量。
3. 删除恒真分支，改为直接调用单行 URI 解析。
4. 拆分函数；是否与 `c/src` 的实现合并，在对比测试通过后再定。

## 17. 补读：sbw_controller_background_tick 与 connection_activate（controller.c）

以下均为阅读结论，未编译、未跑 ASan。两个函数依赖的辅助函数中，`connection_stop`、`launch_healthy`、`clear_active` 已在 17.2 读过，`health_tick`、`management_commands`、`management_telemetry` 未读；`prepare_with_identity`、`check_config`、`save_state`、`observe_core` 已读（controller.c:400–415、217–226、458–476），结论如下（均为阅读结论，未用 ASan 验证）：

- `prepare_with_identity`：`sbw_routing_apply` 成功后直接取 `sbj_get(effective, "content")->v.str.ptr`，没有检查 `content` 是否为 NULL 或是否为字符串。入口处检查过的是 `source` 的 `content`，不是 `effective` 的；若 `sbw_routing_apply` 在某种输入下返回不含 `content` 的对象，这里会空指针解引用。我没有读 `sbw_routing_apply` 的返回契约，所以不下缺陷结论，建议补一次 NULL/类型检查，并给 `sbw_routing_apply` 的头文件补充“成功时一定含字符串 content”的契约注释。
- `check_config`：只是对 `sbw_core_config_check` 的一行封装，没有问题。
- `save_state`：`last_good == controller->last_good` 是指针相等比较，依赖调用方传入的就是 controller 自己持有的指针，语义隐含、没有注释；`controller->runtime.core_running` 和 `controller->last_good` 在加 `state_lock` 之前被无锁读取，随后才加锁写入，存在读写窗口。该函数的调用方多数已持 `mutation_lock`，所以实际是否竞争取决于 `state_lock` 与 `mutation_lock` 各自保护哪些字段，这一点文档和代码里都没有说明，应补充字段归属注释，并用 TSan 验证。
- `observe_core`：失败路径上 `sbw_core_stop(controller->core, NULL)` 在不持 `state_lock` 时调用，错误被丢弃；随后在锁内 `clear_active`、更新阶段、写 `runtime_error`。`sbw_core_poll` 返回 `CORE_BUSY` 时直接返回，这是有意的。魔法数字：健康检查超时 `600` 毫秒，应命名常量；错误码 `TUN_CORE_LOST`、`CORE_EXITED` 与前文的错误码字面量一样应集中定义。好的一面：TUN 核心丢失时给出明确的“验证网络恢复”提示，并走 fail-open 的清理路径，应原样保留。

### 17.1 `sbw_controller_background_tick`（controller.c:1094，约 122 行，已读全）

- 一个函数里串了十件事：抢锁与停止检查、扩展 tick、kill switch 5 秒复查与恢复、网络变化防抖与重连、核心健康与恢复退避、订阅刷新、配置同步与自动激活、远程命令、遥测、状态上报，最后 health tick。应拆成 `tick_kill_switch()`、`tick_network_change()`、`tick_recovery()`、`tick_sync_and_report()`，主函数只留加锁、顺序和 `done:`。
- 锁释放有两种写法：开头三处早退各自手写 `ReleaseSRWLockExclusive`，之后统一走 `done:`。`user_operation_lock` 在函数中途提前释放，`mutation_lock` 在 `done:` 释放，这个不对称没有注释，新增早退很容易漏。建议在注释写明锁的持有区间，并把「抢两把锁」收进一个 `tick_enter()`/`tick_leave()`。
- 「加 `state_lock` → 写 `runtime_error` 或调用 recovery 函数 → 解锁」的三行样板在本函数出现至少 8 次，应抽 `set_runtime_error()`、`recovery_failed()` 之类的小函数。
- 「恢复时优先 `last_good`，并取其 `local_identity`，没有则用当前 identity」的两行选择逻辑在本函数出现两次，之前读过的 `updates.health` 分支里还有一份，应抽成 `pick_recovery_source(controller, &source, &identity)`。
- 取消检查 `cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0` 在本函数出现 2 次，与 15.1、15.3 同类，可共用 `is_cancelled()`。
- 魔法数字：`5000`（kill switch 复查间隔）、`2000`（网络变化防抖）、默认同步间隔 `30`、`1000`（毫秒换算），应命名常量。
- 好的一面：用 `TryAcquire` 让后台 tick 在用户操作期间直接让路，不排队；失败修订只在新 etag 出现后才重试，注释说明是为了避免重启回滚死循环，重构时必须保留；`goto done` 保证 `health_tick` 与解锁一定执行。
- `sbj_set_str(status, "singbox_version", cond ? 版本 : NULL)` 向 `sbj_set_str` 传了可能为 NULL 的值，已核实安全：`sbj_set_str` 调用 `sbj_str`，后者对 NULL 返回 `sbj_null()`（json.c:64–67），所以会写入 JSON null，符合上报预期，不是缺陷。

### 17.2 `connection_activate`（controller.c:561，约 96 行，已读全）

- 流程顺序是对的：先校验、再在不打断旧实例的前提下检查新配置、预检、停旧、启动并确认健康、成功后才持久化 last-good，失败则清理并尝试回滚。这个顺序应原样保留，并写成函数头注释。
- 「`sbw_core_stop` → `sbw_core_poll` → 若 TUN 且 `last_stop_forced` 则判不安全」的清理判断出现了两次（启动失败后、回滚也失败后），仅错误文案不同，应抽 `stop_and_verify_core(controller, has_tun, &error)`。
- 成功分支和回滚分支都直接写 `controller->active = ...`、`controller->active_config = next`，前面没有看到释放旧值。是否泄漏取决于 `connection_stop` 是否已释放并置空 `active`，【已核实，结论：未发现泄漏】已读 `connection_stop`（controller.c:531–560）：它在持有 `state_lock` 时调用 `clear_active`（383–391），后者 `sbj_free(controller->active)` 并置 NULL、`sbw_runtime_config_free(&controller->active_config)`。`connection_activate` 在写入新的 `active`/`active_config` 之前都会先经过 `connection_stop`（成功分支和回滚分支都是如此），所以旧值已经释放，直接赋值不会泄漏。这是阅读结论，未用 ASan 验证。附带发现：`connection_stop` 失败时仍会 `clear_active` 并把阶段置为 DEGRADED，这是有意的 fail-open 行为，应写进函数头注释；`clear_active` 里同时清理 httpdebug、capture、active，职责偏杂，但是单一清理点，值得保留。另外 `launch_healthy`（controller.c:427–455）已读：健康检查超时 25000/10000/3000 ms 与 `sb-easy-local-` 前缀长度 `14` 是手写字面量，应命名常量并用 `sizeof("sb-easy-local-") - 1`。建议把「替换 active 及其 config」收进一个 `set_active_locked()`，释放旧值只写一次。
- 局部变量 `next` 在多个出口手动 `sbw_runtime_config_free`（至少 5 处），回滚路径还会重新给 `next` 赋值，应改为一个清理点。
- 返回前把 `controller->runtime_error` 拷到局部再返回，是为了避免锁外读取，设计合理，应加注释。
- 魔法字符串：错误码 `ROLLED_BACK`、`TUN_FORCE_STOPPED` 等分散在代码里，应集中定义。

### 17.3 整改优先级

1. 先用 ASan 加「连续激活、激活失败后回滚」测试确认 17.2 的 `active` 释放问题；确认之前不改代码。
2. 抽 `set_runtime_error()`、`pick_recovery_source()`、`is_cancelled()` 这类低风险小函数。
3. 为 tick 补行为测试（网络变化防抖、恢复退避、同 etag 不重试）后再拆分。
4. 最后处理 17.2 的 `stop_and_verify_core` 与 `set_active_locked`。

## 18. 补读结论：prepare_with_identity 与 store.c 加解锁配对

以下均为阅读结论，未编译、未跑 ASan/TSan。

### 18.1 撤销 17.x 中 prepare_with_identity 的 NULL 解引用疑点

已读 `sbw_routing_apply`（routing_groups.c:320–403）：成功路径（395 行）返回 `sbj_clone(source)`，并用 `sbj_str_take(sbj_dump(config,-1))` 写入字符串 `content`；所有失败路径（`unavailable`、`unsupported` 以及早退）都返回 NULL。因此 `prepare_with_identity` 在 `effective` 非 NULL 时读取 `content->v.str.ptr` 是安全的，该疑点不成立。仍建议在 `routing.h` 给 `sbw_routing_apply` 补一句契约注释：成功时一定含字符串 `content`，失败返回 NULL。该函数 84 行，`goto unavailable/unsupported` 两个收尾点内联了四个 `sbj_free`，属于可抽取的清理样板，另有一行内塞多语句的格式问题（W2）。

### 18.2 store.c 的加解锁配对

- 用 `LOCK(s)`/`UNLOCK(s)` 逐函数统计，全文件 LOCK 与 UNLOCK 总数相差 1。差值来自 `sb_store_save_capture`（store.c:3305–3340）：函数内 1 次加锁、2 次解锁，其中 3318 行是“摘要已存在”的提前返回（先 `sbq_commit`，失败则 `sbq_rollback`，再 `UNLOCK`，最后 `return`），3340 行是正常路径。两条路径都在返回前解锁，没有发现漏解锁或重复解锁。
- `sb_store_delete_subscription` 只是对 `exec_changes` 的 5 行封装，自身不加锁。
- 统计脚本的局限：按顶层行切分函数，`done:` 标签和多行签名会造成误报，上面的结论以人工读函数体为准。除 `sb_store_save_capture` 外，其余函数只核对了加解锁数量，没有逐个读出口路径，因此只能说“未发现不配对”，不能说“全部配对”。
- 坏味道：`sb_store_save_capture` 中间的提前 `return` 与末尾统一解锁并存，是 S2 提到的双出口风格；`128*1024*1024`、`1000` 是未命名的魔法数字（容量上限），错误文案里又写了一遍“128 MiB or 1000 files”，三处应共用常量；该函数的 SELECT/COUNT/INSERT 都是内联 SQL 加手写 `sqlite3_finalize`，适合用 S2 的 `sbq_stmt` 方案收敛。
- 提前返回路径上先提交事务再返回 `rc`，含义是“已存在则视为成功”，没有注释说明，应补充。

## 19. 补读：health_tick / management_commands / management_telemetry（controller.c）

以下均为阅读结论，未编译、未跑 ASan/TSan。依赖的 `sbw_health_step`、`save_receipt`、`command_receipt`、`refresh_configuration`、`remote->*` 回调未读。

### 19.1 `health_tick`（controller.c:1077–1093，约 17 行，已读全）

- 结构清晰，没有明显坏味道。它读取 `controller->active/candidate/identity/health` 时没有持 `state_lock`，只在写 `health_snapshot` 时加锁。唯一调用点是 `sbw_controller_background_tick` 的 `done:`，此时已持 `mutation_lock`，所以只要这些字段都由 `mutation_lock` 保护就没有竞争；该约定没有文档，应在 `sbw_controller` 结构体字段旁注明各字段归属哪把锁，并用 TSan 验证。
- `sbw_core_poll(..., NULL)` 丢弃错误，与 `observe_core` 同类，属有意的尽力而为，建议加注释。

### 19.2 `management_commands`（controller.c:992–1038，约 47 行，已读全）

- 值得保留的设计：先把 `pending` 回执持久化再执行命令，崩溃后不会重复执行 restart，下次轮询把结果上报为 failed；未知命令也会以 failed 回执确认，避免服务端反复下发；用户手动断开时拒绝远程 restart。重构时必须原样保留，并为“执行中崩溃后恢复”补故障注入测试。
- 坏味道：
  - `128`（命令条数上限与命令名长度上限）是两处同值但含义不同的字面量，`"pending"`/`"done"`/`"failed"` 和 `"reload"`/`"restart"` 是散落的字符串字面量，错误码 `UNKNOWN_COMMAND`、`MANUALLY_DISCONNECTED` 同理，应集中定义。
  - `result` 同时承担循环结果和最后一次回调返回值，三处 `save_receipt` 失败都是“释放 receipt、置 -1、break”的重复三行，可抽 `finish_receipt()`。
  - `reload` 分支里先 `refresh_configuration`，成功且核心在运行才 `connection_activate`，失败时 `operation.message` 来自哪一步取决于分支，不易看出；应抽 `execute_command(controller, name, cancel, &operation)`，主循环只负责回执生命周期。
  - `save_receipt` 失败时直接 `break`，不会对该命令发 ack；服务端会再次下发，下次轮询看到 pending 回执并上报 failed。行为合理，但没有注释。
- 未验证：`command_receipt` 返回的指针在 `save_receipt` 之后是否仍有效（`prior` 在 `receipt = sbj_clone(prior)` 之后不再使用，当前安全）；回执表是否有上限（是否随命令数无限增长）未读。

### 19.3 `management_telemetry`（controller.c:1039–1061，约 23 行，已读全）

- 隐私注释明确：只上报聚合计数，进程名、URL、域名需显式诊断上传，值得保留。
- 速率计算（`(upload - previous) * 1000.0 / elapsed`，计数回退时记 0）与 `c/src/http_server.c` 的 `self_singbox_main` 里的 up/down 计算是同一公式的第三份实现（含 agent 侧），应抽 `sb_rate_per_second(current, previous, elapsed_ms)` 共用，并为“计数回退”“首次采样”“elapsed 为 0”补测试。
- 核心未运行时 `connections` 为 NULL，随后 `sbj_get_int(connections, ...)` 与 `sbj_arr_len(sbj_get(connections, "connections"))` 依赖这些函数对 NULL 的容忍，我只确认过 `sbj_str(NULL)`，没有读 `sbj_get`/`sbj_get_int`/`sbj_arr_len` 的 NULL 处理，不下结论；建议在此处显式处理 NULL 而不依赖约定。
- 核心停止时仍会上报 total=0 并把 `telemetry_upload/download` 重置为 0，重启后计数从 0 开始再累加，服务端看到的是“总量回落”；是否符合服务端预期未读服务端代码，需确认。
- `1000.0` 是毫秒换算字面量；`telemetry_*` 字段在无 `state_lock` 下写入，同样依赖调用方持 `mutation_lock`。

### 19.4 本节对前文的更新

- 第 17 节和第 13.2 节里 `health_tick`、`management_commands`、`management_telemetry` “未读”的说法，以本节为准；`controller.c` 仍有其余函数未读（如 `refresh_configuration`、`save_receipt`、`command_receipt`、`persisted_state`、`dashboard_snapshot`、`capture_dispatch`、`preferences_dispatch`）。

## 20. 更正 19.2 / 19.3 的两处疑点

以下均为阅读结论，未编译、未跑 ASan/TSan。

- 撤销 19.3 对 NULL 的担心：已读 json.c，sbj_as_int 对 NULL 返回 fallback（209-215 行），sbj_arr_len 对非数组返回 0（232 行），sbj_get 对非对象或 NULL key 返回 NULL（311-316 行）。因此 management_telemetry 在核心未运行、connections 为 NULL 时，up/down/conn_count 都得到 0，不会崩溃。仍建议在该处加一句注释说明依赖这一 NULL 容忍约定。
- 更正 19.2 对回执表无上限的担心：save_receipt（controller.c:976-991）每次只保留最近 127 条旧回执再追加新回执，最多 128 条，并且先持久化、成功后才替换内存副本，失败则释放 next，没有泄漏。坏味道：128 与 127 是手写字面量，应命名为常量并用 常量 - 1 推导；persisted_state 先把旧 command_receipts 克隆进 state，save_receipt 随后又 sbj_set 覆盖同一个键，多做一次整表克隆，可给 persisted_state 增加参数或在 save_receipt 里先取走再设置。
- command_receipt 返回借用指针，management_commands 在 sbj_clone 之后不再使用，当前安全。
- 未读：refresh_configuration 的函数体。上一次用 awk 只匹配到第 82 行的前向声明，没有读到定义，所以 19 节中 reload 分支的错误来源仍未核实。

## 21. 补读：refresh_configuration 等四个函数（controller.c:659–760）

以下均为阅读结论，未编译、未跑 ASan/TSan。依赖的 `config_counts`、`sbw_core_*`、`remote->fetch_config`、`apply_kill_switch` 未读；`management_settings_change` 只读到第 760 行（kill switch 回滚分支之后未读）。

### 21.1 refresh_configuration（659–707，约 49 行，已读全）

- 所有权：`download` 在 `done:` 统一释放，成功时先移交给 `controller->candidate` 并置 NULL，`counts`、`effective` 用后即释放，已读路径上未发现泄漏或重复释放。
- 值得保留：先用 `sbw_routing_apply` 校验下载内容，再 `save_state` 持久化，最后才在 `state_lock` 内替换内存副本，失败不会让内存领先于磁盘；“相同 etag 仍可能携带元数据更新”有注释，重构时必须保留。
- 坏味道：读取 `controller->identity/candidate/last_good` 时未持 `state_lock`，只能依赖调用方已持 `mutation_lock`（调用点 1017、1173、1927 均如此），该约定没有文档，应在结构体字段旁注明；`4096`、`keys[2]` 循环、字符串 `"profile"`/`"quickjs"`/`"unknown"` 是字面量，应命名常量；清空 `checked_etag/checked_valid/core_error` 这一组重置与 17 节 enrollment 的重置序列重复，可合并为同一个 `reset_candidate_state_locked()`。
- 未核实：`fetch_config` 返回 0 但 `download` 为 NULL 时 `config_counts(NULL)` 的行为。

### 21.2 management_status / replace_management_settings（728–753，已读全）

- `replace_management_settings` 先存储再发布，注释明确，值得保留。
- `management_status` 的 `(due - now + 999) / 1000` 与 `1000` 是毫秒换算字面量，同类写法在 background_tick、telemetry 中重复，建议统一 `ms_to_seconds_ceil()`；读取字段时依赖调用方持 `state_lock` 共享锁（dispatch 中已读到这样调用），同样应有注释。

### 21.3 management_settings_change（754–760+，部分已读）

- 校验里 `15`、`3600` 出现在代码中两次（比较），错误文案里再写一遍“15 to 3600”，共三处，应共用常量；四个布尔键名靠一串 `sb_streq` 判断，可改为静态键表；`sbj_get_int(params, key, 0)` 对同一键连续调用两次，应取局部变量。
- 未读部分：kill switch 失败后的回滚分支，不下结论。

### 21.4 对前文的更新

- 第 20 节“未读 refresh_configuration”已解决，以本节为准；controller.c 仍未读的函数包括 `dashboard_snapshot`、`capture_dispatch`、`preferences_dispatch`、`config_counts`、`apply_kill_switch`、`extensions_tick`、`httpdebug_dispatch` 等。

## 22. 补读：config_counts / apply_kill_switch / management_settings_change 后半段（controller.c）

以下均为阅读结论，未编译、未跑 ASan/TSan。未读：sbw_json_string、sbw_core_executable、sbw_kill_switch_apply 的实现。

### 22.1 config_counts（103-120，已读全）

- 21.1 担心 download 为 NULL 时的行为：sbj_get(NULL, ...) 返回 NULL（见第 20 节对 json.c 的核实），content 为 NULL 后交给 sbw_json_string 判断；只要该函数对 NULL 返回 false，就会走 invalid 并返回 NULL。sbw_json_string 的 NULL 处理我没有读，所以结论是“很可能安全，未完全核实”。
- 坏味道：8U*1024U*1024U 与 JSON 深度 32 是未命名字面量；invalid 标签前的 sbj_free(config) 手写在条件分支内，而 107 行的 goto invalid 不释放，靠 config 尚为 NULL 才安全，改动时容易出错，应收进单一清理点。
- 好的一面：对 inbounds/outbounds/route/rules 做了类型校验，且只返回计数，不泄露内容。

### 22.2 apply_kill_switch（416-426，已读全）

- 无论 sbw_kill_switch_apply 成功与否，都会刷新 kill_switch 状态并在 state_lock 内替换、释放旧值，没有泄漏；这个“失败后也刷新状态”的行为应写进注释。
- enabled 为 false 时不检查 controller->core，直接调用 sbw_core_executable(controller->core)；该函数对 NULL core 的容忍未读，需确认。
- 与 background_tick、connection_stop、launch_healthy 中重复出现的“先调用 apply_kill_switch(controller, true, ...) 再处理错误”样板可合并为 ensure_kill_switch()。

### 22.3 management_settings_change 后半段（760-777，已读）

- 值得保留：保存设置失败时尝试恢复之前的泄漏保护策略，恢复也失败则报 KILL_SWITCH_STATE_UNCERTAIN 并写入 runtime_error，行为与 fail-open 设计一致，重构时必须保留并补故障注入测试。
- 坏味道：成功后 controller->next_sync_ms = 0 在 state_lock 之外写入，与周边代码风格不一致，依赖调用方持 mutation_lock，需在字段旁注明；错误码 KILL_SWITCH_STATE_UNCERTAIN 与前文其他错误码一样是散落字面量。
- connection_intent（779-788）：持久化 manual_disconnect 失败且是“连接”时不更新 recovery 请求，失败且是“断开”时仍更新，语义不对称，没有注释，应补注释和测试。

### 22.4 对前文的更新

- 第 21 节 21.1 的“未核实 config_counts(NULL)”以 22.1 为准；21.3 的“kill switch 回滚分支未读”已由 22.3 读完。
- controller.c 仍未读：dashboard_snapshot、capture_dispatch、preferences_dispatch、extensions_tick、httpdebug_dispatch、switch_mode 等。

## 23. 补读：sbw_json_string / sbw_core_executable / dashboard_snapshot / switch_mode

以下均为阅读结论，未编译、未跑 ASan/TSan。未读：sbj_is_string 的实现、sbw_dashboard_snapshot、sbw_kill_switch_apply、sbj_set 对已存在键的处理。

### 23.1 对 22.1 / 22.2 两处疑点的结论

- sbw_json_string（common.c:136-139）先调用 sbj_is_string(value)，再检查长度和内嵌 NUL。只要 sbj_is_string 对 NULL 返回 false（同类的 sbj_is_array 已确认如此，sbj_is_string 本身未读），config_counts 在 content 为 NULL 时就走 invalid 并返回 NULL。结论：很可能安全，未完全核实。
- sbw_core_executable（core_process.c:672）对 NULL core 返回 NULL，所以 apply_kill_switch 在 enabled 为 false 且 core 为 NULL 时不会崩溃。sbw_kill_switch_apply 如何处理 NULL 可执行路径未读，关闭保护时是否安全仍待确认。

### 23.2 dashboard_snapshot（controller.c:1277-1305，约 29 行，已读全）

- 所有权清晰：connections、proxies 在 done: 统一释放，mutation_lock 在 done: 释放，所有早退都经过 goto done，已读路径上未发现泄漏。
- 校验值得保留：运行时对 connections、uploadTotal、downloadTotal、proxies 做了类型校验，非法响应返回 INVALID_RESPONSE。
- 坏味道：这是只读快照，却用 TryAcquire 抢 mutation_lock 独占锁，并在锁内做两次对 Clash API 的网络请求；仪表盘轮询期间会让连接、更新等用户操作返回 BUSY。应改为在锁内只复制必要状态（active_config、进程号），解锁后再请求，或改用共享锁；改前先补行为测试，确认是否有意用独占锁来避免与启动/停止并发。
- 未运行时 connections、proxies 为 NULL，直接传入 sbw_dashboard_snapshot。若该函数返回 NULL，随后 sbj_set_bool(result, ...) 会作用于 NULL，是否安全取决于 sbj_set 对非对象的处理，未读，不下结论，建议显式判空。
- connections 的 "connections" 字段允许数组或 null，而上方 management_telemetry 直接把它当数组用 sbj_arr_len，两处对同一响应的容忍度不一致，应抽出 validate_runtime_snapshot()。
- sample_ms 用 GetTickCount64 转 int64，observe_core(controller, false) 的错误被丢弃，字面量字符串 "etag"/"core_pid" 等分散。

### 23.3 switch_mode（controller.c:794-839，约 46 行，已读全）

- 所有权转移用“赋值后置 NULL，done: 统一释放”的写法，identity、candidate、last_good、managed、local、settings 在成功路径都被转移并置 NULL，失败路径由 done: 与 sbj_free(settings) 释放，已读路径上未发现泄漏或重复释放。
- 先持久化再在 state_lock 内替换内存副本，与 refresh_configuration、replace_management_settings 一致，值得保留；“切换模式必须先断开”也有明确的状态检查。
- 坏味道：
  - 替换成功后重置 checked_etag、checked_valid、runtime_error、management_error、同步时间戳的一长串，与 enrollment.apply、enrollment.forget、refresh_configuration 里的重置序列是第 4 份重复，应合并为 reset_device_state_locked()，并按“设备身份变化”与“候选配置变化”两个粒度拆成两个函数，避免过度重置。
  - persisted_state 已经克隆了 managed_archive 与 independent_archive，随后又 sbj_set 覆盖同名键，多做两次整表克隆（与 20 节 save_receipt 的问题同类）。sbj_set 对已存在键是否释放旧值未读，若不释放则每次切换泄漏两份存档，应用 ASan 加反复切换模式的测试确认。
  - 函数开头读取 controller 字段未持 state_lock，依赖调用方持 mutation_lock，与前文一致，应在结构体字段旁注明。
  - 变量 settings 在 goto done 之后才声明；goto 跳过初始化在 C 中合法，但 done: 之后不使用它，靠的是代码顺序，容易被后续修改破坏，建议把声明提到函数顶部并初始化为 NULL。
  - 记录“archive 指向 local 或 managed”的指针在 sbj_free(previous/local/managed) 的分支之后才取，顺序正确但易错，应加注释。
- mode_snapshot 只做三次克隆，没有问题。

### 23.4 对前文的更新

- 22.4 中“controller.c 仍未读：dashboard_snapshot、switch_mode”已解决。仍未读：capture_dispatch、preferences_dispatch、extensions_tick、httpdebug_dispatch、sbw_dashboard_snapshot 及 controller.c 其余零散静态函数。

## 24. 补读：sbj_setn / sbj_is_string / sbw_dashboard_snapshot（更正第 23 节三处未核实项）

以下均为阅读结论，未编译、未跑 ASan/TSan。未读：counter、text、strings 三个辅助函数。

- sbj_setn（json.c:328-358）：键已存在时先 sbj_free 旧值再替换；value 为 NULL 时存入 JSON null；目标不是对象或 key 为 NULL 时释放 value 并直接返回。结论：23.3 担心的 persisted_state 克隆后又 sbj_set 覆盖同名键会泄漏，不成立。真实问题只是多做一次整表克隆（性能与可读性），不是泄漏。该担忧撤销。
- sbj_is_string（json.h:94）对 NULL 返回 false。因此 sbw_json_string(NULL) 返回 false，config_counts 在 content 缺失时走 invalid 并返回 NULL。22.1 / 23.1 中 很可能安全 升级为 已核实安全。
- sbw_dashboard_snapshot（dashboard.c:143-179）开头即 sbj_object()，永远返回非 NULL 对象；对 NULL 的 connections / proxies 通过 sbj_get、sbj_arr_len、sbj_obj_len 的 NULL 容忍得到空结果。23.2 中 对 NULL 调用 sbj_set_bool 的疑点撤销。
- 该函数的小坏味道：魔法数字 128（连接行数上限）、1024（节点上限）、8 与 16（链、成员截断）、65535（延迟上限）；字符串字面量 GLOBAL 与 sb-easy-control-direct 散落；取 history 最后一项时在长度为 0 时用下标 0，依赖 sbj_arr_at 对越界返回 NULL，应显式判空并写注释。
- json.c 里 sbj_setn 用 xrealloc(NULL, n) 当 malloc 使用，风格不一致，可改为 sb_xmalloc。
- 对前文的更新：23.4 中 sbw_dashboard_snapshot 未读 已解决。controller.c 仍未读：capture_dispatch、preferences_dispatch、extensions_tick、httpdebug_dispatch 及零散静态函数。

## 25. 补读：capture_dispatch / preferences_dispatch / extensions_tick / httpdebug_dispatch（controller.c）

以下均为阅读结论，未编译、未跑 ASan/TSan。未读：`sbw_extension_process_new/work_directory/call` 对 NULL 的处理、`sbw_http_debug_overlay`、`sbw_preferences_*`、`sbj_clone(NULL)`、`capture_snapshot`、`extension_stop`。

### 25.1 capture_dispatch（2021-2071，约 51 行，已读全）

- 2022-2025 与 2032-2034 两段重复：都检查 `identity/core` 并在 `c->capture` 为空时创建。第二段在第一段通过后恒不触发，是死代码，可删除（两段的错误文案不同，删除时保留第一段的文案）。
- 一个函数里分发 validate、configure、snapshot、rotate、delete、upload、read 七个方法，read 分支内嵌了分块和 Base64 编码约 14 行，应拆成 `capture_read_chunk()`；方法名比较与 `sbj_obj_len(params) != N` 的校验分散在各分支，适合 W1 的方法表。
- 魔法数字：`768 * 1024`（与 `capture.c` 的 `FILE_MAX` 是同一上限却各写一份，应共用常量）、`65536`（分块大小）、`2U/1U`。
- 值得保留：`bytes` 在所有出口都经 `SecureZeroMemory` 后释放；offset 先校验范围再读文件；Base64 先查长度再分配。编码结果 `encoded` 未清零，抓包片段属敏感数据，建议与 `bytes` 一样清零。
- `goto invalid` 位于 `free(bytes)` 之后或分配之前，已读路径上没有泄漏。

### 25.2 preferences_dispatch（885-941，约 57 行，已读全）

- 命名反直觉：`int valid = ...; if (valid) return NULL;` 中 0 表示成功，应改名为 `rc`/`failed`。同类写法在 `controller.c` 多处出现（`updated`、`applied`、`checked`）。
- 魔法数字：`1024`、`64`、`32`、`300000` 与 `300`（预览有效期毫秒与秒，两份必须一致，应由一个常量推导）、前缀长度 `18`（`preferences.cloud.`，应用 `sizeof(...) - 1`）。
- `preferences.cloud.*` 除 `put` 外直接把 `params` 透传给 `sbw_preferences_cloud_call`，此处不校验参数个数；是否在被调函数内校验未读，不下结论。
- `preview_id` 用 `strcmp` 比较。它只是 5 分钟内有效的本地一次性令牌，且调用受 IPC 授权保护，风险低，但它起到能力凭证作用，建议用常量时间比较并在注释中说明。
- 预览状态（`preferences_pending/base/source/preview_id/expires`）在无 `state_lock` 下读写，依赖调用方持有 `mutation_lock`，应在结构体字段旁注明。
- 值得保留：预览与应用分两步、预览过期、应用前比较身份与候选配置是否变化（`PREFERENCES_LOCAL_CONFLICT`）、随机数用 `BCryptGenRandom` 后清零。所有权：`merged` 在失败分支释放、成功后转入 `preferences_pending`；`pending` 取出后置 NULL 再释放，已读路径上未发现泄漏。

### 25.3 extensions_tick（1381-1396，约 16 行，已读全）

- 三个扩展的 id 与运行状态用并行数组 `ids[]`/`running[]` 表达，新增扩展要同时改两处和循环上限 `3`，应合成一个结构数组并用 `sizeof` 推导长度。
- `30000` 是未命名常量；`extension_stop` 的返回值与 `sbw_extension_change(..., NULL)` 的错误被丢弃。后者传 NULL 错误指针是安全的（`sbw_fail` 已核实容忍 NULL），但被丢弃的失败使「校验失败 → 停止 → 禁用」在禁用失败时无任何记录，建议至少记一条日志。
- 提交与中止路径正确：停止成功才 `sbw_store_commit`，否则 `sbw_store_abort`。

### 25.4 httpdebug_dispatch（1397-1444，约 48 行，已读全）

- 一行多语句风格最严重的函数之一（W2），例如 1403 一行串了 5 个语句和 3 个分配。
- 「停止核心 → `launch_healthy` → 失败则用旧配置再启动一次并忽略错误」的回滚样板出现在 stop（1413-1418）和 attach（1435-1439）两处，且和 `connection_activate` 的回滚逻辑相似，应抽出 `relaunch_with_rollback(c, next_config, previous_config, &error)`。
- 未验证的潜在问题：1402 `sbw_extension_process_new` 失败返回 NULL 时，1403 的 `sbw_extension_process_work_directory(c->httpdebug)` 与 1405 的 `sbw_extension_process_call(c->httpdebug, ...)` 直接使用该指针。若这两个函数不容忍 NULL，就是空指针解引用；我没读它们，所以不下结论，建议显式判空并返回错误。
- 1433 起对 `c->active_config.json` 做指针交换：失败分支恢复 `original` 并 `sbw_secret_free(adapted)`，成功后 `httpdebug_base = original`，停止时 `sbw_runtime_config_free(&c->active_config)` 释放 adapted。所有权划分在已读路径上自洽，但依赖 `json` 字段由 `sbw_runtime_config_free` 释放，并且 `adapted` 需与 `sbw_secret_free` 对应的分配方式一致，建议加注释并用 ASan 加反复 attach/stop 测试确认。
- 该函数绕过 `connection_stop/clear_active`，直接 `sbw_core_stop`，所以不会走流量收集与 kill switch 逻辑。是否有意未读证据，需确认；加注释说明。
- `domains` 参数在此不校验，依赖 `sbw_http_debug_overlay` 内部校验（未读）。
- 值得保留：返回给界面前删除 `password` 与 `username`；已存在会话时拒绝重复 start；attach 前先对新配置做 `check_config`，失败不触碰运行中的核心。

### 25.5 对前文的更新

- 24 节「controller.c 仍未读：capture_dispatch、preferences_dispatch、extensions_tick、httpdebug_dispatch」已解决。controller.c 仍未读的是零散静态函数（如 `ready`、`cancelled`、`record_check`、`apply_local_identity`、`extension_stop/enable`、`capture_upload_*`、`ensure_statistics`、`collect_traffic`、`persist_traffic`、`config_summary`、`runtime_status`、`enrollment_status`、`sbw_controller_poll` 及 new/free）。

## 26. 补读：extension_process 的 NULL 处理与 controller.c 零散静态函数

以下均为阅读结论，未编译、未跑 ASan/TSan。未读：`sbw_extension_process_new`、`sbw_extension_process_free` 对 NULL 的处理、`sbw_traffic_record(NULL, ...)`、`sbw_capture_snapshot(NULL)`、`capture_upload_main`。

### 26.1 撤销 25.4 的空指针疑点

- `sbw_extension_process_work_directory(NULL)` 返回 NULL（extension_process.c:16），`sbw_extension_process_call(NULL, ...)` 返回 EXTENSION_MISSING 错误（同文件 25 行）。所以 `httpdebug.start` 在 `process_new` 失败时，目录得到空串、`call` 失败并返回 NULL，不会解引用空指针。该疑点撤销，仅剩 `sbw_extension_process_free(NULL)` 未读。建议在 `process_new` 失败后显式判空，并在三个函数头注释写明 NULL 容忍约定。
- `sbw_extension_process_call` 内的 20000/3000 毫秒超时是未命名字面量，`start` 与其他方法的区分用字符串比较，应改为常量和枚举。

### 26.2 controller.c 零散静态函数（已读）

- `ready`/`cancelled`/`record_check`：结构清楚。`cancelled` 正是前文反复出现的取消检查的现成封装，说明 15.1/15.3/17.1 里内联的 `cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0` 应改用同一个带 HANDLE 参数的公共函数。
- `apply_local_identity`（843-874）：没有发现泄漏。`source`、`next` 在所有出口释放；先 `save_state` 再在锁内替换内存副本，顺序正确。坏味道：`identity`/`candidate` 的替换序列在 `refresh_configuration`、`switch_mode` 中重复出现，可抽 `install_state_locked()`。
- `extension_stop`（1306-1334）：`revoked` 时先释放 http-debug 进程再还原路由，失败则停掉隧道并记录错误，意图有注释，应保留。`connection_stop` 的返回值被丢弃，与其 fail-open 设计一致，但应加注释。
- `extension_enable`（1348-1380）：`capture` 分支里 `sbw_capture_new` 可能返回 NULL，随后 `sbw_capture_snapshot(c->capture)` 直接使用，对 NULL 的处理未读，不下结论，建议显式判空。回滚逻辑完整（健康检查失败则停止、禁用、必要时回滚到旧版本）。三个错误码字符串和 `BUILTIN_FEATURE` 文案出现两次，应集中定义。
- `capture_upload_begin`/`capture_upload_join`/`capture_uploading`：`begin` 的各失败路径都释放了 `job->bytes`、`job->identity`、`job`，线程创建失败时再 `join` 清理事件，未发现泄漏。风险：`capture_upload_join` 用 `INFINITE` 等待上传线程，而它被 `extension_stop`、`capture.configure`、`enrollment.forget` 在持有 `mutation_lock` 时调用；若 `capture_upload_main` 没有及时响应 `upload_cancel`，服务操作会被无限期阻塞。`capture_upload_main` 未读，需读完后确认，并建议改成有超时的等待。`strcpy_s` 的目标尺寸检查依赖 `digest` 已被 `sbw_capture_digest_valid` 校验（调用方已校验），应在函数内重复断言长度。
- `ensure_statistics`/`collect_traffic`/`persist_traffic`：`collect_traffic` 在 `traffic` 为 NULL 但 `sbw_extension_enabled()` 为真时（capture 开启、statistics 未开启）会继续执行并调用 `sbw_traffic_record(controller->traffic, ...)`，传入 NULL。是否安全取决于该函数对 NULL 的处理，未读，列为待核实。`persist_traffic` 失败时会记录事件，`collect_traffic` 的 30000 毫秒保存间隔、`ensure_statistics` 的一行多语句风格属于魔法数字与 W2 问题。

### 26.3 整改优先级补充

1. 先读 `capture_upload_main` 和 `sbw_traffic_record`，确认 26.2 的两处待核实项，再决定是否属于缺陷。
2. 把取消检查统一为 `cancelled`/`is_cancelled` 公共函数。
3. 为 `capture_upload_join` 的无限等待补一个故障注入测试（上传线程卡住时 `forget` 是否被阻塞）。

### 26.4 对前文的更新

- 25.5 中列出的零散静态函数里，`ready`、`cancelled`、`record_check`、`apply_local_identity`、`extension_stop`、`extension_enable`、`capture_upload_*`、`ensure_statistics`、`collect_traffic`、`persist_traffic` 已读。controller.c 仍未读：`config_summary`、`runtime_status`、`enrollment_status`、`sbw_controller_poll`、`sbw_controller_new/free`、`capture_snapshot`、`extensions_snapshot`、`preferences_export`、`preferences_clear_preview`。

## 27. 补读：capture_upload_main 与 sbw_traffic_record（更正第 26 节两处待核实项）

以下均为阅读结论，未编译、未跑 ASan/TSan，未读 `remote->upload_capture` 的实现。

### 27.1 疑似缺陷：sbw_traffic_record 未对 t 判空（traffic.c:73）

- 函数开头只校验 `pid` 与快照里的 `uploadTotal/downloadTotal`，随后直接执行 `pid != t->pid`，没有检查 `t == NULL`。
- `collect_traffic`（controller.c:513）在 `traffic == NULL` 且 `sbw_extension_enabled()` 为真时不会提前返回（只在两者都不满足时返回），随后调用 `sbw_traffic_record(controller->traffic, ...)`。`ensure_statistics` 只在 statistics 扩展启用时才创建 `traffic`。
- 因此推断：只启用 capture 扩展、未启用 statistics，且核心运行、`/connections` 返回合法计数时，会对 NULL 解引用。这是阅读推断，前提是 `sbw_extension_enabled()` 表示 capture 扩展（controller.c 中 `capture_dispatch` 的用法支持这一点），未实际复现。
- 整改：先写失败测试（只启用 capture、核心运行、采集一次），确认崩溃后在 `sbw_traffic_record` 入口加 `if (!t) return;`，并在 `collect_traffic` 对 `traffic` 和 `capture` 分别判空，不要共用同一个 enabled 条件。
- 同类写法：`sbw_capture_observe(controller->capture, ...)` 的 NULL 容忍已确认（capture.c:`if(!c)return;`），所以只有 traffic 一侧有风险。

### 27.2 capture_upload_main（controller.c:1947-1957，已读全）

- 取消能否及时生效取决于 `upload_capture` 回调是否轮询 `c->upload_cancel`，该回调未读。因此 26.2 对 `capture_upload_join` 使用 INFINITE 的担心仍成立，但无法判定为缺陷；建议改为带超时的等待并补故障注入测试。
- 线程内读取 `c->capture`、`c->remote`，而 `extension_stop` 在 `capture_upload_join` 之后才 `sbw_capture_free(c->capture)`，顺序正确，没有发现使用已释放对象。
- `strcpy_s(c->upload_status, ..., error.message)`：目标大小受检，过长会触发运行时约束处理而不是溢出，但约束处理器行为（中止或忽略）未核实，应改成带截断的复制。
- 所有权：`job->bytes` 先清零再释放，`identity` 与 `job` 也释放，没有发现泄漏。

### 27.3 对前文的更新

- 26.2 中 sbw_traffic_record 的待核实项已解决，结论见 27.1；capture_upload_main 的待核实项部分解决，剩余依赖 `remote->upload_capture`。
- 仍未读：`remote->upload_capture` 实现、`config_summary`、`runtime_status`、`enrollment_status`、`sbw_controller_poll`、`sbw_controller_new/free`、`capture_snapshot`、`extensions_snapshot`、`preferences_export`、`preferences_clear_preview`。

### 27.4 补充核实：27.1 的前提成立

已读 `extensions.c:33`：`sbw_extension_enabled()` 等价于 `sbw_extension_is_enabled("capture")`。因此 `collect_traffic` 里 `if(!controller->traffic&&!sbw_extension_enabled())return true;` 的含义是：traffic 未创建且 capture 也未启用才提前返回。只启用 capture、未启用 statistics 时，`traffic` 为 NULL 但函数继续执行，并把 NULL 传给 `sbw_traffic_record`，而后者没有判空。27.1 的推断在代码层面成立，仍是阅读结论，未实际复现、未用 ASan 验证。该项应列为已读范围内第一个疑似真实缺陷，整改见 27.1：先写失败测试再加判空。另外 `sbw_extension_enabled` 这个函数名没有体现它只表示 capture，建议改名为 `sbw_capture_extension_enabled`，避免再被当成“任意扩展已启用”。

## 28. 补读：config_summary / runtime_status / enrollment_status / preferences_clear_preview（controller.c）

以下均为阅读结论，未编译、未跑 ASan/TSan。未读：`profile()`、`sbw_subscriptions_summary`、`sbw_routing_groups` 的返回契约、`sbj_clone(NULL)`。

- config_summary（166-199，约 34 行）：candidate 为空时手工构造三项计数为 0 的对象，否则调用 config_counts 并在返回 NULL 时写入 JSON null；NULL 路径已处理，未发现空指针问题。sbj_set_str 传 NULL 已核实写入 JSON null。坏味道：校验状态字符串 unavailable、not_checked、valid、invalid 是散落字面量，应集中为枚举加名称表；该函数每次调用都重新计算 routing_groups、subscriptions_summary 并克隆 health_snapshot，而 runtime_status 又调用它，仪表盘轮询时重复计算，是否成为瓶颈未测量。三元表达式嵌套三层（188-189 行）可读性差。
- enrollment_status（146-165）：错误文案 Stored device state is unavailable 与 ready() 中同一句硬编码两处，应共用常量。
- runtime_status（361-382）：组合 enrollment_status、config_summary、management_status，三者都不加锁，全部依赖调用方持有 state_lock（dispatch 中已读到共享锁调用），契约没有文档，应在函数头写明并在结构体字段旁标注归属。connection_available 一行内含五个条件，应拆成命名布尔变量。
- preferences_clear_preview（875-879）：释放并置 NULL、对 preview_id 做 SecureZeroMemory，清理完整，无问题。
- 本节的新增发现不构成缺陷，仅是可读性与重复；第 27 节的 sbw_traffic_record 判空仍是目前已读范围内唯一疑似真实缺陷。

### 对前文的更新

- 第 27 节末尾 config_summary、runtime_status、enrollment_status、preferences_clear_preview 未读已解决。controller.c 仍未读：sbw_controller_poll、sbw_controller_new/free、capture_snapshot、extensions_snapshot、preferences_export、profile。

## 29. 补读：upload_capture（control_plane.c:781-800）

以下均为阅读结论，未编译、未跑 ASan/TSan。未读：send_request、required_field、response_json、server_free 的实现。

- 取消传递：upload_capture 把 cancel 句柄传给 send_request。因此 27.2 中“上传线程可能不响应 upload_cancel”的担心取决于 send_request 是否轮询该句柄，该函数尚未读，结论待定；若它像 fetch_wait 一样轮询，则 capture_upload_join 的 INFINITE 等待风险较低。
- 重复的校验：digest 长度 64 加十六进制小写校验在此手写一遍，与 sbw_capture_digest_valid、cache_path、prune_cache 是第 4 份实现，应统一为 sbw_hex_digest_valid()。
- 魔法数字重复：768U*1024U 与 capture.c 的 FILE_MAX、capture_dispatch 的 768*1024 是同一上限的第 3 份字面量；length < 24 与 capture.c 的文件头大小 24 同源；65536（响应上限）、100（endpoint 缓冲）也是字面量。endpoint 缓冲 100 个 wchar 足够容纳 20 个前缀字符加 64 位摘要，当前不会截断，但依赖上述两个常量，应改为 sizeof 推导。
- endpoint 先用字符串初始化再被 swprintf_s 覆盖，初始化是多余的；wide 在 swprintf_s 之后立即释放，路径上无泄漏。
- required_field 在同一条语句里调用两次，若第一次失败，第二次仍会执行并覆盖 error，应分开判断。
- 确认回执：服务端必须返回 ok 与相同 digest 才算成功，这一设计值得保留。
- 对前文的更新：27.3 中“remote->upload_capture 实现未读”已解决；仍未读 send_request。

## 30. 补读：send_request_extended（control_plane.c:506-581，约 76 行，已读全）

以下均为阅读结论，未编译、未跑 ASan/TSan。未读：`request_init`、`request_prepare`、`request_await`、`header`、`validate_headers`、`request_free` 的实现。

- 取消：`cancel` 经 `request_init` 进入 pending_request，等待由 `request_await` 完成。第 29 节关于 `capture_upload_join` 使用 INFINITE 的担心，取决于 `request_await` 是否轮询该句柄，仍待核实。
- 参数过多（S6）：`send_request_extended` 有 16 个参数，`send_request` 包装有 13 个，`binary`、`panel` 两个布尔参数分别切换 Content-Type 与 Cookie/If-Match 行为，调用点难读。建议改为 `request_options` 结构体。
- 重复校验：token 与 etag 各写一个 `*c <= 32 || *c >= 127` 风格的字符循环，应抽出 `header_value_valid(value, allow_space)`。
- 变量复用：`bytes` 先用于状态码查询的 `DWORD` 大小，再作为读取长度，含义不同，应拆开。
- 潜在空指针（未核实）：`content_length` 在 `header(...)` 之后直接 `*content_length`。若该头不存在时 `header` 不把输出置为空串，就是空解引用；需读 `header` 确认。
- 值得保留：Authorization 头缓冲区用后 SecureZeroMemory；响应体既按 Content-Length 预检又按实际读取累计检查上限；拒绝 3xx 重定向；负载复制进 async 状态以保证回调期间有效。
- 魔法值：`MAX_HEADER`、`127`、`32`、`"application/vnd.tcpdump.pcap"` 字面量。

## 31. 补读：request_init / request_prepare / request_await / header（control_plane.c:337-468，更正第 29、30 节两处待核实项）

以下均为阅读结论，未编译、未跑 ASan/TSan。未读：check_cancel、option、status_callback、reject_duplicate、sbw_decode_legacy_header、request_free 的实现。

- 撤销 29/30 对 capture_upload_join 使用 INFINITE 的担心（降为低优先级）：request_await 用 WaitForMultipleObjects 同时等待完成事件和 cancel 句柄，等待前后各调用一次 check_cancel，并带截止时间。capture_upload_join 先 SetEvent(upload_cancel) 再等线程，而 upload_cancel 正是传给 upload_capture 的 cancel，所以上传线程会很快醒来退出。但其余未经过 request_await 的步骤（例如 mark_uploaded、capture_delete 的本地文件操作）不受此保护，且 INFINITE 仍无超时兜底，建议仍加带超时的等待并写入日志。
- 撤销 30 对 content_length 空指针的担心：header() 开头即 *out = NULL，头不存在（ERROR_WINHTTP_HEADER_NOT_FOUND）时两条路径都返回 sb_strdup("") 并成功，所以 send_request_extended 里 *content_length 是安全的；header 返回失败时调用方都 goto done，不会解引用 NULL。已读路径上未发现空指针问题。
- 引用计数模型与第 15 节一致：request_init 初始 references=1，状态回调注册成功后 InterlockedIncrement，注释写明由 HANDLE_CLOSING 释放。这是第三份同样的 WinHTTP 异步骨架（route_probe、subscriptions、control_plane），抽取共享模块时应以 control_plane 这份为蓝本：它同时处理超时、取消和事件。
- 三份实现的行为差异（抽取时必须逐项保留或统一）：control_plane 用 WINHTTP_ACCESS_TYPE_NO_PROXY，subscriptions 用 AUTOMATIC_PROXY，route_probe 用 NAMED_PROXY；control_plane 与 route_probe 保存 REQUEST_ERROR 的错误码，subscriptions 的 fetch_callback 丢弃错误码（见第 15 节）；control_plane 用 CRITICAL_SECTION 保护状态，另两份用 Interlocked 变量。
- 坏味道：
  - check_cancel 在 request_prepare、request_await 内共出现 3 次，另有 request_init 一次，每次 send 流程约 10 次调用，可在循环入口统一；
  - request_await 的参数 BOOL started + DWORD expected + DWORD *bytes + error 含义靠位置记忆，且 started 为 FALSE 时直接读 GetLastError，调用方必须紧跟在 WinHTTP 调用之后，中间不能插入任何会改写 last error 的调用，需在注释写明；
  - header() 在栈上放 char wire[MAX_HEADER+1] 与 wchar_t legacy[MAX_HEADER+1] 两个缓冲，MAX_HEADER 的值未读，若较大则栈占用显著，需确认；
  - header() 的 legacy 回退分支（ERROR_INVALID_PARAMETER/ERROR_WINHTTP_INVALID_OPTION）是兼容旧系统的路径，没有注释说明哪些系统会走到，也没有测试覆盖，应补注释和测试；
  - request_init 中 sb_xcalloc 的 path 在 WinHttpOpenRequest 之后立即释放，没有泄漏；agent 同理；goto invalid 统一调用 request_free，路径上未发现泄漏；
  - WinHttpSetTimeouts 四个超时设为同一个 timeout，同时又用 deadline 总超时，两层超时语义重叠，应在注释说明谁是主约束。
- 值得保留：整个请求的总截止时间 + 取消 + 响应体上限 + 头部数量/大小上限 + 禁止重定向与自动认证，是三份实现里最完整的一份。

### 对前文的更新

- 29 节“仍未读 send_request”、30 节“request_await 是否轮询 cancel 待核实”“content_length 空指针待核实”均已解决，以本节为准。
- control_plane.c 仍未读：check_cancel、option、status_callback、reject_duplicate、request_free、validate_headers、percent_decode、clean_text 等辅助函数，以及 enroll、fetch_config 两个调用方。

## 32. 补读：check_cancel / status_callback / request_free / reject_duplicate（control_plane.c）

以下均为阅读结论，未编译、未跑 ASan/TSan。未读：`option`、`state_release`、`validate_headers`、`sbw_decode_legacy_header`、`clean_text`、`percent_decode`、`enroll`、`fetch_config`。

- `check_cancel`（259-265）：无句柄返回 0，WAIT_OBJECT_0 返回 cancelled，WAIT_FAILED 返回 network_error，其余返回 0。简洁正确；前文 15.1、15.3、17.1 里内联的取消检查应统一改用它（或 controller.c 的 `cancelled`），并移到公共头文件。
- 引用计数（31 节的模型得到确认）：`request_init` 初始为 1，回调注册成功后再加 1；`request_free` 关闭句柄并释放 1 次；`HANDLE_CLOSING` 通知再释放 1 次。`status_callback` 进入时先加 1、结尾释放 1，用来保证回调执行期间 state 不被另一线程释放。已读路径上未发现重复释放或泄漏。坏味道：`HANDLE_CLOSING` 分支在这对加减之间再释放一次，读起来像过度释放，需要注释说明三次操作的对应关系；这是 route_probe、subscriptions 的同类回调里没有的写法，抽取共享模块时应以这份为准并统一。
- `request_free`（329-333）：先 `WinHttpCloseHandle`，再 `state_release`，最后 `memset(request, 0, ...)`，对重复调用安全。注意 `WinHttpCloseHandle` 会同步触发回调，回调内部再访问 state，所以 state 必须在关闭句柄之后才释放，当前顺序正确，应写成注释。
- `reject_duplicate`（438-443）：用第二个 index 再查一次同名头，若还能查到就判为重复头并拒绝，防止响应头走私式歧义；逻辑反直觉（`||` 左边查到即失败），应加注释。
- 栈占用：`MAX_HEADER` 为 1024，`header()` 里 `char wire[1025]` 加 `wchar_t legacy[1025]` 约 3 KB，可接受。31 节关于栈占用的担心撤销。
- `status_callback` 对 `REQUEST_ERROR` 用 `bytes == sizeof(WINHTTP_ASYNC_RESULT)` 判断 `info` 有效，而 route_probe 用 `length >= sizeof(...)`，两处判断条件不一致，统一时应取 `>=`（更宽松且不会读越界）。

### 对前文的更新

- 31 节末尾 control_plane.c 未读列表中的 `check_cancel`、`status_callback`、`request_free`、`reject_duplicate` 已读完；仍未读 `option`、`state_release`、`validate_headers`、`sbw_decode_legacy_header`、`clean_text`、`percent_decode`、`enroll`、`fetch_config`。
- 目前已读范围内唯一疑似真实缺陷仍是第 27 节的 `sbw_traffic_record` 未判空（推断，未复现）。

## 33. 补读：option / state_release / clean_text（control_plane.c）

以下均为阅读结论，未编译、未跑 ASan/TSan。未读：`validate_headers`、`sbw_decode_legacy_header`、`percent_decode`、`is_control`、`enroll`、`fetch_config`。

- `option`（334-336）：对 `WinHttpSetOption` 的一行封装，把 DWORD 值取地址传入，没有问题。
- `state_release`（286-295）：引用归零才释放，先关闭 connection 与 session 句柄，再关闭事件、清零并释放 payload 与 headers（含认证头，值得保留），最后销毁临界区。已读路径上没有发现遗漏或重复释放。顺序是先关 connection 再关 session，与 WinHTTP 要求的由内到外一致，应写成注释。
- `clean_text`（43-49）：校验空指针、长度上限、控制字符和 UTF-8 合法性，失败统一返回调用方指定的错误码。结构清晰。它与 `sbw_json_string`、`subscription_parser.c` 入口处的“NUL + UTF-8”检查以及 `fetch_run` 的同类检查是第 4 份相近实现，应统一为 `sbw_text_valid(value, length, limit)`。
- 坏味道：`clean_text` 的 `length > INT_MAX` 与 `limit` 同时检查，限制来源不清；`failure(error, code)` 每次只带错误码，没有阶段信息，排查时只能靠错误码字符串推断。

### 对前文的更新

- 第 32 节“仍未读 option、state_release”已解决；`clean_text` 已读。control_plane.c 仍未读：`validate_headers`、`sbw_decode_legacy_header`、`percent_decode`、`is_control`、`enroll`、`fetch_config`。
- 已读范围内唯一疑似真实缺陷仍是第 27 节的 `sbw_traffic_record` 未判空（推断，未复现）。

## 34. 补读：validate_headers / percent_decode / enroll / fetch_config（control_plane.c）

以下均为阅读结论，未编译、未跑 ASan/TSan。未读：`is_control`（grep 未在 static 函数定义中找到，可能是宏）、`sbw_decode_legacy_header`（control_plane.c:413）、`required_field`、`response_json`、`hex`。

- `validate_headers`（470-492）：先取长度再分配，上限检查在分配前，所有权清楚。坏味道：直接把缓冲区里的 CRLF 改写成 NUL 再逐行扫描，原地修改；`MAX_HEADER + 128`、`MAX_HEADER + 1` 是未命名的余量字面量；循环里 `if (!end) break;` 放在长度检查之后，最后一行也会被检查，行为正确但不易看出，应加注释。
- `percent_decode`（62-79）：边界检查 `i + 2 >= length` 对 `%41` 结尾和 `%4` 结尾都正确，已逐例推演，未发现越界。坏味道：`hex()` 与 util.c、proxy_parser.c 的十六进制解码是又一份重复；解码结果在 `clean_text` 失败时释放，路径上没有泄漏。
- `enroll`（691-740）：
  - 所有权：`device` 在创建后立即交给 `request`，之后任何失败都由 `done:` 里的 `sbj_free(request)` 释放；`code`、`payload` 先清零再释放，值得保留。
  - 一致性问题：请求体里写死 `supports_proxy_selection=false`、`supports_local_route_stats=false`、`supports_diagnostic_upload=false`，而 docs/windows-client-design.md 的能力示例写的是 true。这两处不是同一分支的代码，我没有核实服务端是否据此启用功能，只能标为「文档与实现不一致，需确认哪个是准的」。同一组能力字面量也应集中为一个能力表，不要散落在 enroll 里。
  - 重复：token 的 `*c <= 32 || *c >= 127` 校验是第 3 份（send_request_extended 中有 2 份），应抽 `header_value_valid()`。
  - 一行里连续调用 5 次 `required_field` 并共用同一个 error，前一次失败后后一次会覆盖错误信息；`required_field(profile, ...)` 在 `profile` 为 NULL 时的行为未读，不下结论。
  - 把 `strcmp(returned_server.normalized, server.normalized)` 的不一致统一报 `server_mismatch`，值得保留，它防止服务端把设备引到别的源。
- `fetch_config`（742-779）：
  - 先把原始响应体写入 `output.content`，后面若是 `config` + `subscription_sources` 结构又用 `sbj_dump` 重新序列化覆盖，同一份配置在内存里复制两到三份（上限 MAX_CONFIG_BODY），且重新序列化后的字节与服务端的 ETag 对应的字节可能不同。这是否影响「ETag 对应的内容」语义，需要读服务端响应格式后确认，目前只记为疑点。
  - `content` 分支用单行内塞三条语句的写法（771-774），属于 W2。
  - 304 且响应没有 ETag 时回退到请求里的 etag，空则判 invalid_response，逻辑合理，建议加注释。
  - 四次 `required_field` 在检查前全部求值，同样共用 error。
  - `output` 在 `sbj_set_*` 之后才赋给 `*download`，失败路径上没有它的分配，没有泄漏。

### 对前文的更新

- 第 33 节末尾 control_plane.c 未读列表中的 `validate_headers`、`percent_decode`、`enroll`、`fetch_config` 已读完；仍未读 `is_control`、`sbw_decode_legacy_header`、`required_field`、`response_json`、`hex`。
- 已读范围内的疑似真实缺陷仍只有第 27 节的 `sbw_traffic_record` 未判空（推断，未复现）。

## 35. 补读：required_field / response_json / hex / is_control / sbw_decode_legacy_header（control_plane.c）

以下均为阅读结论，未编译、未跑 ASan/TSan。未读：`legacy_fallback`。

- `required_field`（680-687）：先 `sbj_get`，再校验字符串、非空、`clean_text`，失败返回 NULL。`sbj_get` 对 NULL 对象返回 NULL（见第 20 节），所以 34 节担心的 `required_field(profile, ...)` 在 `profile` 为 NULL 时会走失败分支，不会解引用空指针，该疑点撤销。`clean_text` 失败后又调用一次 `failure(error, "invalid_response")`，两次错误码相同，后者覆盖前者没有实际影响；34 节“连续调用 5 次共用同一 error 会被覆盖”的担心也只剩可读性问题，因为所有失败码都是 `invalid_response`。坏味道：返回借用指针，生命周期依赖 `body` 不被释放，应在注释写明。
- `response_json`（675-679）：解析并要求顶层是对象，失败释放并返回 NULL，没有问题。深度 32 是未命名字面量，与 `config_counts`、`management_request` 重复，应共用常量。
- `is_control`（36）：`c < 32 || c == 127`，是 static 函数而非宏，之前的 grep 未匹配到是因为不在 `static` 行首的签名模式里。重复：`sbw_decode_legacy_header` 内联了 `value[i] < 32 || value[i] == 127`，`send_request_extended` 与 `enroll` 的 token 校验写成 `*c <= 32 || *c >= 127`（多排除空格和 127 以上），三种写法语义不完全相同，应分别命名为 `is_control` 与 `header_token_char_valid`，不要合并成一个。
- `hex`（56-61）：又一份十六进制解码，与 `util.c` 的 `hexval`、`proxy_parser.c` 的 `hex_value` 并存，累计至少 4 份。
- `sbw_decode_legacy_header`（413-437，约 25 行）：长度上限先于分配检查；`result` 在每个失败路径都被释放，未发现泄漏；`wire_size > (int)MAX_HEADER` 的强转依赖 `MAX_HEADER` 小于 INT_MAX，当前为 1024 成立。坏味道：`0xfffd` 与 `GetACP()` 分支逻辑密集，没有注释说明哪些系统区域设置会走 legacy 路径，且 `legacy_fallback` 未读，无法判断 advisory 为 true/false 时的差异，应补注释和针对非 UTF-8 代码页的测试。

### 对前文的更新

- 34 节末尾 control_plane.c 未读列表中的 `is_control`、`sbw_decode_legacy_header`、`required_field`、`response_json`、`hex` 已读完；仍未读 `legacy_fallback`。
- 已读范围内疑似真实缺陷仍只有第 27 节的 `sbw_traffic_record` 未判空（推断，未复现）。

## 36. 补读：legacy_fallback（control_plane.c:405-411，已读全）

以下均为阅读结论，未编译、未跑 ASan/TSan。

- 行为：advisory 为 false 时直接返回 invalid_response；advisory 为 true 时先用 GetCPInfo 取代码页信息，失败返回 invalid_response，size * MaxCharSize 超过 MAX_HEADER 返回 response_too_large，其余情况把输出置为空字符串并返回成功。也就是说，对“建议性”响应头（如 X-SB-Easy-Profile-Name），无法按本机代码页解码的值会被静默丢弃成空串，而不是报错。
- 这与 fetch_config 配合是自洽的：profile_name 为空时回退到已保存的名称或 profile_id（见第 34 节），所以不会造成空名称。结论：未发现缺陷。
- 坏味道：函数名 fallback 没有说明它会丢弃值；advisory 的语义（哪些头是建议性的）只在 header() 的调用点用布尔字面量 true/false 表达（X-SB-Easy-Profile-Name 为 true，其余为 false），应改为命名枚举或常量；size * MaxCharSize 是保守上界，应在注释里说明；GetCPInfo 失败与其它失败共用 invalid_response，排查时无法区分，应在日志里记录阶段。
- 该函数缺少针对非 UTF-8 代码页（如 936、1252）的测试，应与 sbw_decode_legacy_header 一起补测。

### 对前文的更新

- 第 35 节“仍未读 legacy_fallback”已解决。control_plane.c 里本文涉及的辅助函数已基本读完。
- 已读范围内疑似真实缺陷仍只有第 27 节的 sbw_traffic_record 未判空（推断，未复现）。

## 37. 补读：sbw_controller_poll / capture_snapshot / extensions_snapshot / preferences_export / profile（controller.c）

以下均为阅读结论，未编译、未跑 ASan/TSan。未读：`sbw_capture_snapshot`、`sbw_extensions_snapshot`、`sbw_traffic_running` 对 NULL 的处理、`sbw_preferences_payload/encrypt`。

- `sbw_controller_poll`（477-481）：用 TryAcquire 抢 mutation_lock，抢不到直接返回，否则调用 observe_core 后解锁。结构清楚，没有问题。它与 `sbw_controller_background_tick` 开头的“抢锁、失败即让路”是同一模式，可抽 `try_enter_mutation()`/`leave_mutation()`。
- `capture_snapshot`（2004-2020）：
  - 所有权：`apps`、`name`、快照句柄在所有出口都释放或移交，未发现泄漏；`CreateToolhelp32Snapshot` 的 `INVALID_HANDLE_VALUE` 已检查。
  - 该函数在做“枚举系统进程列表”的 Win32 细节，与“组装 capture 状态”混在一起，应拆成 `list_running_process_names()`。
  - 魔法数字 `96`（进程名长度上限，与 capture.c 中 `attribution.app[97]` 同源）和 `512`（进程数上限）应命名常量并共用。
  - `sbw_capture_snapshot(c->capture)` 不判空：调用方 `capture_dispatch` 已保证 `c->capture` 非空且 worker 在运行，所以已读路径安全；但函数自身没有写明此前提，应加注释或判空。
  - 枚举过程中超过 512 个进程会被静默截断，没有标记，界面看不出列表不完整。
- `extensions_snapshot`（1335-1347）：
  - `sbw_traffic_running(c->traffic)` 与 `c->traffic && !sbw_traffic_running(c->traffic)` 在 traffic 为 NULL 时的行为未读，需确认该函数对 NULL 返回 false（`sbw_extension_process_running(c->httpdebug)` 同理）。
  - 对 http-debug 的特殊处理写在通用循环里，按 id 字符串比较；新增扩展需要改此处，应并入第 25.3 节提出的“扩展描述结构数组”。
  - `running`/`failed` 这组状态在 capture、statistics、http-debug 三处各用不同表达（参数、函数、内联），不统一。
- `preferences_export`（880-884）：先检查 identity，再生成 payload，再加密，payload 无论成败都释放；结构正确。口令只作为参数传递，没有在此处留副本；加密函数是否对口令做清零未读。
- `profile`（139-145）：source 为 NULL 返回 JSON null，否则只取 id 与 name；没有问题。注意它对 NULL 返回 null 而 `config_summary` 的 counts 等其他字段对 NULL 返回零值对象，同一文件内“缺失”的表示方式不一致，应在 API 文档写明界面如何处理。

### 对前文的更新

- 第 28 节末尾列出的 `sbw_controller_poll`、`capture_snapshot`、`extensions_snapshot`、`preferences_export`、`profile` 已读完。controller.c 仍未读：`sbw_controller_new/free`、`sbw_controller_*` 的其余公开函数、`httpdebug` 相关的 `health_io`/`health_proxies`/`health_probe`/`health_select`、`sbw_is_mutating_method`、以及 1216-1276、1306 附近之外的零散函数。
- 已读范围内疑似真实缺陷仍只有第 27 节的 `sbw_traffic_record` 未判空（推断，未复现）。

## 38. 补读：sbw_controller_new / sbw_controller_free / health_proxies / health_probe / health_select（controller.c）

以下均为阅读结论，未编译、未跑 ASan/TSan。未读：`sbw_is_mutating_method` 的函数体（controller.c:343）、`identity_valid`、`saved_config_valid`、`archive_valid`。

### 38.1 sbw_controller_new（243-291，约 49 行，已读全）

- 加载存储失败（260 行）或没有保存状态（261 行）时直接返回半初始化的 controller，只靠 `startup_error` 标记失败，调用方必须检查，否则会在不可用状态下继续使用；该契约没有注释。`ready()` 正是为此存在，但新建函数的头部应写明。
- 校验失败时走 `STORAGE_CORRUPT`，原状态保持不动，与 `ready()` 的文案一致（见第 28 节，同一句话硬编码了三处，应共用常量）。
- 魔法数字重复：`128`（回执上限，与 `save_receipt` 的 128/127 同源）、`15`/`3600`/`30`（同步间隔，与 `management_settings_change` 和 `default_management_settings` 重复，共 3 处加文案 1 处），布尔键名数组与 `management_settings_change` 里的 `sb_streq` 链是同一份清单，应共用一个静态键表。
- 校验用一长串 `&&` 连接（263-268），含义是“版本为 1 且各部分合法”，应拆成 `saved_state_valid()`。
- 所有权：成功路径末尾 `sbj_free(saved)`；各 clone 都复制而不是转移，没有发现泄漏。两个早退路径不释放 `saved`，前提是 `load` 失败或返回 NULL 时 `saved` 为 NULL，`store->load` 的契约未读，需确认。

### 38.2 sbw_controller_free（292-323，已读全）

- 顺序合理：先取消网络监听、停止并 join 管理线程与监控线程，再释放状态，最后 `persist_traffic` 后才释放 `traffic` 与 `core`，保证落盘使用的对象仍有效。`httpdebug` 在核心停止前释放，与 `extension_stop` 的“先撤销执行再恢复路由”思路一致。
- 风险：`WaitForSingleObject(..., INFINITE)` 有两处（管理线程、监控线程），若线程卡在不响应取消的阻塞调用里，服务停止会被无限期挂起。结合第 31 节，网络调用本身会响应取消，但本地文件操作不一定，建议改为带超时的等待并记录日志，超时后走 fail-open 清理。
- `sbw_store_join()` 在释放控制器中间调用，是全局状态（见 9.5 的 `extension_store.c` 全局变量）而不是控制器成员，生命周期归属不清晰，应写注释。
- 注释写明“所有 IPC 工作线程由调用方先 join”，这是一个关键前置条件，应在 `sbw_controller_free` 头文件声明处也写一遍，并补“释放时仍有请求在途”的故障注入测试。

### 38.3 health_proxies / health_probe / health_select（1063-1076）

- 三个薄封装，把 `health_io` 里的 pid、取消句柄和 `active_config` 传给运行时接口，没有问题。`health_probe` 仅在 `rc == 0` 时写 `*delay`，失败时调用方的 `delay` 保持未写入，是否在使用前初始化取决于 `sbw_health_step`（未读）。
- 坏味道：`health_io` 持有 `controller` 指针并在无 `state_lock` 下读取 `active_config`，依赖调用方持 `mutation_lock`（`health_tick` 唯一调用点已持有，见 19.1），契约无文档。

### 对前文的更新

- 第 37 节“controller.c 仍未读：`sbw_controller_new/free`、`health_io` 相关回调”已解决。controller.c 仍未读：`sbw_is_mutating_method` 函数体、`identity_valid`、`saved_config_valid`、`archive_valid`、`sbw_controller_start/stop` 等其余公开函数。
- 已读范围内疑似真实缺陷仍只有第 27 节的 `sbw_traffic_record` 未判空（推断，未复现）。

## 39. 补读：sbw_is_mutating_method / identity_valid / saved_config_valid / archive_valid（controller.c）

以下均为阅读结论，未编译、未跑 ASan/TSan。未读：sbw_identity_is_independent 对 NULL 的处理。

- sbw_is_mutating_method（343-351）：把约 40 个方法名用一条 `||` 链串在一个 return 里，前缀匹配（`updates.`、`preferences.`）与全名匹配混用，前缀长度 8、12 为手写字面量。这份清单与 sbw_controller_dispatch 里的前置规则（UPDATE_BUSY 白名单、对象参数例外、extensions.、capture.、httpdebug. 等分支）是同一份知识的另一副本，改一处要同步改另一处。这是 W1 方法表的直接证据：应把 flags（是否变更、是否需要授权、是否允许在更新期间调用）放进同一张表，由 pipe_server.c:81 与 dispatch 共用，并加一条测试：表里每个方法都有 handler，且 handler 不在表外。
- 值得核对而未核实：capture.configure、capture.rotate、capture.delete、capture.upload 在 dispatch 里持有 mutation_lock 执行，但未出现在该清单中；capture.* 是否有意不算变更（pipe_server 据此决定是否校验客户端会话）需要确认，不下结论。
- identity_valid（121-138）：required[] 与 optional[] 两个数组按同一下标配对校验，读起来像一对一关系，实际是两个无关字段，应拆成两个循环；server 前缀检查 `https://`(8)、`http://`(7) 手写长度；4096 重复出现。独立模式分支要求 server、host_id、agent_token 都是空串，含义没有注释。
- saved_config_valid（227-236）：`i >= 2` 表示后两个键允许空串，靠下标隐含语义，应写成带 allow_empty 的结构数组；它对 config_counts 的调用会解析并丢弃整份配置（最大 8 MiB）只为判断合法，启动时对 candidate、last_good、两份 archive 各解析一次，最多 6 次，是否影响启动时间未测量。
- archive_valid（237-242）：identity_valid(sbj_get(archive, identity)) 在 identity 缺失时传入 NULL，非独立分支靠 sbj_is_object(NULL) 返回 false 兜底，安全；独立分支依赖 sbw_identity_is_independent(NULL) 的行为，未读。

### 对前文的更新
- 第 38 节“未读 sbw_is_mutating_method、identity_valid、saved_config_valid、archive_valid”已解决。controller.c 仍未读：controller 的 start/stop 等其余公开函数（约 300-343 行与 monitor_main）、sbw_identity_is_independent。
- 已读范围内疑似真实缺陷仍只有第 27 节的 sbw_traffic_record 未判空（推断，未复现）。

## 40. 补读：sbw_identity_is_independent / sbw_controller_set_core / sbw_controller_set_updater（controller.c、independent.c）

以下均为阅读结论，未编译、未跑 ASan/TSan。未读：monitor_main、sbw_core_free 对并发使用的处理。

- sbw_identity_is_independent（independent.c:8-10）：先 sbj_is_object(identity) 再比较 mode，对 NULL 安全。因此第 39 节中 archive_valid 独立分支依赖它处理 NULL 的担心撤销，已核实安全。
- sbw_controller_set_core（约 321-338 行）：先 sbw_core_free(旧 core) 再赋新值，而 monitor 线程可能仍在使用 controller->core。若 set_core 在监控线程运行期间被再次调用（旧 core 非空、monitor 已存在），存在释放后使用的风险。目前读到的调用点只在启动阶段，未读 service_main.c 的调用位置，因此只能说隐患，未证明缺陷。整改：在函数头注释写明只能在启动阶段调用一次，或先停 monitor 再替换。
- 同一函数在 monitor 创建失败时释放 core 并置 NULL、记录 INITIALIZATION_FAILED，清理完整；但 checked_etag 的重置与 enrollment、refresh_configuration、switch_mode 是同一组重复序列的又一份（累计 5 份），应合并为 reset_candidate_state_locked()。
- sbw_controller_set_updater：释放旧 updater 后赋新值，无锁，同样依赖只在启动阶段调用。

### 对前文的更新
- 第 39 节末尾 sbw_identity_is_independent 未读已解决。controller.c 仍未读：monitor_main。
- 已读范围内疑似真实缺陷仍只有第 27 节的 sbw_traffic_record 未判空（推断，未复现）。

## 41. 补读：monitor_main 与 service_main.c 的启动顺序（收窄第 40 节）

以下均为阅读结论，未编译、未跑 ASan/TSan。未读：`sbw_updater_installing(NULL)` 的行为、`capture_auto_upload`、`sbw_controller_start_background`。

- `sbw_controller_set_core` 在整个 service_main.c 中只有一个调用点（service_main.c:74），发生在 `sbw_controller_new` 之后、`sbw_controller_start_background` 与管道服务启动之前。监控线程正是由 set_core 内部创建（controller.c:331，条件 `core && !controller->monitor`），所以首次调用时不存在旧监控线程。第 40 节“替换 core 时监控线程可能仍在使用旧 core”在当前调用方式下不会发生，降为纯隐患：它只在将来有人第二次调用 set_core 时成立，应在函数头注释写明“仅限启动阶段调用一次”。
- 新发现的竞争隐患：监控线程在 set_core（service_main.c:74）内部就已启动，而 `sbw_controller_set_updater` 在其后（service_main.c:76）才调用。`monitor_main` 每 2 秒循环一次，持有 `mutation_lock` 后无 `state_lock` 地读取 `controller->updater`（`sbw_updater_installing(controller->updater)`），而 `set_updater` 在不持任何锁的情况下写同一指针并释放旧值。监控线程先等待 2000 毫秒才第一次循环，所以实际窗口很小，但这是对 `updater` 指针的无同步读写，且启动初期 `updater` 为 NULL；`sbw_updater_installing(NULL)` 的行为未读，不下结论。整改：把 `sbw_controller_set_updater` 移到 `sbw_controller_set_core` 之前，或让监控线程改由 `sbw_controller_start_background` 启动；并在 `set_updater` 内持 `mutation_lock`。这是目前阅读范围内第二个值得先用 TSan 复现的疑点（第一个是第 27 节的 `sbw_traffic_record` 未判空）。
- `service_main.c` 的 `run()`：`sbw_controller_new` 失败时 `return` 前没有释放 `store`、`remote`（它们已被 `sbw_controller_new` 在 `!remote || !store` 分支内释放，但仅限那条分支；控制器创建成功后失败则不会走到这里），当前路径无泄漏，但所有权转移到 controller 的约定没有注释。`core_error` 与 `updater_error` 创建后不检查，core 为 NULL 时仍会注册给 controller，由 `core_error` 记录原因，行为合理但应加注释。
- `monitor_main` 的取消检查 `controller->cancel && WaitForSingleObject(controller->cancel, 0) == WAIT_OBJECT_0` 是第 5 次出现的同类内联检查，应改用共享的 `cancelled()` 或公共 `is_cancelled(HANDLE)`。2000、`sbw_core_options` 里的 8000 与 5000、`sbw_winhttp_new(25000, ...)` 都是未命名字面量。
- `monitor_main` 每 2 秒做 `observe_core(true)`、`collect_traffic`、`capture_auto_upload`，全部在 `mutation_lock` 内；`collect_traffic` 会请求 Clash API，期间用户操作会得到 BUSY。这与第 23 节 `dashboard_snapshot` 的问题同源，应一并改为“锁内只复制状态，锁外请求”。

### 对前文的更新
- 第 40 节“controller.c 仍未读：monitor_main”已解决。controller.c 里已无大块未读函数；仍未读 `capture_auto_upload`、`sbw_controller_start_background`、`sbw_updater_installing`。

## 42. 补读：sbw_updater_installing / capture_auto_upload / sbw_controller_start_background（controller.c、updater.c）

以下均为阅读结论，未编译、未跑 ASan/TSan。未读：`management_main`、`interface_changed`、`sbw_kill_switch_startup_action`、`sbw_capture_rotate` 的返回契约。

### 42.1 更正第 41 节的 updater 担心

- `sbw_updater_installing`（updater.c:272-277）对 NULL 返回 false，其余情况在 updater 自己的互斥里读取 phase，所以 `monitor_main` 在 `set_updater` 之前读到 NULL 是安全的，41 节里 `sbw_updater_installing(NULL)` 的未读项已核实。
- 剩下的只是对 `controller->updater` 指针本身的无锁读写：`set_updater` 先释放旧值再赋新值；启动时旧值为 NULL，释放 NULL 无副作用，监控线程第一次循环要等 2000 毫秒。结论：当前启动顺序下窗口极小，属隐患而不是缺陷；41 节里把它列为第二个需 TSan 复现的疑点，降级为低优先级。整改仍是把 `set_updater` 移到 `set_core` 之前，或让监控线程改由 `start_background` 启动。

### 42.2 capture_auto_upload（1984-2003，约 20 行，已读全）

- 所有权无问题：两次 `sbw_capture_snapshot` 都在使用完 `config`/`files` 之后才 `sbj_free`，`config` 指针用完才释放；`c->capture` 已先判空。
- 坏味道：`sbw_capture_rotate(c->capture, NULL)` 的返回值被丢弃，轮转失败时仍继续上传旧文件，且无日志；`60`（默认上传间隔秒）和 `* 1000` 是字面量，与 capture.c 配置校验里的 `upload_seconds` 默认值是两份；`strcpy_s(c->upload_status, ..., error.message)` 与 27.2 同类，应改成带截断的复制；每个周期最多只启动一个文件的上传（找到第一个未上传的文件就 break），这是有意的节流，但没有注释。
- 在 `monitor_main` 持有 `mutation_lock` 时调用，内部又会执行 `capture_upload_begin`（读文件、创建线程），持锁时间偏长，与 41 节同类。

### 42.3 sbw_controller_start_background（1239-1275，约 37 行，已读全）

- 缩进错误：1241 行 `if (!sbw_updater_installing(...)) {` 内的整块（1242-1260）没有缩进，闭合括号在 1261 行，读起来像顶层语句，很容易在合并或修改时放错括号；应先格式化（W2）。
- 一个函数混合了：更新中跳过、kill switch 的三种启动期调和（管理员恢复、保留未知、按配置应用）、创建事件与线程、注册网络变更通知。应拆成 `reconcile_kill_switch_at_startup()` 与 `start_management_worker()`。
- 返回值被丢弃：`(void)NotifyIpInterfaceChange(...)` 失败时没有任何记录，网络切换将不再触发重连，却没有任何错误提示；至少应记一条日志，并在 `runtime_error` 之外的位置标注“网络变化通知不可用”。
- 先 `CREATE_SUSPENDED` 创建线程，注册通知后再 `ResumeThread`，并在恢复前设置 `management_running = true`，顺序合理，应写成注释，说明为什么挂起启动（避免通知回调先于线程就绪）。
- 长错误字符串 `KILL_SWITCH_RECOVERY_REQUIRED` 直接写在函数体内，应集中到错误表；`restored` 的含义是“失败码”（非 0 表示失败），命名反直觉，与 25.2 的 `valid` 同类，应改名。
- 失败路径：线程创建失败时关闭两个事件并置 NULL，返回 `INITIALIZATION_FAILED`，调用方 `service_main.c:run` 随后调用 `sbw_controller_free`，其中对 NULL 事件有判断，没有发现泄漏。

### 对前文的更新

- 第 41 节末尾“仍未读 capture_auto_upload、sbw_controller_start_background、sbw_updater_installing”已解决。controller.c 里大块函数已基本读完；未读的只剩 `management_main`、`interface_changed`、`sbw_capture_rotate`、`sbw_kill_switch_*` 这类被调函数。
- 已读范围内最值得先用 TSan/测试复现的两处仍是：第 27 节的 `sbw_traffic_record(NULL, ...)` 判空，以及第 41 节的 `set_updater` 指针无同步读写（后者已降为低优先级）。

## 43. 补读：management_main / interface_changed / sbw_kill_switch_startup_action

以下均为阅读结论，未编译、未跑 ASan/TSan。未读：`sbw_capture_rotate`（上一次 awk 未匹配到定义）、`sbw_controller_network_changed`。

- `management_main`（controller.c:1217-1225）：每 500 毫秒调用一次 `sbw_controller_background_tick`，退出时在 `state_lock` 内清 `management_running`。结构清楚。`500` 与 `monitor_main` 的 `2000` 都是未命名字面量；取消检查改用了 `cancelled(controller, NULL)`，与 `monitor_main` 的内联写法不一致，印证第 41 节应统一为 `cancelled()`。后台 tick 内部又用 TryAcquire 抢锁，所以 500 毫秒间隔下大部分周期会因用户操作或 monitor 线程持锁而空转，属于正常设计，但应在注释里说明。
- `interface_changed`（1229-1238）：只对 `HardwareInterface` 触发 `sbw_controller_network_changed`，并用注释说明忽略核心自己的虚拟网卡以避免打开 TUN 递归触发重连，意图清楚，应原样保留。`GetIfEntry2` 的失败被静默忽略，即读不到网卡信息时不触发重连，倾向于不动作，与 fail-open 设计一致，但没有日志。`(void)type` 表示忽略通知类型，删除/参数变化/初始通知都会触发，依赖后续的防抖（`network_due_ms = now + 2000`），应在注释写明。回调在系统线程里运行，`sbw_controller_network_changed` 若涉及锁则需确认，未读。
- `sbw_kill_switch_startup_action`（kill_switch.c:5-10）：对 `preference` 非布尔且已有过滤规则返回 PRESERVE_UNKNOWN，非布尔且无规则返回 UNCHANGED，真则 ENABLE，假且已有规则则 DISABLE，否则 UNCHANGED。这是一张四行真值表，逻辑正确、对 NULL 安全（`sbj_get_int(NULL, ...)` 返回回退值，`sbj_is_bool(NULL)` 返回 false）。它很适合做表驱动单元测试，建议补齐 2x3 组合的用例；`start_background`（第 42 节）里对它调用了两次，可改成取一次结果存局部变量再分支。

### 对前文的更新

- 第 42 节末尾未读列表中的 `management_main`、`interface_changed`、`sbw_kill_switch_startup_action` 已读完；仍未读 `sbw_capture_rotate`、`sbw_controller_network_changed`。
- 已读范围内最值得先复现的仍是第 27 节 `sbw_traffic_record(NULL, ...)` 未判空（推断，未复现）。

## 44. 补读：sbw_controller_network_changed / sbw_capture_rotate / seal

以下均为阅读结论，未编译、未跑 ASan/TSan。未读：`seal_path`、`inventory`。

- `sbw_controller_network_changed`（controller.c:1226-1228）：仅对 `network_generation` 做 `InterlockedIncrement`，无锁、无阻塞，适合在系统回调线程里调用；`background_tick` 通过比较 generation 并加 2000 毫秒防抖来消费它。设计正确，第 43 节对回调线程加锁的担心撤销。
- `sbw_capture_rotate`（capture.c:394）：一行内加锁、调用 `seal`、解锁，结果原样返回，没有问题。
- `seal`（capture.c:193-199）：先 flush 再关闭句柄，失败时返回固定文案；`part` 在所有路径释放。坏味道：
  - 末尾 `sbj *files=inventory(c);sbj_free(files);` 构造整份清单后立即丢弃，只为了刷新 `file_count`/`stored_bytes` 等副作用（见 capture.c:173-183），意图没有注释，函数名也看不出来，应拆成 `refresh_storage_counters()`。
  - `rotate_seconds` 默认值 60 与 `*1000` 在 capture.c 的 203、283 行重复，`sbw_capture_rotate` 失败时 `capture_auto_upload` 丢弃返回值（见第 42 节）。
  - 283、306 行用 `strcpy_s(c->issue, ..., error.message)` 记录问题，与 27.2 同类，应改为带截断的复制。
  - `seal(c, NULL)`（319 行）传空错误指针是安全的（`sbw_fail` 已核实容忍 NULL）。

### 对前文的更新

- 第 43 节未读的 `sbw_capture_rotate`、`sbw_controller_network_changed` 已读完。controller.c 与 control_plane.c 中本文涉及的函数已基本读完；未读的是被调用的 `seal_path`、`inventory`、`sbw_core_*`、`sbw_runtime_*` 等。
- 已读范围内最值得先复现的仍是第 27 节 `sbw_traffic_record(NULL, ...)` 未判空（推断，未复现）。

## 45. 补读：inventory / seal_path 后半段（capture.c:160-192）

以下均为阅读结论，未编译、未跑 ASan/TSan。未读：seal_path 前半段（capture.c:160 行之前）。

- inventory（173-192）：
  - 副作用：函数名像只读清单，实际会重置并重算 c->file_count、c->stored_bytes。seal 调用它却丢弃返回值（第 44 节），应拆成 refresh_storage_counters() 与 list_captures()。
  - 截断：行内 size 写入 item.nFileSizeLow（32 位），而 stored_bytes 用了高低位合并。当前文件上限 768 KiB，所以不会截断，但两处口径不一致，上限改动后会静默出错，应统一用 64 位。
  - 魔法数字：len==69（64 位摘要加 .pcap 共 5 个字符）、len>5、1000、116444736000000000、/10000 手写时间换算，capture.c 的 timestamp_us 里又有一份同样的 FILETIME 换算（单位不同），应抽 filetime_to_unix_ms/us。
  - 摘要从 wchar_t 强转 char 后再用 sbw_capture_digest_valid 校验，非 ASCII 文件名会被拒绝，安全，但应写注释说明依赖该校验。
  - 搜索句柄 FindClose 配对正确；INVALID_HANDLE_VALUE 提前返回时 files 已分配并返回，没有泄漏。
  - 每个 pcap 文件调用一次 GetFileAttributesW 检查 .uploaded 标记，最多 1000 次，每次 seal 都会触发，规模可接受，未测量。
- seal_path 后半段（160-171）：先 MoveFileExW，ERROR_ALREADY_EXISTS 时删除 part 文件，视为成功（内容寻址，同摘要即同内容），逻辑自洽，应加注释。其它错误用 sprintf_s 带 Windows 错误码生成消息，缓冲区受检。注意 MoveFileExW 没有带 MOVEFILE_REPLACE_EXISTING，所以才依赖 ALREADY_EXISTS 分支。
- 结论：本节未发现缺陷，仅有可读性与重复问题。已读范围内最值得先复现的仍是第 27 节 sbw_traffic_record(NULL, ...)。

## 46. 补读：seal_path 前半段与 sbw_capture_validate 校验段（capture.c:100-171）

以下均为阅读结论，未编译、未跑 ASan/TSan。未读：sbw_capture_validate 的 lists 循环开头（约 100-120 行）、compile() 之外的 BPF 细节。

### 46.1 seal_path（约 148-171，已读全）

- 流程：read_path 整读（read_path 已保证长度在 24 到 FILE_MAX 之间）、校验 24 字节 PCAP 头、逐条记录扫描、截断尾部不完整记录、对有效字节算摘要、MoveFileExW 改名。记录校验包含：长度非 0 且不超过 65535、incl_len 等于 orig_len、微秒字段小于 1000000、长度不越界。循环条件 size-valid>=16 与 n>size-valid-16 在无符号运算下是安全的，因为 valid 始终不超过 size。已读路径上没有发现越界读或泄漏：bytes 在头不匹配、无有效记录、截断失败、哈希之后都被释放。
- 值得保留：损坏的未完成文件会被截断到最后一条完整记录再封存，而不是整体丢弃；截断先 FlushFileBuffers 再算摘要，摘要对应的是截断后的内容。
- 坏味道：
  - 记录校验是一行内的七个条件（while 行），含 65535、1000000、16、24 等字面量，应拆成 pcap_record_valid()，并为每个条件补一个用例（长度 0、65536、incl 不等于 orig、微秒越界、尾部不足 16 字节）。
  - pcap_header 是 24 字节硬编码数组（魔数 0xa1b2c3d4 小端、版本 2.4、snaplen 65535、链路类型 101），没有注释；应注明链路类型 101 即 LINKTYPE_RAW，并与写文件头的位置共用同一份常量。
  - 无有效记录时 DeleteFileW 并返回 0，调用方无从得知文件被丢弃，也没有日志。
  - put32 与 get32 是手写小端序，项目里其他地方（Winsock、BCrypt）没有同类需求，保留即可，但应补往返测试。

### 46.2 sbw_capture_validate 整数与布尔校验段

- 值得保留：整数字段用 integers/low/high/defaults 四个并行数组驱动，范围与默认值集中在一处，比其他文件里散落的比较更好；这是应当推广的写法。
- 坏味道：
  - 四个并行数组靠下标对应，应合并为一个结构数组 {name, low, high, default}。
  - 布尔默认值靠 i==2 表示 wifi_only 默认为真，下标隐含语义，应写成带 default 的结构数组。
  - file_kb 上限 768 与 FILE_MAX 768U*1024U、capture_dispatch 的 768*1024、upload_capture 的 768U*1024U 是同一上限的第 4 份字面量；rotate_seconds、upload_seconds 默认 60 与 capture_auto_upload 的 60、seal 里的 60 重复。
  - 约 7 处 {sbj_free(out);goto invalid;} 重复，应改为单一清理标签。
  - BPF 编译失败返回 NULL 且保留 INVALID_BPF 的具体信息，而其余失败统一为 INVALID_CAPTURE_CONFIG，两种错误风格并存，应写注释说明是有意的。
- 已读路径上 out 在所有失败分支都被释放，未发现泄漏；goto invalid 在 out 创建之前跳转时，invalid 标签不使用 out，安全。

### 对前文的更新

- 第 45 节末尾的 seal_path 前半段未读已解决。
- 已读范围内最值得先复现的仍是第 27 节的 sbw_traffic_record(NULL, ...) 未判空（推断，未复现）。

## 47. 补读：capture.c 列表校验段、capture_proxy.c、capture_broker.c

以下均为阅读结论，未编译、未跑 ASan/TSan。未读：windows/CMakeLists.txt 中 capture.c 与 capture_proxy.c 的实际编译归属、sbw_extension_process_duplicate、sbw_secure_store_new。

### 47.1 sbw_capture_validate 列表段（capture.c:107-121）

- 过滤项总数上限 100、apps 长度 96、domains/hosts 长度 253 为字面量；apps 与 capture.c 的 attribution.app[97] 同源，domains 与 host_valid 的 253 同源，应命名常量共用。
- 失败分支重复写 sbj_free(normalized);sbj_free(out);goto invalid 共 3 处，应收进单一清理标签。
- 手写转小写 *p+32，与 util.c 的 sb_lower_dup 重复；去掉末尾点号只对 domains/hosts 生效，靠 i>0 隐含，应写注释。
- 已读路径上 normalized、out 在所有失败出口都被释放，未发现泄漏。

### 47.2 capture_proxy.c（宿主侧代理，约 60 行）

- 与 capture.c 同时定义了 struct sbw_capture、sbw_capture_new、sbw_capture_digest_valid、sbw_capture_observe 等同名符号。两个文件只能有一个进入同一可执行文件，我没有读 windows/CMakeLists.txt 确认归属（可能 capture.c 属于隔离的 worker 进程，capture_proxy.c 属于服务进程）。若确实如此，应改名或拆目录并在文件头注明，否则极易误链。
- sbw_capture_new：process 创建或 init 失败时仍返回非 NULL 的 c，错误只写入 error 后被调用方忽略（controller 只判 c==NULL），由后续 sbw_capture_worker_running 兜底报 EXTENSION_FAILED。行为安全，但返回契约不清，应注明。work 参数被 (void) 丢弃，是死参数。
- 对 c 为 NULL 的路径：call() 把 NULL process 交给 sbw_extension_process_call，已确认其返回 EXTENSION_MISSING，所以 configure、snapshot 中随后对 c 的解引用都在 result 成功之后，已读路径上安全。
- sbw_capture_observe 单函数含 broker 创建、句柄复制、通知 worker、构造参数，多条语句挤在一行，是 W2 最严重样本之一。每次调用还克隆整份 connections 发给 worker，每 2 秒一次，开销未测量。
- 疑似句柄泄漏（推断，未复现）：sbw_extension_process_duplicate 把驱动句柄复制进子进程，之后 call(c,broker) 失败时只 sbw_capture_broker_stop，父进程无法关闭已复制进子进程的那份句柄，子进程会一直持有到退出。需读 duplicate 实现后确认，并考虑失败时让子进程重启。
- strcpy_s 写 issue 同 27.2，应截断复制。
- sbw_capture_read 的十六进制解码用 strchr 逐位查表，为第 5 份十六进制解码；上限 1572864 是 2*768KiB 的字面量，应由同一常量推导。sbw_capture_digest_valid 在此是第 5 份摘要校验。

### 47.3 capture_broker.c（特权驱动代理，约 60 行）

- 值得保留：只加载固定哈希的 WinDivert.dll 与 WinDivert64.sys，先复制到宿主专属目录再校验、保持句柄打开防替换，再 LoadLibraryEx 限定目录；打开句柄使用 SNIFF|RECV_ONLY 标志并有注释，由驱动强制只读。这是整个项目里最稳健的特权边界之一，重构时必须完整保留并补测试：哈希不匹配、目标文件被替换、源文件缺失。
- sbw_capture_broker_vendor 是第 3 份 BCrypt SHA-256 十六进制实现（capture.c、plugin_storage.c、此处），read_vendor 是第 4 份重解析点与目录检查；4MiB 上限写了两种形式。应并入第 9.2 节建议的 sbw_sha256_hex 与 sbw_open_regular_file。
- 魔法数字：WinDivert 参数号 0、2、关闭方式 3、队列 1024 与 8MiB、标志 0x0005 均为裸数字。因为本文件为避免依赖 windivert.h 而自行声明函数指针类型，才没有用到头文件里的宏；应在此文件内用 enum 命名并写明对应的 WINDIVERT_PARAM_* 与 FLAG 值。
- b->param 三次返回值被忽略，队列参数设置失败时静默使用默认值。
- sbw_capture_broker_new 失败统一报 CAPTURE_DRIVER_TRUST，会覆盖 sbw_secure_store_new 已写入的更具体错误；目录创建失败与哈希不匹配无法区分，应在日志记录阶段（不含路径）。
- 已读路径上 directory、dll、bytes、source、dest 均释放，未发现泄漏；stage_vendor 在 goto done 之后才声明 HANDLE f，C 中合法但脆弱，建议提到函数顶部。

### 对前文的更新

- 第 46 节未读的 sbw_capture_validate 列表循环、第 45 节以前没有读的 capture_proxy.c、capture_broker.c 已读完。
- 已读范围内最值得先复现的仍是第 27 节 sbw_traffic_record(NULL,...) 与本节 47.2 的子进程句柄泄漏（均为推断，需 ASan/测试确认）。

## 48. 更正第 47 节：capture.c 与 capture_proxy.c 的归属

以下均为阅读结论，未编译、未跑 ASan/TSan。

- windows/CMakeLists.txt:112 把 service/capture.c 与 secure_store.c 编成 sb_windows_capture_impl（隔离 worker 一侧）；:168 把 capture_proxy.c、capture_broker.c 编进 sb_windows_controller（服务一侧）。两个目标分属不同可执行文件，同名符号（struct sbw_capture、sbw_capture_new、sbw_capture_digest_valid 等）不会在同一链接单元内冲突，47.2 的冲突担心撤销。
- 残留坏味道：同名同签名的两套实现靠构建目标隔离，改一处容易漏另一处；digest 校验在两边各一份。建议把共享的 digest/hex 校验移到单独头文件，并在两个文件头注明所属进程。
- 47.2 的子进程句柄泄漏疑点仍待核实，见 sbw_extension_process_duplicate。

## 49. 补读：extension_process.c 开头（句柄复制与进程关闭，收窄 47.2）

以下均为阅读结论，未编译、未跑 ASan/TSan。未读：sbw_extension_process_new、sbw_extension_process_free、worker 侧对 broker 句柄的处理。

- sbw_extension_process_duplicate（extension_process.c:17）：仅在 worker 进程仍在运行时才 DuplicateHandle，权限用 DUPLICATE_SAME_ACCESS，不继承，返回的是子进程句柄表里的数值。父进程拿不到这个句柄的本地副本，所以无法在失败路径上单独关闭它。
- close_worker（8-14）：先关 job，再在进程仍运行时 TerminateProcess，等待最多 3000 毫秒后 CloseHandle，之后关闭管道和可执行文件句柄，释放 sandbox。进程退出后系统会回收其句柄表，所以子进程里复制的驱动句柄最迟在 worker 被释放或终止时关闭。
- 对 47.2 的结论：疑点不是泄漏，而是持有时间。capture_proxy.c 在 call(c, broker) 失败时只关闭父进程的驱动句柄，子进程里的副本在 worker 存活期间继续保持驱动打开，直到 worker 收到 stop 或被释放。是否会在这段时间内继续嗅探，取决于 worker 在 broker 调用失败时是否主动关闭该句柄，该逻辑未读，不下结论。建议：失败路径上显式对 worker 发 stop，并在注释里写明句柄所有权转移给 worker；补一个 broker 调用失败后驱动句柄被释放的故障注入测试。
- 坏味道：
  - sbw_extension_process_running 一行内同时判断 NULL、process、failed、等待状态；duplicate 一行内是 running 检查加 DuplicateHandle，W2 风格。
  - 3000 毫秒是未命名字面量，与 sbw_extension_process_call 里的 20000/3000 同类。
  - close_worker 在持有 lock 的上下文是否被调用未读；sbw_extension_process_running 无锁读取 c->failed 与 c->process，而 call 在持锁时写 c->failed，存在数据竞争隐患，需用 TSan 确认。
  - sbw_extension_process_running 每次调用 WaitForSingleObject，监控线程与 UI 轮询都会触发，开销小，未测量。

### 对前文的更新
- 47.2 的子进程句柄泄漏疑点降级：不是泄漏，是失败路径上的持有时间问题，待读 worker 侧后定性。
- 已读范围内仍最值得先复现的是第 27 节 sbw_traffic_record(NULL,...) 未判空；其次是本节 c->failed 的无锁读写（推断，未复现）。

## 50. 补读：extension_process.c 的 sbw_extension_process_new 后半段与 free（更正 25.4 / 47.2）

以下均为阅读结论，未编译、未跑 ASan/TSan。未读：sbw_extension_sandbox_verify_process、sbw_extension_sandbox_new 的失败清理细节。

- sbw_extension_process_new（extension_process.c:50-107）在所有失败路径都返回非 NULL 的 c：failed 标签里先 close_worker(c)，再置 c->failed=true，并在注释中说明这是为了避免监控线程每 2 秒重启一个坏插件。因此 25.4 里“process_new 失败返回 NULL 后 work_directory/call 解引用 NULL”的疑点前提不成立：返回的是 failed 描述符，work_directory 返回 NULL，call 因 running 为 false 返回 EXTENSION_FAILED，httpdebug.start 随后 free 并置 NULL。26.1 的结论改为：不是 NULL 容忍，而是“永不返回 NULL”的约定，应在函数头注释写明，调用方不要再写 NULL 判断。
- sbw_extension_process_free(NULL) 安全（if(c)）。close_worker 最多等待 3000 毫秒，process_free 因此可能阻塞调用线程，应写进注释。
- 47.2 / 49 的子进程句柄担心进一步收窄：worker 被 job 以 KILL_ON_JOB_CLOSE 管理，close_worker 先关 job，所以 free 或失败（c->failed 时 call 内 close_worker）后 worker 必被终止，复制进去的驱动句柄随进程回收。仍未验证的只有“call(broker) 失败但 worker 未被 close_worker”的路径：call 返回 NULL 可能是 worker 业务错误（ok=false）而不是通信失败，此时 worker 仍存活并持有句柄，capture_proxy.c 只停了父进程的 broker。建议该路径显式 action(c,"stop")。
- 值得保留：沙箱（AppContainer 能力）、句柄白名单（PROC_THREAD_ATTRIBUTE_HANDLE_LIST）、先挂起创建 -> 校验令牌 -> 加入 job -> 再恢复、job 的内存/CPU/UI/进程数限制、失败阶段字符串与 Win32 错误码保存。重构时必须原样保留并补故障注入测试。
- 坏味道：
  - 函数约 58 行，goto failed 20 余处，stage 字符串变量与 startup_error 布尔共同决定错误消息，应改为上下文结构体加单一清理函数，并把阶段做成枚举。
  - id 的推导用三层三元表达式比较路径字符串，应与 extension_store 的 releases 表合并（按路径查表）。
  - 魔法数字：512MiB、768MiB、CPU 速率 2500（25%）、ActiveProcessLimit 4/1，应命名常量。
  - failed 标签里 close_worker 之前先 free(exe)/free(root)，其后仍可能使用 exe 的路径已不再需要，顺序无问题，但 pi.hThread 在三处失败分支手工关闭，应并入统一清理。
  - startup_error 在“trust”和“sandbox”阶段为 false，使这两种失败只写默认消息，与其他阶段信息量不一致。

### 对前文的更新
- 25.4 / 26.1 的 NULL 担心改为“从不返回 NULL”约定；47.2 / 49 的句柄担心收窄为“call 业务失败时 worker 仍持有句柄”。
- 目前已读范围内最值得先复现的仍是第 27 节 sbw_traffic_record(NULL,...)；其次是 49 节 c->failed 的无锁读写与本节 call 失败后的句柄持有（均为推断，未复现）。

## 51. 更正第 27、37 节：sbw_traffic_record 判空疑点撤销

以下为阅读结论，未编译、未跑 ASan/TSan。

- 撤销第 27 节的疑似缺陷。windows/CMakeLists.txt:168 把 service/traffic_proxy.c 编进 sb_windows_controller（服务侧），traffic.c 不在该目标里，是 worker 侧实现。第 27 节读的是 traffic.c，读错了文件。
- 服务侧 traffic_proxy.c:8 的 sbw_traffic_running 先判 t 非 NULL 再查进程；:16 的 sbw_traffic_record 入口就是 if(!sbw_traffic_running(t))return;。所以只启用 capture、未启用 statistics 时，collect_traffic 传入 NULL 是安全的空操作，不会崩溃。call() 对 NULL 的 t 也返回 NULL。
- 第 27.4 节、第 42/43/44 节中『目前最值得先复现的疑似缺陷是 sbw_traffic_record』一律作废。当前已读范围内没有被证实的真实缺陷，只有可读性、重复、魔法数字和少量需要 TSan 验证的无锁读写隐患。
- 第 37 节 extensions_snapshot 中『sbw_traffic_running 对 NULL 的行为未读』已解决：对 NULL 返回 false。
- 仍成立的小问题：collect_traffic 在 traffic 为 NULL 时仍继续轮询 Clash API，只为给 capture 喂数据；条件 !traffic && !sbw_extension_enabled() 可读性差，建议拆成两个命名布尔变量。sbw_extension_enabled 只表示 capture，建议改名。
- 教训写入方法论：同名函数在 windows/ 下可能有 worker 侧与服务侧两份实现（capture.c/capture_proxy.c、traffic.c/traffic_proxy.c），下结论前必须先查 CMake 确认文件归属。

## 52. 补读：extension_sandbox.c 90 行以后

- sbw_extension_sandbox_new（约 105-131 行）：失败统一 goto fail，保存 GetLastError 后 sbw_extension_sandbox_free 再恢复，注释说明了原因。free 会撤销 loopback 豁免、释放 AppContainer SID 与三块内存。已读路径上未发现泄漏。
- 值得保留：用根路径 SHA-256 前 6 字节派生确定性 AppContainer 名；已存在则 Derive；环境变量只放行八个白名单键，值来自令牌与已知文件夹而非继承环境；verify_process 检查 AppContainer SID 匹配、完整性级别不高于 Low、危险特权（Debug/TCB/LoadDriver/Impersonate）未启用。重构必须原样保留并补负面测试。
- 坏味道：第 5 份 BCrypt SHA-256 实现；32768、65、8、4 等字面量；network 能力只对 http-debug 开启，按 id 字符串比较，应放进 releases 表；environment() 里 keys[] 与 values[] 靠下标配对；一行多语句风格（W2）。
- sbw_extension_sandbox_new 在 CreateAppContainerProfile 成功后若后续失败，不删除该 profile，只靠确定性命名下次复用；是否会累积残留 profile 未读，需确认卸载流程。

## 53. 当前覆盖状态小结

已逐行读过的：controller.c 绝大部分、control_plane.c 绝大部分、capture*.c、extension_process.c、extension_sandbox.c、extension_store.c 与 plugin_storage.c 前部、route_probe.c、subscriptions.c fetch_run、update_transaction.c 主函数、c/ 下 proxy_users.c、proxy_clock.c、auth_oidc.c finish、http_server.c 的 self_singbox_main 与锁上下文、store.c 的若干函数、apple/Core 的 sba_build_runtime 与 support.c。仍只扫描未读的：store.c 其余约 3000 行、http_server.c 与 http_routes_*.c 的处理器、wireguard.c 其余、proxy_parser.c 其余、agent_main.c、agent_ui.c、auth_security.c、windows/ui-host、windows/tests、其余工作流。没有编译，没有跑任何测试、ASan 或 TSan。因此本文仍不能声称已列出全部坏味道。

## 54. 补读：c/src/agent_main.c（1463 行，只读了前 120 行与 runtime_init、apply_config、run_cycle、sb_agent_main）

以下均为阅读结论，未编译、未跑 ASan/TSan。未读：`runtime_free`、`run_local_action`、`run_commands`、`split_command_line`、`resolve_agent_identity`、`local_ui_options`、各 `ui_*` 回调、`agent_proxy_exchange`、`wait_for_work`，以及 120–808 行和 1196–1383 行之间的全部内容。

### 54.1 函数规模

- 按 awk 启发式，超过 50 行的函数只有四个：`sb_agent_main` 80 行、`runtime_init` 71 行、`run_cycle` 62 行、`apply_config` 57 行，均低于 S1 的 80 行目标线以下或接近线上。agent_main.c 的函数粒度明显好于 store.c、http_server.c，不是优先整改对象；文件本身 1463 行，也在 1500 行目标内。

### 54.2 runtime_init（808–878）

- 值得保留：所有失败统一 `goto fail`，`fail:` 只调用一次 `runtime_free(rt)`，且开头先 `memset(rt, 0, ...)`，使部分初始化的对象可安全释放。这正是 S2 与 W5 想推广的“单一清理点”写法。
- 坏味道：
  - 魔法数字 `15000`、`5000`（客户端超时毫秒），未命名。
  - 三层嵌套的代码块各自声明 `options`，同名异型（`sb_agent_config_options`、`sb_singbox_supervisor_options`、`sb_agent_client_options`），可读性差，应拆成 `init_supervisor()`、`init_clients()`、`init_proxy_runtime()`。
  - `AGENT_HOST_ID` 与已登记 host_id 不一致时直接报错，这条业务规则只在此处，没有注释和对应测试名，需补回归测试。
- 未验证：`runtime_free` 是否容忍字段为 NULL 或零值（例如 `rt->supervisor`、`rt->client` 尚未创建就失败），需读该函数。`pthread_mutex_init`、`pthread_cond_init` 的返回值未检查，属于全局约定。

### 54.3 apply_config（991–1047）

- 托管分支与外部管理分支的成功尾部完全重复：`set_running`、`set_etag`、`set_rule_source`、`printf("applied config ...")`，应抽 `commit_applied_config()`。
- `free(reloaded.detail)` 在三条路径上各写一次，容易漏；`process_result` 应提供 `process_result_free()`。
- 注释写着“C++ lets the restore failure escape…”，是对历史实现的引用，应改写成当前行为说明：恢复失败时报告恢复错误而不是重载错误。该行为本身（用恢复错误覆盖原始重载错误）会丢失重载失败原因，值得业务确认，重构前不要改。
- 所有权：`prepared`、`previous` 在 `out:` 统一释放，已读路径上未发现泄漏。

### 54.4 run_cycle（1133–1194）

- 五个相互独立的花括号块，每块各自声明 `sb_err error = {0}`，结构清晰，可拆成 `cycle_poll_config()`、`cycle_supervise()`、`cycle_report()` 但收益有限。
- 遥测失败只打印到 stderr 而不进入 `errors`，有注释说明是有意设计，应保留。
- 与 cpp/ 的 `AgentRuntime::run_cycle` 相比，这里托管分支没有检查“期望运行”状态；我没有读到 C 版是否还有 `desired_running` 等价字段，也没有读 `run_local_action`，不下结论。

### 54.5 sb_agent_main（1383–1463）

- 主循环是 `for (;;)`，没有任何信号驱动的退出路径；文件头注释写明 SIGINT/SIGTERM 保持默认动作，所以进程被信号直接终止，`runtime_free`、`sb_agent_ui_free` 不会执行。这是对 C++ 版行为的刻意移植，但在“托管 sing-box 子进程”场景下，子进程是否随之退出取决于 `sb_singbox_supervisor` 的实现（未读，嵌入式引擎模式下则在同一进程内）。需要读 `singbox_supervisor_child.c` 确认：若子进程不随父进程退出，会留下孤儿 sing-box 并持续占用端口与 TUN。这是目前已读范围内一个值得核实的运行期风险，**推断，未复现**。
- `goto fail` 之后的清理只释放 `local_ui` 和 `runtime`，而 `options.address` 在“UI 创建失败”分支手工 `free`、成功分支在块尾 `free`，两处风格不同，容易错位。
- `--once` 路径复用同一个 `err`，且在 `runtime_init` 成功后才进入，行为合理。
- 注释和标识符仍保留历史名：`AGENT_SERVICE` 为 `sb-easy-cpp-agent`，注释写明这是为了保持面板存储值不变，是兼容性决定，应保留，但常量旁应写明“不得改名”的原因。

### 54.6 辅助函数（1–120）

- `parse_unsigned` 又是一份手写整数解析（含溢出检查，质量比 `atoi` 好），与 S4 提议的 `sb_parse_int_range`、`windows/service/control_plane.c` 的 `decimal`、`proxy_parser.c` 的端口解析构成至少 4 份实现，应统一。
- `parent_path`、`path_append` 手工复刻 `std::filesystem` 语义，注释写着 libstdc++，仍是历史包袱；若只用于 Linux 配置路径，可换成 `dirname` 的受控封装并补测试（含 `/`、`a/`、`/a`、空串）。
- `#ifndef SB_EASY_VERSION #define SB_EASY_VERSION "1.0.0"` 回退值与 `c/CMakeLists.txt` 通过 `sb_core` 的 PUBLIC 定义传入的服务版本（当前 1.1.0）不一致；正常构建中该回退是死代码，同 9.3 的结论，应改为缺失即 `#error`。
- `environment()`、`environment_flag()` 简洁，但 `environment_flag` 每次 `sb_lower_dup` 后分配释放，规模无影响。

### 54.7 覆盖状态更新

- 第 53 节列出的“agent_main.c 仍未读”改为：已读 1–120、808–878、991–1047、1133–1194、1383–1463，其余约 800 行未读。
- 已读范围内没有新增被证实的真实缺陷；54.5 的子进程残留是待核实的推断。

## 55. 核实 54.5：agent 被信号终止时托管 sing-box 子进程的去向

以下为阅读结论，未编译、未复现。未读：`singbox_supervisor_embedded.c` 的停止路径、Dockerfile 与 systemd unit 的 KillMode 设置。

- `singbox_supervisor_child.c:158-172`：`posix_spawnp` 只配置了 stdin 重定向到 /dev/null，没有 `POSIX_SPAWN_SETPGROUP` 或 `SETSID`，也没有 `prctl(PR_SET_PDEATHSIG)`。
- `agent_main.c` 只有 `signal(SIGPIPE, SIG_IGN)`（1386 行），没有 SIGTERM/SIGINT 处理器，也没有 `atexit`。文件头注释说明这是有意保持默认动作。
- 推断：非 `--once` 模式下，agent 被 `kill <pid>`（SIGTERM）或 SIGKILL 直接终止时，`sb_singbox_supervisor_stop` 不会执行，sing-box 子进程不会收到信号，会成为孤儿并继续占用端口与 TUN。只有终端 Ctrl+C 因同属一个前台进程组，才会让子进程一起收到 SIGINT。
- 缓解因素（未核实）：在容器里 agent 若是 PID 1，退出时整个容器被回收；systemd 默认 KillMode=control-group 会清理同组进程。风险主要在裸机上只杀单个 PID 的场景。
- 监督器本身已有优雅停止：`singbox_supervisor_child.c:236-251` 先 SIGTERM、等待超时、再 SIGKILL 并 waitpid，说明缺的只是 agent 没有调用它。
- 整改：为 SIGTERM/SIGINT 安装处理器，用 self-pipe 唤醒主循环，退出前调用 supervisor 停止并释放 runtime。`http_server.c` 的 `g_signal_pipe` 已有同样的写法可复用。不建议用 `PR_SET_PDEATHSIG`，因为 `posix_spawn` 无法在子进程里调用它，而且该信号绑定的是创建线程而不是进程。改动前先补测试：向 agent 发 SIGTERM 后断言 sing-box 进程已退出。
- 这是目前已读范围内最有价值的待核实运行期问题，状态为推断，未复现。

## 56. 收窄第 55 节：孤儿 sing-box 风险只在特定部署下成立

以下为阅读结论，未编译、未复现。未读：Dockerfile 的 ENTRYPOINT/CMD 细节、compose 的 init 设置、linux/packaging 两个 unit 的 KillMode（本节随后读取）。

- docker-entrypoint.sh 对 `sb-easy agent` 使用 `exec sb-easy-agent`，agent 取代 shell 成为容器主进程。容器内 agent 若是 PID 1，被 SIGTERM/SIGKILL 终止后容器整体回收，子进程不会残留；默认信号处理对 PID 1 的特殊语义（无处理器的 SIGTERM 会被忽略）是否生效取决于是否启用 init，未读，故该场景是否能被 docker stop 正常停止待确认。
- 嵌入式引擎构建（singbox_supervisor_embedded.c）在同一进程内托管引擎，进程终止即引擎终止，不存在孤儿问题；它的 stop 在 175 行，失败只记录 last_error。
- 因此孤儿风险只对「非容器、非嵌入、以子进程方式托管、且只杀单个 PID」的裸机部署成立，范围比第 55 节写的小。整改仍是安装 SIGTERM/SIGINT 处理器，但优先级下调为中低。
- linux/packaging 下的 unit 属于桌面隧道服务，不是 agent 的 unit，不能据此判断 agent 的 KillMode。

## 57. 补读：agent_main.c 的 runtime_free / run_local_action / run_commands / wait_for_work

以下均为阅读结论，未编译、未跑 ASan/TSan。未读：sb_agent_client_free、sb_agent_clash_free、sb_proxy_runtime_free、sb_singbox_supervisor_free 对 NULL 的处理，run_runtime_command、proxy_test_tags、report_latency。

- runtime_free（768-790）：释放顺序合理，先 proxy 与 client，再 supervisor（注释说明会停止托管子进程），最后字符串与互斥量，结尾 memset 清零。runtime_init 开头先 memset 再逐步创建，所以失败路径上 goto fail 调用它时，未创建的字段为 NULL；这些 free 函数是否容忍 NULL 未读，故 runtime_init 失败路径是否安全仍待确认（free(NULL) 的字符串字段没有问题）。
- 关于第 55 节的补充：runtime_free 经 sb_singbox_supervisor_free 会停止子进程，说明正常退出路径（--once 与 fail 分支）是干净的；孤儿风险仍只在被信号直接终止时出现，结论不变。
- run_local_action（1070-1084）：只处理 reload 与 restart，start 与 stop 在 C 版没有对应分支，与 cpp 版 AgentRuntime 的 start/stop 队列动作不一致；本地 UI 是否还提供 start/stop 未读（ui_request_action），不下结论。成功与失败路径都释放 result.detail，没有泄漏；成功时才打印日志。
- run_commands（1092-1131）：值得保留：未知命令也会以失败状态回执，服务端不会反复下发。坏味道：命令名用 strcmp 链分发，新增命令要改这里；test-proxies 分支嵌套较深且内部另声明 sb_err error，与外层 err 并存，易混；changes_running_state 布尔变量只为一次条件，可并入分支；字符串 reload/restart/test-proxies 是散落字面量。回执失败即 break，剩余命令下次轮询重发，行为合理，应加注释。
- wait_for_work（1197-1208）：用 CLOCK_MONOTONIC 的条件变量，行为正确。100*365*24*60*60 的上限手写常量，可命名。它只等待 refresh、reload、restart 三个标志，不含 start/stop，与 run_local_action 一致。

### 对前文的更新
- 第 54 节未读列表中的 runtime_free、run_local_action、run_commands、wait_for_work 已读完。agent_main.c 仍未读：约 120-768、880-991、1050-1070、1085-1092、1209-1383 行。
- 已读范围内仍没有被证实的真实缺陷；最值得先核实的是第 55/56 节的裸机孤儿进程场景（推断，未复现）。

## 58. 补读：agent_main.c 120-768 行（路径、凭据、环境变量、命令行拆分、run_program）

以下均为阅读结论，未编译、未跑 ASan/TSan。未读：sb_atomic_replace_file 的文件权限实现、sb_enroll_device、agent_main.c 的 880-991、1050-1070、1085-1092、1209-1383 行（含各 ui_* 回调和 agent_proxy_exchange）。

- 值得保留：split_command_line 不经 shell，手写引号和转义状态机，未闭合时报错；resolve_agent_identity 优先级清楚（环境令牌 > 凭据文件 > 一次性注册码），环境令牌缺 SB_EASY_SERVER 时明确报错；load_device_credential 区分三种结果（已加载、不存在、出错），host_name 与 profile_name 按 JSON 里的长度复制以保留内嵌 NUL。local_route_rules、outbound_overrides 等在各失败出口都释放 parsed、text、path，未发现泄漏。
- 重复实现：run_program（agent_main.c）与 singbox_supervisor_child.c 开头的 run_program 几乎逐行相同（posix_spawnp、waitpid 循环、四种 detail 文案），应抽到共享的进程工具里；parse_unsigned 与 parse_port 之外，windows 侧 decimal、proxy_parser 的端口解析是同类实现，累计至少 4 份；read_stream 与别处读文件的循环重复。
- 待核实（推断）：save_device_credential 先 sb_atomic_replace_file 再 chmod(0600)。若原子替换创建的临时文件按 umask 取默认权限，则在替换到 chmod 之间令牌文件可能被同机其他用户读取。我没有读 sb_atomic_replace_file 是否先以 0600 创建，所以不下结论；整改：让原子写入接口接收 mode 参数并在创建时设置，chmod 只作兜底，并补一条权限断言测试。
- read_stream 没有大小上限，整文件读入内存，配置、凭据、覆盖文件都走它。输入来自本机管理员配置，风险低，但应加上限（例如 8 MiB）并命名常量。
- 默认 AGENT_UI_BIND 为 0.0.0.0:51822，只在设置了 AGENT_UI_PASSWORD 时启用，README 已提示明文 HTTP；建议默认改为 127.0.0.1，需要远程访问时显式配置。这属于默认值安全性问题，改动会影响现有部署，需在发布说明里写明。
- 令牌等敏感字符串用普通 free 释放，没有清零（agent_identity_free），与 windows 侧用 SecureZeroMemory 的做法不一致，建议统一为 sb_secure_free 一类的封装。
- 魔法数字与历史注释：65536（读缓冲）、15000（注册超时毫秒）；std::filesystem、libstdc++、C++ environment() 之类注释都是对历史实现的引用，应改写成当前契约说明；错误文案里的 basic_filebuf::underflow、filesystem error: status 是为兼容旧输出刻意保留的，改之前要确认没有客户端依赖。
- 路径助手 parent_path、path_append、path_beside 手工复刻 std::filesystem 语义，需补 /、a/、/a、空串等边界测试后再考虑替换。

### 覆盖状态更新
- agent_main.c 已读 1-1050 行（除 880-991）、1070-1085、1092-1209、1383-1463，其余未读。已读范围内没有被证实的真实缺陷；最值得先核实的是 save_device_credential 的权限窗口和第 55/56 节的裸机孤儿进程场景（均为推断，未复现）。

## 59. 核实 58 节：save_device_credential 的权限窗口不成立

以下为阅读结论，未编译、未复现。

- atomic_file.c:28-37 的 destination_mode：目标文件不存在时 mode 取 0600，已存在时沿用其权限（st_mode & 0777）。第 89 行 open(temporary, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, mode) 用该 mode 创建临时文件。因此首次登记时凭据文件从创建起就是 0600，不存在被同机其他用户读取的窗口。58 节对此的担心撤销。
- 残留的小问题：目标文件已存在且权限宽松时（例如被手工改成 0644），新内容会沿用宽松权限，之后 save_device_credential 的 chmod(0600) 才收紧，期间有短暂窗口。该情形需要有人先改坏权限，风险低。整改：对凭据文件让原子写入接收显式 mode 参数，chmod 仅作兜底，并补一条权限断言测试。
- 值得保留：临时文件用 O_EXCL 加随机后缀、写入后 fsync、校验器通过后才 rename、rename 后 fsync 目录、失败时 unlink 临时文件。这是整个 C 实现里最完整的原子写入，也是 Windows 侧 update_files.c、secure_store.c 可对照的样板。
- 坏味道：destination 为 slash==destination 的目录推导与 agent_main.c 的 parent_path 是同一逻辑的又一份实现；sb_mkdirs(directory, 0777) 的 0777 受 umask 约束，但意图没有注释；rename 成功后 fsync_directory 失败时返回错误而文件已替换，调用方会误以为未生效，应在注释中写明。

### 覆盖状态
- 已读范围内仍没有被证实的真实缺陷。待核实的推断只剩：第 55/56 节裸机部署下 agent 被 SIGTERM 终止后 sing-box 子进程成为孤儿（风险已收窄），以及若干需要 TSan 验证的无锁读写（例如 extension_process 的 failed 字段）。
- 仍未读：agent_main.c 的 880-991、1050-1070、1085-1092、1209-1383 行（ui_* 回调、agent_proxy_exchange 等），store.c 其余约 3000 行，http_server.c 与 http_routes_*.c 的处理器，wireguard.c、proxy_parser.c 其余部分，agent_ui.c，auth_security.c，windows/ui-host，windows/tests。没有编译，没有运行任何测试、ASan 或 TSan。

## 60. 补读：agent_main.c 剩余区段（状态访问器、UI 回调、入口）

以下均为阅读结论，未编译、未跑 ASan/TSan。未读：`sb_proxy_runtime_status` 的内部加锁、`sb_agent_config_options_from_json/save` 的实现、`sb_agent_clash_*`。

- 状态访问器（880-934）：`set_etag`、`copy_etag`、`set_running`、`get_running`、`set_rule_source` 均在 `state_mutex` 内读写，写法一致，没有问题。`take_queued_actions` 在锁内取走并清零标志，行为正确。
- `agent_proxy_exchange`（920-934）：读写 `rt->proxy_capability_due_ms` 不加锁。它只由 proxy runtime 线程调用时没有竞争，但该线程归属没有注释，也没读 `sb_proxy_runtime` 的线程模型，结论是未发现竞争、也未证明没有。`60000` 是未命名的毫秒字面量。
- `ui_request_action`（1345-1360）：只支持 refresh、reload、restart 三个动作，与 `take_queued_actions`、`wait_for_work`、`run_local_action` 一致，所以 57 节「C 版没有 start/stop 是否与 cpp 不一致」的疑问可以关闭：C 版有意只保留这三种，应在注释里写明与 cpp 版 `AgentRuntime` 的差异。动作名是散落字符串，应与 UI 前端共用一张表。
- `ui_update_settings`（1263-1288）：先校验、再落盘、成功后才替换内存并请求刷新，顺序正确，失败路径释放 `updated`。小问题：先在锁内复制 `current`、解锁、再计算和保存，两个并发 UI 请求会互相覆盖（后者基于旧的 current），属于丢失更新；本地 UI 只有单管理员使用，风险低，但应在注释说明或在保存期间持有一把专用互斥锁。
- `ui_status`（1211-1245）：在持有 `state_mutex` 时调用 `sb_proxy_runtime_status(rt->proxy_runtime)`。若该函数内部取自己的锁，而 proxy 线程在持有自己的锁时调用 `agent_proxy_exchange`（会调用 `get_running`/`copy_etag` 取 `state_mutex`），就存在 state_mutex 与 proxy 锁相反顺序的可能。这是目前读到的最值得用 TSan 或读 `proxy_runtime.c` 确认的一处锁顺序疑点，推断，未证实。
- `ui_proxies`（1301-1342）：`value_string(outbound, type, ...)` 对同一个键读了两次，一次带 unknown 回退、一次带空串回退，应取一次；所有失败路径统一 `goto fail`，`proxy` 在中途失败处手工释放，已读路径上没有泄漏。
- `run_runtime_command`（1052-1068）：连续调用两次 `sb_singbox_supervisor_running`，两次之间状态可能变化，结果与说明文案可能不一致，应取一次存局部变量。
- `usage()` 仍写着 bind 默认 `0.0.0.0:51822`，与 58 节指出的默认暴露面问题一致；该文案、README 和代码默认值是三处，改默认值时必须同时改。
- `report_latency`（1086-1090）：丢弃 `updated` 计数，不影响正确性。

### 覆盖状态
- agent_main.c 现在除 `local_ui_options` 之后已读部分外基本读完，没有新增被证实的真实缺陷；仍待核实的只有：55/56 节的裸机孤儿进程场景，以及本节 `ui_status` 持锁调用 `sb_proxy_runtime_status` 的锁顺序（均为推断）。
- 仍未读：store.c 其余约 3000 行、http_server.c 与 http_routes_*.c 的处理器、wireguard.c 与 proxy_parser.c 其余部分、agent_ui.c、auth_security.c、proxy_runtime.c、windows/ui-host、windows/tests。没有编译，没有运行任何测试、ASan 或 TSan。

## 61. 核实 60 节：ui_status 与 proxy_runtime 的锁顺序疑点撤销

以下为阅读结论，未编译、未跑 TSan。已读 proxy_runtime.c:205-345。

- sb_proxy_runtime_step 先 trylock `operation`，调用 `runtime->exchange`（即 agent_proxy_exchange）期间不持有 `runtime->mutex`。`runtime->mutex` 只在 stopping()、outcome()、start、stop、status 里短暂持有，临界区内只改字段。
- agent_proxy_exchange 会取 `state_mutex`（get_running、copy_etag），所以存在 `operation -> state_mutex`。ui_status 持有 `state_mutex` 时调用 sb_proxy_runtime_status，后者取 `runtime->mutex`，所以存在 `state_mutex -> runtime->mutex`。`operation` 与 `runtime->mutex` 从不嵌套，ui_status 也不取 `operation`，已读路径上没有环，60 节的死锁疑点撤销。
- sb_proxy_runtime_stop 先 join 工作线程，再取 `operation` 调用 bridge.stop，顺序正确；join 期间不持有任何锁。
- 残留的坏味道：
  - 三把锁（operation、runtime->mutex、agent 的 state_mutex）的层级没有文档，应在 proxy_runtime.c 头部写明 `operation -> state_mutex`、`state_mutex -> mutex`，并注明 operation 与 mutex 不得嵌套。
  - sb_proxy_runtime_step 约 55 行，pending_request 里有四处手工 free 的重复序列，函数内 goto done 与多处早退并存；一行多语句风格严重（W2）。
  - 魔法数字：SB_PROXY_POLL_MILLIS 已命名，但 wait_ms < 1000、1000000000L、ttl 的 -1 和 *1000 是裸字面量；ttl 减 1 的含义没有注释。
  - agent_proxy_exchange 对 rt->proxy_capability_due_ms 无锁读写，只有 worker 线程调用 exchange（step 由 operation 互斥，且 --once 路径与 worker 不同时运行），所以当前没有竞争，应在字段旁注明线程归属。
  - 失败时用 `&ignored` 丢弃底层错误，对外只给固定文案，排查时只能靠 issue 字符串，应记录阶段日志（不含请求内容）。
- 值得保留：计数器先 begin 再 exchange、apply 先于 acknowledge、只确认已提交的原字节、时钟回退即停桥，这些顺序都有注释说明原因，重构时必须原样保留并补故障注入测试。

### 覆盖状态
- 已读范围内仍没有被证实的真实缺陷。仍待核实的推断只剩 55/56 节的裸机孤儿进程场景（范围已收窄）。
- 仍未读：store.c 其余约 3000 行、http_server.c 与 http_routes_*.c 的处理器、wireguard.c 与 proxy_parser.c 其余部分、agent_ui.c、auth_security.c、windows/ui-host、windows/tests。没有编译，没有运行任何测试、ASan 或 TSan。

## 62. 补读：agent_ui.c 开头与 auth_security.c 开头

以下均为阅读结论，未编译、未跑 ASan/TSan。两个文件都只读了 1–140 行。未读：agent_ui.c 的 route_request、begin_request、sb_agent_ui_new；auth_security.c 的 issue_locked、mfa_verify_locked、complete_bound。

- agent_ui.c 的 session_login：用 sb_consttime_streq 比较凭据，令牌 sb_random_hex(32)，会话 12 小时，值得保留。
- 坏味道：登录后按新令牌在会话表里查重并替换，256 位随机令牌不可能碰撞，该分支是死代码。会话数组没有上限。已读部分看不到登录限速或锁定，是否在 begin_request 里处理未读，不下结论。sb_monotonic_ms 在同一函数里连续调用两次。
- 头注释大量引用 Drogon 与 cpp 行为，属于 S10 的历史包袱；SB_EASY_VERSION 又有一份 #ifndef 回退；sb_agent_ui_options_init 默认地址 0.0.0.0，与第 58 节的默认暴露面问题一致。
- auth_security.c：AES-256-GCM，12 字节随机 nonce，purpose 作为 AAD，缓冲长度 length+29 与 1+12+密文+16 的布局吻合，用后 OPENSSL_cleanse，解密拒绝内嵌 NUL。值得保留。
- 设计提醒：加密密钥由 jwt_secret 经 HMAC 派生，轮换 JWT_SECRET 会使依赖它加密的密文（已读到 OIDC 的 verifier 与 client secret）无法解密，README 应写明。MFA 是否同样依赖未读。
- 坏味道：29、12、16、65536、90000、1024、256 是未命名字面量；sb_auth_sec_encrypt 用一条七个调用的 && 链，失败时无法知道是哪一步，应拆开并记录阶段。

## 63. 补读：agent_ui.c 路由与请求入口、auth_security.c 的 issue_locked / mfa_verify_locked

以下均为阅读结论，未编译、未跑 ASan/TSan。已读：agent_ui.c:672-880、auth_security.c:143-202、385-444。未读：handle_login、static_file_response（路径穿越防护）、mfa_failed_locked、recovery_hash、sb_auth_totp_code、sb_auth_security_complete_bound。

### 63.1 agent_ui.c
- 值得保留：/api/ 下除 /api/login 与 /health 外一律先校验会话；POST/PUT/DELETE/PATCH 额外要求 UI 标记头（防跨站请求）；请求体有 512 KiB 上限，Content-Length 与流式读取两处都检查；handler 之间用 handler_mutex 串行。
- 待核实（不下结论）：static_file_response 如何处理 ../ 与 %2e%2e，路径已被 drogon_url_decode 解码（含把路径里的 '+' 解成空格，这是对 Drogon 行为的刻意复刻，但对路径并不标准），穿越防护必须在解码之后做，需读该函数并补测试（/assets/..%2f、/assets/../、符号链接）。
- 待核实：handle_login 是否有失败限速或锁定。route_request 里没有，sb_agent_ui_options_init 默认监听 0.0.0.0，会话数组无上限，三者叠加意味着默认配置下可被无限次猜密码；需读 handle_login 后定性，建议补失败计数与指数退避，并把默认监听改为 127.0.0.1。
- handler_mutex 把所有处理器串行，而 handle_route_test 会发起带超时的真实 CONNECT 请求，一个慢请求会让整个本地 UI（含登录与状态）排队。建议只对修改共享状态的处理器加锁，或把路由测试放到工作线程。
- 坏味道：begin_request 把读体、URL 解码、小写化、路由、响应发送、清理全放一个函数；route_request 68 行；exact_routes 表驱动是好写法，应推广到 route_regex（该函数用手写正则语义的字符串判断模拟 Drogon 正则，dot_star、single_file_path、segment_is 一组辅助函数为历史兼容而存在，注释已写明）。魔法数字 8（'/assets/' 长度）、7（'assets/' 长度）、5（'/api/' 长度）应用 sizeof 推导。中文错误文案直接写在 route_request 里，应集中到文案表。
- begin_request 的 413 分支在体已部分读入时释放 body 后返回，路径上无泄漏；req.path/lower、resp.body/set_cookie 在正常出口均释放。

### 63.2 auth_security.c
- issue_locked（59 行）：值得保留：登录时在同一把互斥下重查 MFA 是否已启用，注释说明方法标签不能当作 MFA 已完成的证明；会话令牌只存 HMAC 哈希；每个账户只保留最近 100 个会话。坏味道：
  - 先 required_user_locked 查一次用户，再 SELECT 同一用户一次，重复查询。
  - JWT 头 eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 是手写 base64 字面量，应注明其解码为 {"alg":"HS256","typ":"JWT"} 并与验证侧共用同一常量。
  - INSERT 成功后清理旧会话的 DELETE 失败会返回 NULL 并释放 token，但会话行已写入，造成一条永远无人持有的会话（72 小时后过期，影响小）；两步不在同一事务里，应合并或把清理失败降级为日志。
  - 魔法数字 24、100、86400；SQL 全部是单行长字符串。
  - 已读路径上 st、id、hash、json、encoded、signature 均有释放，未发现泄漏。
- mfa_verify_locked（59 行）：值得保留：先查锁定、再校验码字符、再解密；TOTP 窗口 ±1 步，要求 step > last_step 以防重放（pending 设置阶段除外）；比较用常量时间；循环不提前退出；恢复码用 UPDATE ... used_at IS NULL 并以 sqlite3_changes()==1 判定一次性消费。坏味道与待核实：
  - 恢复码 UPDATE 成功但后续 UPDATE auth_mfa 失败时恢复码已被消耗而登录失败；是否被外层事务回滚未读，需确认（若无事务，用户会无故丢失一个恢复码）。
  - 函数同时承担状态读取、解密、TOTP 匹配、恢复码匹配、状态写回，应拆成 mfa_load_state、mfa_match_totp、mfa_consume_recovery、mfa_record_success。
  - 魔法数字 30（TOTP 步长，出现 2 次）、6、9、128、256；pending 与 last_step 的分支用三元表达式嵌套（sbq_bind_int 那一行），可读性差。
  - 返回 bool 而错误在 err 里，与同文件其他函数返回 int 的约定不一致。

### 63.3 覆盖状态
- 已读范围内仍没有被证实的真实缺陷。待核实且值得优先处理的是：agent_ui.c 的 handle_login 限速与 static_file_response 的路径穿越防护（均为推断，需读代码和测试）。
- 仍未读：store.c 其余约 3000 行、http_server.c 与 http_routes_*.c 的处理器、wireguard.c 与 proxy_parser.c 其余部分、auth_oidc.c 其余、auth_device_policy.c、observability.c、windows/ui-host、windows/tests。没有编译，没有运行任何测试、ASan 或 TSan。

## 64. 核实 63 节：本地 UI 登录限速与静态文件路径防护

以下为阅读结论，未编译、未复现。已读 agent_ui.c:393-405、407-429、441-479、222-225。未读：file_content_type、sb_path_join、sb_read_file 的实现，以及 civetweb 对原始 URI 的预处理。

### 64.1 登录没有失败限速（已核实，属于设计缺口）
- handle_login 只做：UI 标记头检查、JSON 解析、常量时间比较、成功则签发 12 小时会话。对 agent_ui.c 做 grep（attempt、throttle、lockout、rate、failed）没有任何失败计数或锁定逻辑。
- 叠加默认监听 0.0.0.0:51822、会话数组无上限（62 节），在配置了弱 AGENT_UI_PASSWORD 时可被在线暴力猜测。README 已提示该端口应限制在可信网络，所以这是已文档化的部署约束，不是实现错误，但仍建议加防护。
- 整改：按来源地址与全局两个维度记录失败次数，连续失败后指数退避（例如 1、2、4、8 秒，上限 60 秒），并给会话数组加上限（例如 64）。同时把默认监听改为 127.0.0.1，改默认值要同步 usage()、README 与发布说明。补测试：连续错误密码后的延迟、成功后清零、并发登录。
- 注意：handler_mutex 把所有处理器串行，退避必须用时间戳判断而不是 sleep，否则会拖住整个本地 UI。

### 64.2 静态文件路径防护（已核实，当前基本可靠）
- safe_static_relative_path 拒绝：空串、以 / 开头、含 NUL、任一整段恰为 ..。由于 begin_request 已先对路径做 URL 解码（drogon_url_decode），%2e%2e 在进入该函数前就是 ..，所以会被拒绝；/assets/..%2f 同理。
- 剩余风险（推断，需读 sb_path_join 与做测试）：1) stat 跟随符号链接，UI 目录内若有指向目录外的符号链接，S_ISREG 检查通过后会被读出；这需要有人先在 UI 目录里放链接，风险低。2) 只拒绝恰为 .. 的段，不拒绝 . 段和空段（a//b），对安全无影响但行为应写成测试。3) 路径在 URL 解码后再检查，是正确顺序，应写成注释并补回归测试（/assets/../、/assets/..%2f、/assets/%2e%2e/、含 NUL 的 %00）。
- 整改：对解析后的真实路径做前缀校验（realpath 后必须位于 ui_directory 之内），作为第二道防线；补上面列出的回归测试。
- 坏味道：static_file_response 把整个文件读进内存再响应，无大小上限（read_stream、sb_read_file 同类）；cache_control 字符串是字面量；内容类型由 file_content_type 按扩展名决定，未读。
- session_cookie：HttpOnly + SameSite=Strict，没有 Secure 标志。服务本身是明文 HTTP，加 Secure 会让浏览器在 HTTP 下丢弃 cookie，所以不加是合理的；README 已建议用反向代理终止 TLS，此时应在代理层补 Secure。应写成注释。
- 登录成功响应里 username 取自请求而非配置值；两者已经常量时间比较相等，所以没有差别，仅是可读性问题。

### 覆盖状态
- 已读范围内仍没有被证实的真实缺陷；有两处值得优先处理的设计缺口：本地 UI 登录无限速（64.1）、默认监听 0.0.0.0（58、62、64.1）。
- 仍未读：store.c 其余约 3000 行、http_server.c 与 http_routes_*.c 的处理器、wireguard.c 与 proxy_parser.c 其余部分、auth_oidc.c 其余、auth_device_policy.c、observability.c、windows/ui-host、windows/tests。没有编译，没有运行任何测试、ASan 或 TSan。

## 65. 补读：store.c 的 sb_store_redeem_agent_enrollment 与 sb_store_wg_import

以下均为阅读结论，未编译、未跑 ASan/TSan。已读：store.c:2302-2410、3465-3570。未读：exec_stmt、exec_bound 是否在内部 finalize 语句、wg_snapshot_locked、restore_peer、wg_settings_locked、wg_import_same_ip、parse_object_or_empty 对非对象的处理。

### 65.1 sb_store_redeem_agent_enrollment（约 105 行，已读全）

- 值得保留：注册码只存 SHA-256 哈希；在同一事务内先 SELECT 未兑换、未过期、主机启用的记录，再用 UPDATE ... redeemed_at IS NULL 并检查 sqlite3_changes()==1 做一次性消耗，并发兑换时第二个得到 CONFLICT；设备能力字段先校验布尔类型，白名单键才写入 capabilities，服务端不从传输方式推断设备类型（有注释）。
- 坏味道：
  - 函数一次做校验、查询、拆行、合并能力、消耗注册码、写主机、提交，应拆成 enrollment_lookup、merge_device_capabilities、enrollment_consume。
  - `rc = st ? (sbq_bind_text(...), exec_stmt(st, err)) : -1;` 用逗号表达式，可读性差，应拆成两行。
  - 魔法数字 32（注册码最小长度）、字符串 'default'；两个静态键表（feature_keys、keys）与 Windows 侧 enroll() 里写死的能力字段（见第 34 节）是同一份知识的不同副本，应集中成一个能力表。
  - 过期判断依赖 SQLite 的 datetime('now') 字符串比较，与其他处用 sb_unix_now() 的整数时间戳风格不一致。
- 待核实（推断）：SELECT 取回的是主机已有的 agent_token 并原样返回，没有看到在兑换时轮换令牌；若同一主机多次生成注册码，多个设备会共享同一令牌。需要读主机创建与令牌轮换的代码后才能定性，目前不下结论。
- 所有权：result、enrollment_id、capabilities、code_hash 在各出口都有释放，失败路径释放 result，未发现泄漏；st 是否被 exec_stmt 释放属上面的未读项。

### 65.2 sb_store_wg_import（约 104 行，已读全）

- 值得保留：预览与应用共用同一段比对逻辑；摘要覆盖导入前快照和输入批次，应用时必须带回相同的 preview_digest，否则报“预览后状态已变化”，是防 TOCTOU 的好写法；预览路径回滚事务，冲突时不写任何数据；成功后写入迁移记录与审计，并返回 migration_id 以便回滚。
- 坏味道：
  - 一个函数混合快照、摘要、冲突检测、预览报告、设置合并、逐个插入、迁移记录与审计，应拆成 wg_import_plan、wg_import_report、wg_import_apply。
  - 出口有三种：goto success、goto done、中途 rc 判断，done 里还要靠 `rc != 0` 才回滚，而预览路径已提前回滚，读者需要逐行推演才能确认不会重复回滚。
  - 对已有 peer 做嵌套循环比对，复杂度 O(n×m)，规模小可接受，未测量。
  - 字面量 "wg-easy-v14"、"imported"、"preview"、各动作字符串 "add"、"conflict"、"already_present" 散落在函数里；冲突文案用 sb_asprintf 拼接，是对外契约，修改要谨慎。
  - `SBJ_ARR_FOREACH(additions, index, peer) { if (rc == 0) rc = restore_peer(...); }` 循环不在失败时 break，应用 break。
- 已读路径上 before、after、report、additions、ids、settings、digest、migration_id 均在 done 中释放，material 与 serialized 在使用后立即释放，未发现泄漏。

### 覆盖状态
- 已读范围内仍没有被证实的真实缺陷；待核实的推断：65.1 的令牌是否在兑换时轮换；55/56 节的裸机孤儿进程场景（范围已收窄）。
- 仍未读：store.c 其余约 2500 行、http_server.c 与 http_routes_*.c 的处理器、wireguard.c 与 proxy_parser.c 其余部分、auth_oidc.c 其余、auth_device_policy.c、observability.c、windows/ui-host、windows/tests。没有编译，没有运行任何测试、ASan 或 TSan。

## 66. 核实 65.1：agent_token 的生成、兑换与轮换（store.c:2219-2300）

以下为阅读结论，未编译、未复现。已读 sb_store_rotate_agent_token、sb_store_create_agent_enrollment。未读 new_agent_token 的熵来源与长度（store.c:725）、host 创建处（1971 行）、轮换接口的 HTTP 路由与审计。

- 兑换不轮换令牌（已核实）：redeem 直接返回 hosts.agent_token 已有值；轮换只发生在 sb_store_rotate_agent_token 这个单独接口。所以同一主机重复登记（例如重装设备）会拿到同一个长期令牌，旧设备若未被注销仍可继续使用。这是设计取舍，不是实现错误，但应在文档中写明，并考虑兑换时可选轮换。
- 创建新注册码时，同一主机尚未兑换的旧码被立即置为过期（UPDATE expires_at = now），新码有效期写死 10 分钟，值得保留。10 分钟与注册码最小长度 32 是字面量，应命名常量。
- 存储不对称：注册码只存 SHA-256 哈希，而 agent_token 以明文存在 hosts 表，并用 SQL 等值比较查找（store.c:2413）。数据库被读取时，令牌可直接冒用，注册码则不能。建议令牌也存哈希，兑换时返回明文并只展示一次；这会改变 SQLite 模式与现有 Agent 兼容性，属于契约变更，需单独评审，不得顺手改。
- 坏味道：create_agent_enrollment 里 rc = st ? (sbq_bind_text(...), exec_stmt(st, err)) : -1 的逗号表达式；后面为取 expires_at 再 SELECT 一次，可在 INSERT 前用同一个 SQL 表达式算出；各分支手工 sqlite3_finalize；code 与令牌共用 new_agent_token，用途不同，应各有命名函数。
- 所有权：id、code、code_hash、expires_at 在各出口均释放或转移给 out，未发现泄漏。

### 覆盖状态
- 已读范围内仍无被证实的真实缺陷。待核实且优先：明文令牌存储的取舍（66）、本地 UI 登录无限速与默认监听 0.0.0.0（64.1）、裸机 SIGTERM 孤儿 sing-box（55/56，范围已收窄）。
- 仍未读：store.c 其余约 2400 行、http_server.c 与 http_routes_*.c 的处理器、wireguard.c 与 proxy_parser.c 其余部分、auth_oidc.c 其余、auth_device_policy.c、observability.c、new_agent_token、windows/ui-host、windows/tests。没有编译，没有运行任何测试、ASan 或 TSan。

## 67. 补读：new_agent_token（store.c:725-735）

以下为阅读结论，未编译、未复现。未读：sb_random_bytes 的实现（util.c）。

- 令牌与注册码都由两个 sb_uuid_v4() 去掉连字符后拼接，得到 64 个十六进制字符。每个 UUID v4 固定了 6 位（版本 4 位、变体 2 位），所以每个有 122 位随机性，合计约 244 位，熵足够，不是弱令牌。sb_uuid_v4 在随机数失败时 abort（见第 12.2 节），不会返回弱值。
- 坏味道：用 UUID 拼接充当令牌是间接写法，意图没有注释，且依赖 UUID 的固定位布局，若将来 sb_uuid_v4 改成别的格式，令牌长度和字符集会静默变化；应直接用 sb_random_hex(32) 或 sb_auth_sec_random，并命名为 new_secret_token。注册码与 agent_token 共用同一个生成函数，用途不同，应各有命名封装。该函数在 store.c 中是静态函数，而 auth_security.c 另有 sb_auth_sec_random，也是重复。
- 这是改动令牌格式的契约变更风险点：现有已发放的令牌是 64 位十六进制，更换格式要保证旧令牌仍可校验，不得顺手改。

### 覆盖状态
- 已读范围内仍无被证实的真实缺陷。待核实且优先：明文令牌存储的取舍（第 66 节）、本地 UI 登录无限速与默认监听 0.0.0.0（第 64.1 节）、裸机 SIGTERM 孤儿 sing-box（第 55/56 节，范围已收窄）。
- 仍未读：store.c 其余约 2400 行、http_server.c 与 http_routes_*.c 的处理器、wireguard.c 与 proxy_parser.c 其余部分、auth_oidc.c 其余、auth_device_policy.c、observability.c、windows/ui-host、windows/tests。没有编译，没有运行任何测试、ASan 或 TSan。

## 68. 补读:auth_device_policy.c(208 行,已读全)

以下均为阅读结论,未编译、未跑 ASan/TSan。未读:auth_device_groups 等表的建表迁移(外键与级联)、HTTP 层调用 sb_auth_device_allowed 的位置、sbj_validate_utf8。

- 值得保留:sb_auth_device_allowed 用一条 SQL 完成授权判断,默认拒绝。admin 恒通过;operator 与只读操作下的 viewer 需要 auth_user_scope 存在一行,且 scope 为 all 或命中设备组授权;写操作(mutate=1)时 viewer 一律拒绝,组授权必须是 operate。用户不存在或没有 scope 行都得到 FORBIDDEN。所有入参先过 sb_auth_sec_token 校验。
- 需要注意的不一致:sb_auth_user_scope 对没有 scope 行的用户返回 scope=groups、grants 为空,而 sb_auth_device_allowed 要求 scope 行存在,所以没有 scope 行的 operator 实际是拒绝一切。两处结论一致(都是最小权限),但返回值会让界面以为存在一条 groups 范围的记录,应在注释里写明。
- 坏味道:
  - 同一套「prepare、bind、step、finalize、失败 goto rollback」样板在本文件出现约 12 次,是 S2 的又一个样本,适合用 sbq_stmt 收敛。
  - sb_auth_device_group_save 与 sb_auth_user_scope_set 在持有全局数据库锁时对每个主机、每个分组各执行一次 SELECT 校验存在性(上限 2000 与 500 次),是 N+1;用 IN 查询或外键约束即可。
  - sb_auth_user_scope_set 的授权循环用 seen.items[i] 取组 ID、用 grants[i] 取权限,依赖两个数组下标一一对应。因为重复项在前面被拒绝,当前一一对应成立,但这是隐含耦合,应让校验阶段直接产出 {group_id, permission} 数组。
  - group_save 里把任何 SQLITE_CONSTRAINT 都报成「Device group name already exists」;外键或 CHECK 约束失败也会被误报成名称冲突,应区分扩展错误码。
  - json_text 在这里又是一份(与 agent_config.c、auth_device_policy.c 已记录的重复同属一类),魔法数字 128、256、2000、500 应命名常量并与 HTTP 层校验共用。
  - 返回值约定不一致:group_save、remove、scope_set 返回 int(0/-1),sb_auth_device_allowed 返回 bool 并把原因放进 err。
- 所有权:seen、id、result、current 在各出口都有释放或转移,已读路径上未发现泄漏。sb_auth_device_groups 里 current 指针在 push 后仍被使用,而 result 数组可能在后续 push 时重新分配,但存的是元素指针(sbj*)不是元素地址,所以安全。
- 待核实:sb_auth_device_group_remove 只 DELETE 分组行,是否清理 auth_device_group_hosts 与 auth_device_grants 取决于外键 ON DELETE CASCADE,正在查迁移文件。

### 覆盖状态
- 已读范围内仍无被证实的真实缺陷。仍未读:store.c 其余约 2400 行、http_server.c 与 http_routes_*.c 的处理器、wireguard.c 与 proxy_parser.c 其余部分、auth_oidc.c 其余、observability.c、windows/ui-host、windows/tests。没有编译,没有运行任何测试、ASan 或 TSan。

## 69. 核实 68 节：设备组删除的级联清理

以下为阅读结论，未编译、未复现。已读 migrations/015_auth_security.sql:63-79（通过 git grep，仅看到匹配行，未读全文）。未读：该迁移其余部分、SQLite 是否在每个连接上启用了 PRAGMA foreign_keys。

- auth_device_group_hosts.group_id 与 auth_device_grants.group_id 都声明了 REFERENCES auth_device_groups(id) ON DELETE CASCADE，所以 sb_auth_device_group_remove 只 DELETE 分组行是够的，68 节「是否清理授权」的疑点在表结构层面成立为安全。
- 前提未核实：SQLite 默认不强制外键，只有每个连接执行 PRAGMA foreign_keys=ON 级联才生效。前面读过 database.c 的 WAL 与 busy_timeout 设置（database.c:140-145），但没有看到 foreign_keys，需要 grep 确认。若未开启，删除分组后授权行会残留，且残留的 group_id 之后若被同 ID 重建会意外恢复旧授权。这是目前最值得先核实的一点，推断，未复现。
- 整改：确认 foreign_keys 已开启并补回归测试（删除分组后 auth_device_grants 与 auth_device_group_hosts 行数为 0）；未开启则在 sb_database 打开连接处启用，并先评估现有数据库是否已有孤儿行，否则开启后迁移可能失败。
- auth_user_scope 的 user_id 外键与级联未在 grep 输出中看到，用户删除后其 scope 与 grants 是否清理未核实。

### 覆盖状态
- 已读范围内仍无被证实的真实缺陷。待核实且优先：foreign_keys 是否启用（69）、明文令牌存储的取舍（66）、本地 UI 登录无限速与默认监听 0.0.0.0（64.1）。
- 仍未读：store.c 其余约 2400 行、http_server.c 与 http_routes_*.c 的处理器、wireguard.c 与 proxy_parser.c 其余部分、auth_oidc.c 其余、observability.c、windows/ui-host、windows/tests。没有编译，没有运行任何测试、ASan 或 TSan。

## 70. 核实 69 节：foreign_keys 已启用

以下为阅读结论，未编译、未复现。已读 database.c:144 与 database.h:19 的 grep 结果，未读 database.c 打开连接的完整流程。

- database.c:144 在打开连接时执行 `PRAGMA foreign_keys = ON`，database.h 注释也写明 foreign_keys = ON 与 WAL。因此 sb_auth_device_group_remove 只删分组行即可，auth_device_group_hosts 与 auth_device_grants 会按 ON DELETE CASCADE 级联清理。69 节中「foreign_keys 是否启用」的疑点撤销，不再列为优先待核实项。
- 仍未核实：auth_user_scope 的 user_id 外键与级联（用户删除后 scope 与 grants 是否清理）；所有连接是否都经过该打开路径（例如测试或 proxy_clock 的独立连接）。
- 建议补一条回归测试：删除分组后断言 auth_device_grants 与 auth_device_group_hosts 行数为 0，防止日后有人去掉该 PRAGMA。

### 覆盖状态
- 已读范围内仍无被证实的真实缺陷。待核实且优先：明文令牌存储的取舍（66）、本地 UI 登录无限速与默认监听 0.0.0.0（64.1）、裸机 SIGTERM 孤儿 sing-box（55/56，范围已收窄）。
- 仍未读：store.c 其余约 2400 行、http_server.c 与 http_routes_*.c 的处理器、wireguard.c 与 proxy_parser.c 其余部分、auth_oidc.c 其余、observability.c、windows/ui-host、windows/tests。没有编译，没有运行任何测试、ASan 或 TSan。

## 71. 补读:observability.c 前 200 行(sample/target/status/configure/alert/evaluate)

以下均为阅读结论,未编译、未跑 ASan/TSan。已读 observability.c:1-200;未读:sb_observability_history 的 SQL 后半段、200 行以后的函数、observability.h、相关迁移表结构。

- 值得保留:所有计数器入参先校验为非负安全整数;累计值用 saturated_add 防溢出;采样时间倒退(now < at)直接提交并忽略;计数器回退按重置处理,把新值当作增量并累计 counter_resets;告警用 单个活动事件 + 唯一约束 的 upsert,恢复与复发语义写在注释里;evaluate 在一个事务里完成告警评估与过期数据清理。
- 待核实(推断):sb_observability_sample 在检查 row 之前就调用 sbq_int(st, 0..5)。row != 1(没有行)时读取列的结果按 SQLite 文档是未定义的,当前因 ensure_host 刚插入过该行而实际不会发生,但读取顺序应改为先判断 row。
- 坏味道:
  - alert_locked 用同一个函数的两条 SQL:活动分支用匿名 ?,恢复分支用 ?1..?5。恢复分支没有 ?3,却仍执行 sbq_bind_text(st, 3, host),依赖 SQLite 对越界绑定返回 SQLITE_RANGE 且被忽略。能工作,但不应依赖,应按分支分别绑定。
  - evaluate 在持有全局数据库锁时遍历所有 hosts 与 proxy_nodes,每个主机最多再 prepare 三条告警语句,是 N 次 prepare,主机数大时持锁时间长;可预编译一次或合并为单条 SQL。
  - 魔法数字:60(采样桶秒数,同时出现在 sample、settings、history 三处)、3600(探测新鲜度)、86400、253402300800(9999 年上限)、366*86400、2000(桶数上限)、30(评估间隔,只出现在设置返回值里,与实际调度间隔是否一致未读)。
  - 告警类型字符串 device_offline、config_drift、config_failure、node_unreachable、node_slow、node_probe_stale 在 evaluate 和清理 SQL 里各写一遍,应集中为常量表。
  - sb_observability_sample 约 50 行,一行多语句,函数内三条 goto 出口风格与全文件一致,但可读性差(W2)。
  - 结构体里的 mutex、cond、thread、running、stopping 在已读部分没有用到,需读后半段确认是后台评估线程所用。
- 所有权:所有语句都经 finish 或显式 finalize,settings 对象在读取后立即释放,已读路径上未发现泄漏。

### 覆盖状态
- 已读范围内仍无被证实的真实缺陷。仍未读:observability.c 200 行以后、store.c 其余约 2400 行、http_server.c 与 http_routes_*.c 的处理器、wireguard.c 与 proxy_parser.c 其余部分、auth_oidc.c 其余、windows/ui-host、windows/tests。没有编译,没有运行任何测试、ASan 或 TSan。

## 72. 补读：observability.c 200–386 行（history/hosts/alerts/token/prometheus/monitor）

以下均为阅读结论，未编译、未跑 ASan/TSan。本节读完后 observability.c 已读全。未读：observability.h、相关迁移表结构。

- 解决第 71 节的疑问：`monitor_loop` 每 30 秒评估一次，与 `settings_locked` 返回的 `evaluation_interval_seconds` 30 一致，但两处都是字面量，应共用常量。
- 值得保留：指标 token 以 `sbm_` + 64 位十六进制发放，只存 SHA-256，校验时先查长度与前缀，再用 `CRYPTO_memcmp` 常量时间比较；吊销返回空串并把哈希置 NULL；Prometheus 输出对 host_id、resource_id 转义反斜杠、引号、换行并替换控制字符；历史查询限制范围与步长，防止一次取出过多桶。
- 坏味道与待确认：
  - `monitor_loop` 的 `pthread_cond_timedwait` 用 `CLOCK_REALTIME` 计算截止时间，而条件变量按默认时钟初始化。系统时间被调整时评估间隔会变长或变短，应改用 `CLOCK_MONOTONIC`（agent_main.c 的 `runtime_init` 已有 `pthread_condattr_setclock` 的写法可复用）。`sb_observability_evaluate` 的错误被 `NULL` 丢弃，评估连续失败时无任何记录，应至少限频记日志。
  - `sb_observability_check_token` 把 `68`、`4`、`64` 写成字面量，应由 `sizeof("sbm_") - 1 + 64` 推导，并与 `rotate_token` 的 `sb_random_hex(32)` 共用常量。
  - `kind` 在 Prometheus 输出里未经 `metric_label` 转义。其来源是内部固定的六种告警类型，当前安全，但依赖这一前提，应注释或统一转义。
  - 手写 `LIMIT 500`、`60`、`3600`、`86400`、`2000` 散落在多处；`hosts` 查询里 `(o.sampled_at/60)*60` 与 `sample` 里 `now / 60 * 60` 是同一桶宽的两份写法。
  - `sb_observability_hosts` 每行用子查询取一次 `offline_seconds`，可在外层取一次；`sbj_parse` 对空状态返回 NULL，靠 `sbj_get_str` 的 NULL 容忍，应注释。
  - 全文件一行多语句、SQL 为超长字符串，属于 W2；与其他文件同样存在 prepare、bind、finish 样板，适合用 S2 的方案收敛。
- 所有权：`hosts`、`alerts`、`label`、`resource`、`out` 均有释放或转移，已读路径上未发现泄漏。

### 覆盖状态
- 已读范围内仍无被证实的真实缺陷。待核实且优先：明文令牌存储的取舍（第 66 节）、本地 UI 登录无限速与默认监听 0.0.0.0（第 64.1 节）、裸机 SIGTERM 孤儿 sing-box（第 55/56 节，范围已收窄）。
- 仍未读：store.c 其余约 2400 行、http_server.c 与 http_routes_*.c 的处理器、wireguard.c 与 proxy_parser.c 其余部分、auth_oidc.c 其余、windows/ui-host、windows/tests。没有编译，没有运行任何测试、ASan 或 TSan。

## 73. 补读：http_routes_hosts.c 的 Agent 令牌鉴权与 handle_agent_config

以下均为阅读结论，未编译、未跑 ASan/TSan。已读 http_routes_hosts.c:860-915、986-1044。未读：managed_render_request（75 行）、agent_subscription_sources、sb_store_find_enabled_host_by_token 之外的鉴权调用点。

- agent_token / resolve_agent_host：只接受大小写敏感的 "Bearer " 前缀，空令牌返回 401。主机令牌通过 SQL 等值查询（store.c:2413）匹配，遗留全局 AGENT_TOKEN 则用 strcmp 比较（http_routes_hosts.c:892）。后者不是常量时间比较，而同一代码库里 agent_ui.c、observability.c、auth_oidc.c 都已使用 sb_consttime_streq / CRYPTO_memcmp。遗留令牌只在未命中主机令牌时才比较，且仅在配置了 AGENT_TOKEN 时存在，网络侧可利用性很低，但属于风格与安全做法不一致，建议改用 sb_consttime_streq，并补一条长度不同、前缀相同的用例。SQL 等值查询同样不是常量时间，是否值得改成哈希后查询属于第 66 节令牌存储取舍的一部分，不要单独改。
- 好的一面：令牌 trim 后判空、失败统一返回 Invalid agent token，不区分令牌不存在与主机被禁用。
- handle_agent_config（约 58 行）：goto done 单一清理点，host、profile、request、config、body、etag 均在 done 释放，304 分支把空体交给 sb_resp_text，body 在 200 分支转交后置 NULL，已读路径上未发现泄漏。
- 坏味道：
  - include_sources 分支（约 5 行）压成单行多语句，且在 goto 中途声明 sources、envelope，W2 风格；应拆成 build_agent_payload()。
  - 在一次 GET 里依次做渲染、touch_host、observability_target 两次写库，GET 有写副作用，需在注释写明（心跳语义）。
  - managed_render_request 带 provision_network_identity=true 参数，GET 配置拉取可能触发 WireGuard 身份分配与同步（sb_http_sync_wireguard_best_effort），布尔参数语义不清，应改枚举。
  - 字面量 "quickjs"/"profile"、"default"、7（Bearer 前缀长度）应命名并用 sizeof 推导；与 Windows 侧 fetch_config 的规则来源字符串是同一契约的不同副本。
  - ETag 以序列化后的 body 计算，含 sources=1 时 body 是信封而非配置本身，同一主机带与不带 sources 参数会得到不同 ETag；这是否与客户端缓存预期一致未读客户端代码，不下结论。

### 覆盖状态
- 已读范围内仍无被证实的真实缺陷。待核实且优先：明文令牌存储取舍（第 66 节）、本地 UI 登录无限速与默认监听 0.0.0.0（第 64.1 节）、裸机 SIGTERM 孤儿 sing-box（第 55/56 节，范围已收窄）。
- 仍未读：store.c 其余约 2400 行、http_server.c 与 http_routes_*.c 其余处理器、wireguard.c 与 proxy_parser.c 其余部分、auth_oidc.c 其余、windows/ui-host、windows/tests。没有编译，没有运行任何测试、ASan 或 TSan。

## 74. 收尾：阅读审计结束，转入整改（汇总）

本节标志只读审计阶段结束。继续逐文件补读的收益已经很低：第 27、37、51 节之后，已读范围内没有证实任何真实缺陷，多数疑点被后续核实撤销。后续不再追加“补读”章节，改为按下表整改，每项先补测试再改代码。

### 74.1 仍成立的待办（按优先级）

| 优先级 | 事项 | 出处 | 状态 |
| --- | --- | --- | --- |
| 高 | 本地 UI 登录无失败限速，默认监听 0.0.0.0，会话数组无上限 | 62、64.1 | 已核实的设计缺口 |
| 高 | agent_token 明文存储并用 SQL 等值查找；兑换不轮换 | 66 | 契约变更，需单独评审 |
| 中 | 遗留全局 AGENT_TOKEN 用 strcmp 比较，应改 sb_consttime_streq | 73 | 已读确认 |
| 中 | 裸机部署下 agent 被 SIGTERM 终止，sing-box 子进程成为孤儿 | 55、56 | 推断，未复现 |
| 中 | observability monitor_loop 用 CLOCK_REALTIME 的条件变量等待 | 72 | 已读确认 |
| 中 | S1–S9、W1–W8 的结构性整改（长函数、goto 样板、重复辅助函数、atoi、编译告警统一） | 1–6 | 按第 2、6 节顺序实施 |
| 低 | 魔法数字命名、历史注释改写、一行多语句格式化 | 各节 | 随 P2、P1.5 处理 |

### 74.2 已撤销的疑点（不要再作为缺陷）

sbw_traffic_record 判空（51）、ui_status 与 proxy_runtime 锁顺序（61）、save_device_credential 权限窗口（59）、foreign_keys 未启用（70）、persisted_state 覆盖键泄漏（24）、route_key 重复所有权（15.4）、plugin_storage 越界（9.1，现状安全）。

### 74.3 下一步

1. 先执行 P0：补特征测试与语句泄漏检查。
2. 高优先级两项（本地 UI 限速、令牌存储）单独出方案，不与重构混在一个变更里。
3. 整改前须确认 CONVENTIONS.md 的文件归属，避免与并行 agent 冲突。
4. 本文仍未编译、未运行任何测试、ASan 或 TSan；整改后需要重新扫描。

### 74.4 整改进度（2026-10-28）

改动都在 `C:\Users\cloudy064\.codex\worktrees\latest-review\sb-easy`（基于 8486f0b，未提交）。这台 Windows 机器没有 curl、libyaml 头文件，MinGW 也没有 `spawn.h`、`sys/socket.h`，所以**只对部分文件做过 gcc `-fsyntax-only`，没有链接，没有运行任何测试，没有 ASan/TSan**。

| 事项 | 改动 | 验证状态 |
| --- | --- | --- |
| 本地 UI 登录限速 | `agent_ui.c`：连续失败超过 10 次后指数退避 1s…60s，窗口内返回 429，成功后清零；全局计数，用时间戳而非 sleep | `agent_ui.c` 语法检查通过；新增 `agent_ui_login_backoff` 测试未运行 |
| 会话数上限 | `agent_ui.c`：上限 64，超出时淘汰最接近过期的会话 | 同上；新增 `agent_ui_session_cap` 测试未运行 |
| 默认监听 0.0.0.0 | 不改默认值（会破坏容器部署，违反 CONVENTIONS.md 的兼容约定）；`agent_main.c` 在非回环地址监听时向 stderr 打告警 | `agent_main.c` 无法在本机做语法检查（缺 `spawn.h`） |
| 遗留 AGENT_TOKEN 比较 | `http_routes_hosts.c`：`strcmp` 改为 `sb_consttime_streq` | 语法检查通过，未补长度不同/前缀相同的用例 |
| monitor_loop 时钟 | `observability.c`：改用 `CLOCK_MONOTONIC`，条件变量同时设置单调时钟属性 | 语法检查通过（mingw64 gcc） |
| 裸机 SIGTERM 孤儿 sing-box | `agent_main.c`：安装 SIGINT/SIGTERM 处理器（只置标志），`wait_for_work` 改为 1s 分片等待，收到信号后执行 `sb_agent_ui_free` + `runtime_free` 并返回 0 | 未编译，未测试；需要在 Linux 上补「发 SIGTERM 后 sing-box 子进程已退出」的测试 |

仍未做：agent_token 哈希存储与兑换时轮换（契约变更，需单独评审）；S1–S9、W1–W8 的结构性整改（按第 2、6 节顺序，先补测试）。更新：上述改动已提交到分支 `fix/agent-ui-hardening`（b069617）并推送，在 archlinux（`/work/workspace/github/sb-easy-verify`）上用 `-DSB_EASY_WARNINGS_AS_ERRORS=ON` 完整构建，`ctest` 27/27 通过；ASan/UBSan 构建下 agent_ui、observability、http_hosts、util、store 5 个测试通过，无报告。仍未验证：SIGTERM 后 sing-box 子进程确已退出（没有对应自动化测试，需补）；后续：`agent_sigterm_e2e`（commit 4893f63）在 archlinux 上通过，agent 收到 SIGTERM 后以 0 退出且受管 sing-box 子进程随之退出。全量并行 ASan 运行第一次出现 `config_renderer_test`、`store_test` 失败，串行重跑和随后的全量并行重跑（28/28）均通过，未复现，原因未查清，疑为并行负载下的偶发问题，已在 master（8486f0b）基线上做 3 轮并行 ASan 对照，均 27/27 通过，分支上也再未复现（后续并行 ASan 28/28），该次失败判定为偶发，原因未查清。TSan（archlinux，-fsanitize=thread，agent_ui、observability 两个测试）：分支与 master 基线表现一致，均报 civetweb 内部的 data race（mg_stop、mg_free、close_all_listening_sockets，由 sb_http_server_start/stop、sb_agent_ui_new/free 触发），属于原有问题；本次新增的限速、会话上限、信号处理代码未出现在竞争栈中。agent_sigterm_e2e 在 TSan 下通过。其余测试套件的 TSan 未跑，civetweb 竞争需单独处理（升级版本或加 TSan suppressions）。补充：commit 9ad9091 把 `http_routes_proxy_users.c` 里遗留 AGENT_TOKEN 的 `sb_streq` 也改为 `sb_consttime_streq`，archlinux 上 http_hosts、http_proxy、proxy_runtime、proxy_users 四个测试通过。令牌使用点（待做哈希存储时需同步修改）：store.c 的 new_agent_token、sb_store_rotate_agent_token、sb_store_find_enabled_host_by_token（SQL 等值查询）、兑换返回 hosts.agent_token（store.c 约 2326–2345）、http_routes_hosts.c 返回明文令牌（约 812、826、951 行）。

更新（令牌哈希阶段 1，commit 785f689）：迁移 019 新增 hosts.agent_token_hash，创建/轮换时写入哈希，查找先按哈希再回退明文，启动时回填；store_test 的迁移计数与临时迁移版本号已随之调整（18→19，临时版本 19→20）。archlinux 上 http_admin、http_hosts、proxy_users、store_test、control_plane_e2e 通过。并行 ASan 全量 28 项中仅 config_renderer_test 失败（断言 config != NULL，脚本渲染返回 NULL），串行 5 次与满载 5 次共 10 次均通过，推断为并行 ASan 下触及 QuickJS 50ms 截止时间的偶发问题，未证实，与本次改动无关。阶段 2、3 与兑换时轮换仍待决定，见 docs/agent-token-hashing-plan.md。

更新（S3/S4，分支 fix/agent-ui-hardening，commit 8b4b7b9）：新增 sb_hex_value 与 sb_parse_int_range（util.c/util.h），proxy_parser.c 复用前者；clash_websocket.c 三处 atoi 改为严格解析（端口 1-65535，状态码恰为 3 位且 100-599，以前宽松接受尾随垃圾）；json_string_is 提到 http_internal.h 作为 sb_json_string_is，两份签名不同的 json_value_string 有意保持分开；util_test 补 hex_value 与 parse_int_range 边界用例。archlinux 上 -Werror 构建后全量 ctest 28/28 通过。下一项：S2 的 sbq_stmt 语句辅助与 store.c 迁移，先补语句泄漏检查。

更新（S2 起步与稳定性，分支 fix/agent-ui-hardening，commit 139274a）：sqlite_internal.h 新增 sbq_stmt / SBQ_AUTO（粘滞绑定错误，cleanup 属性自动 finalize，仅限 c/，MSVC 的 windows/ 不可用）；sb_store_create_user 已迁移为首个使用方，store.c 其余 prepare/bind/finalize 样板尚未迁移。并行 ASan/全量 ctest 偶发失败（config_renderer_test、store_test、script_engine_test）均为默认 50ms QuickJS 截止时间在负载下触发，三个测试里使用默认限制的用例已改为 5s（生产默认不变）；之后 archlinux 上全量并行 ctest 连续 3 轮 28/28 通过。仍待办：S2 其余迁移、S1 长函数拆分、S5–S9、W1–W8、令牌哈希阶段 2/3 与兑换轮换（需契约决策）、TSan 全量（civetweb 内部竞争为原有问题）、合入 master/PR。

更新（S2，分支 fix/agent-ui-hardening，commit fee0caf）：store.c 中 create_user、update_wireguard_peer、create_wireguard_peer、proxy 节点 restore 已迁移到 SBQ_AUTO，手写 "finalize; goto done" 样板已清零；archlinux 上全量并行 ctest 28/28 通过，ASan 下 store_test、wireguard_test、http_proxy、proxy_users 通过。仍待办：store.c 其余 prepare/finalize 样板与 goto 计数下降、S1 长函数拆分、S5–S9、W1–W8、令牌哈希阶段 2/3 与兑换轮换（需契约决策）、TSan 全量、PR。

更新（S2 批量迁移，分支 fix/agent-ui-hardening，commit 94c9001 至 f6ac82a）：store.c 里 app_setting、host_exists、令牌哈希回填、delete_user、next_wireguard_address、profile/host/subscription/proxy 的 find 与 list、host_outbounds、host_commands、enrollment 创建与兑换、诊断报告、proxy 节点增改、upsert_one、import_display_tag、capture 与 wg import 列表、restore_subscription、restore_wireguard_peer、wg_snapshot_locked、read_nodes、wg_import_rollback 均已迁移到 SBQ_AUTO。手写 `sqlite3_finalize` 从 63 降到 3（`exec_stmt`、`exec_bound` 两个共享辅助函数，以及 `sb_store_render_request_for_host` 里的 host 语句，后者必须在 UNLOCK 之前 finalize，cleanup 属性会晚于解锁，故保留手写）；`goto done` 从 85 降到 70（基线 101，降幅约 31%，未达到 50% 目标，剩余的 goto 多数是锁与内存的统一出口，不是语句泄漏样板）。每个批次都在 archlinux 上验证：全量并行 ctest 28/28，ASan 下 store、http_admin、auth、wireguard、subscription 相关测试通过。

更新（S1 起步与 proxy_users.c 迁移，分支 fix/agent-ui-hardening，commit 4dc8fde 至 5ddcea6）：`sb_proxy_lease_exchange` 拆出 `validate_exchange_request`（校验与重复上报检查，错误消息与顺序不变）和 `save_lease_session`（会话 upsert），函数内其余语句改为 SBQ_AUTO；该函数的主体（宿主检查、重放/冲突判定、上报应用、快照构建）仍在同一函数内，尚未继续拆分。`proxy_users.c` 里手写 `sqlite3_finalize` 从 30 降到 0（run_id、runtime_report/ready、devices_locked、user_locked、users_list、user_save/remove/reset、claim、device create/revoke、node_locked、ingress list/save、report_locked、subscription、lease_locked 均已迁移；持有数据库锁的函数里语句放在独立块内，保证在 unlock 之前 finalize）。每批在 archlinux 上验证：全量并行 ctest 28/28，ASan 下 proxy、store、http_admin 相关测试通过。仍待办：`sb_proxy_lease_exchange` 主体继续拆分、其他长函数、S5–S9、W1–W8、令牌哈希阶段 2/3 与兑换轮换（需契约决策）、TSan 全量、PR。

更新（S2 收尾，分支 fix/agent-ui-hardening，commit 至 3d56fea）：auth_device_policy.c、auth_oidc.c、auth_security.c（496c98b）、observability.c（eefa3ce）、preferences_sync.c 与 proxy_clock.c（c46363e）、database.c（3d56fea）的手写 `sqlite3_finalize` 全部清零，语句改为 SBQ_AUTO；持有数据库锁的函数里语句放在独立块内，保证在 unlock、commit 或 rollback 之前 finalize；observability.c 的 `finish()` 改为只 step、不再 finalize。过程中 auth_oidc.c 的 `SBQ_AUTO d` 触发 -Wshadow（已改名为 `del`），并在验证命令里加入 `echo BUILD_OK`，避免旧二进制让 ctest 假通过。`c/src` 里剩余的手写 finalize 仅有 store.c 的 3 处（`exec_stmt`、`exec_bound`、`sb_store_render_request_for_host` 的 host 语句，均为有意保留）和 sqlite_internal.h 的 2 处辅助函数定义。每批均在 archlinux 上验证：-Werror 构建、全量并行 ctest 28/28，ASan 下 auth、store、http_admin、observability、preferences、proxy、control_plane 相关测试通过。S2 视为完成；仍待办：S1 长函数拆分、S5–S9、W1–W8、令牌哈希阶段 2/3 与兑换轮换（需契约决策）、TSan 全量、PR。

更新（S9 告警统一，分支 fix/agent-ui-hardening，commit cbc60e9 至 717e182）：CMake 新增 `sb_enable_warnings(target)`，对 sb_core、程序、测试、嵌入式 smoke 统一应用 `-Wall -Wextra -Wshadow`，`SB_EASY_WARNINGS_AS_ERRORS` 对全部目标生效；去掉 `-Wno-unused-parameter`，12 处确实未使用的回调参数（http_routes_admin.c、http_routes_hosts.c、wireguard.c、agent_core_test.c、http_core_test.c）以 `(void)x` 标注；`preferences_sync_test.c` 的 misleading-indentation 已拆行修正。每步在 archlinux 上验证：全量 -Werror 构建后 ctest 28/28。仍待办：`-Wformat=2`/`-Wconversion` 分阶段引入、clang-tidy 与 cppcheck 报告模式 CI、S1、S5–S8、W1–W8、令牌哈希阶段 2/3、TSan 全量、PR。

更新（S7 起步，分支 fix/agent-ui-hardening，commit d7beecf、a2f83ca）：proxy_users.c 的 `4102444740LL` 与 `4096` 命名为 `MAX_UNIX_TIME`、`MAX_EXCHANGE_REPORTS`；http_server.c 的 domain_stats 上限与 civetweb 的 keep-alive、请求超时、最大请求体命名为 `SB_HTTP_MAX_DOMAIN_STATS`、`SB_HTTP_KEEP_ALIVE_TIMEOUT_MS`、`SB_HTTP_REQUEST_TIMEOUT_MS`、`SB_HTTP_MAX_REQUEST_BYTES`，错误文案与数值不变。全量 -Werror 构建后 ctest 28/28，ASan 下 http_*、control_plane_e2e 6/6 通过。全仓四位以上数字字面量共 240 处（35 个文件），多数是合法用法（状态码、SQL、测试向量），其余需人工筛选，S7 仍在进行。

更新（S8，分支 fix/agent-ui-hardening，commit a9d5d91）：clash_websocket.c 的 `bridges`、http_server.c 的 `g_sink_owner` 与 `g_signal_pipe`、proxy_runtime.c 的 `native_owned`、proxy_clock.c 的 `registry` 旁均已写明保护它的锁与生命周期（`g_signal_pipe` 只在信号处理函数里 write，无锁；`registry` 按引用计数，最后一次 detach 释放）；仅加注释，没有改代码。-Werror 构建后全量 ctest 28/28。日志 sink 所有权测试 `log_sink_ownership` 已补（commit 2ed48fe）：最新创建的服务器接管 sink，释放所有者后其余服务器不再收到日志行；archlinux 上 -Werror 构建后 http_core_test 通过。S8 视为完成。

更新（S1 续，分支 fix/agent-ui-hardening，commit 4b93430）：`sb_proxy_lease_exchange` 里构建租约快照的部分（ingress 节点检查、runtime_ready、node_locked、用户租约循环）拆为静态函数 `build_lease_snapshot`，事务、数据库锁与回滚仍由调用方持有，语句顺序与错误消息不变。-Werror 构建后全量 ctest 28/28，ASan 下 proxy、store、http_admin、control_plane 7/7 通过。该函数现在由 `validate_exchange_request`、会话重放/冲突判定、`build_lease_snapshot`、`save_lease_session` 组成；重放/冲突判定已在 commit 79eac8b 拆为 `check_lease_session`（返回 0 新请求、1 精确重放并带出已存快照、-1 序号冲突/存档快照无效/数据库错误，查询、错误消息与判定顺序不变），-Werror 构建后全量 ctest 28/28，ASan 下 proxy、store、http_admin、control_plane 7/7 通过；`sb_proxy_lease_exchange` 主体现在只剩宿主检查、上报应用与事务收尾。

更新（S6 起步，分支 fix/agent-ui-hardening，commit 02b2e40 与 4f8a1ec）：store.c 的 `validate_proxy` 与 `fingerprint_of` 由 8 个 (指针, 长度) 参数改为接收 `const sb_proxy_record *`，三处调用方同步；`upsert_one` 持有的是 `sb_parsed_node`，在函数内构造一个 `sb_proxy_record` 视图再传入。教训：02b2e40 在 archlinux 上编译失败（upsert_one 类型不符），但验证命令里的 `tail` 吞掉了失败，旧二进制让 ctest 28/28 假通过；4f8a1ec 修复，并把验证命令改为构建失败即 `BUILD_FAILED` 退出，不再运行 ctest。修复后全量 ctest 28/28，ASan 下 store、proxy、http_admin、subscription、control_plane 8/8 通过。仍待办：sbq_bind_text_n、sb_json_assign_string_n 等 (ptr, len) 接口的值类型化（需先评估公开头文件兼容性）、S5 大文件拆分、W1–W8、令牌哈希阶段 2/3、-Wformat=2/-Wconversion、clang-tidy/cppcheck、TSan 全量、PR。

更新（S5 起步，分支 fix/agent-ui-hardening，commit dbe24b0）：store.c 末尾的 wg-easy 迁移部分（预览、受保护的应用、回滚，共 246 行）纯移动到新文件 store_wg_import.c；新增私有头 store_internal.h，放 `struct sb_store`、`S/LOCK/UNLOCK/H` 宏、`WIREGUARD_PEER_SELECT`，并把两边共用的 `parse_object_col`、`read_wireguard_peer`、`dump_checked`、`settings_upsert_sql`、`bind_dump`、`exec_bound`、`restore_peer` 由 static 改为外部链接（只在私有头里声明，不进公开头）。store.c 由 3626 行降到 3408 行。

更新（S5 续，分支 fix/agent-ui-hardening，commit 758c40f）：store.c 末尾的抓包存储（save/list/get/delete capture，共 91 行）纯移动到 store_captures.c，`exec_stmt` 由 static 改为外部链接并在 store_internal.h 声明；store.c 降到 3317 行。

更新（S5 续，分支 fix/agent-ui-hardening，commit 7c4ed69）：store.c 中的主机命令队列（enqueue/list/acknowledge，共 87 行）纯移动到 store_host_commands.c；`COMMAND_SELECT`、`VEC_APPEND_MOVE`、`FINISH_LIST` 三个宏移入 store_internal.h，`host_exists` 与 `read_host_command` 由 static 改为外部链接并在私有头声明；store.c 降到 3207 行。

更新（S5 续，分支 fix/agent-ui-hardening，commit 3c110ef）：store.c 中的订阅存储（find/list/create/update/delete、record_fetch、apply_fetch、record_failure，共 220 行）纯移动到 store_subscriptions.c；`SUBSCRIPTION_SELECT` 移入 store_internal.h，`strvec_to_json`、`read_subscription`、`exec_changes`、`upsert_one` 由 static 改为外部链接并在私有头声明；store.c 降到 2982 行（起点 3626）。

更新（S5 续，分支 fix/agent-ui-hardening，commit 544b3c2）：store.c 中的 agent 注册与令牌查找（create/redeem enrollment、find_enabled_host_by_token、touch_host、update_agent_status，共 221 行）纯移动到 store_enrollment.c；`HOST_SELECT` 移入 store_internal.h，`parse_object_or_empty`、`read_host`、`new_agent_token` 由 static 改为外部链接并在私有头声明；store.c 降到 2753 行（起点 3626，累计减少约 24%）。

更新（S5 续，分支 fix/agent-ui-hardening，commit 85a05e0）：store.c 中的代理节点存储与延迟更新（update_proxy_latencies/latency、find/list/create/update/delete proxy node、import_display_tag、upsert_one、upsert_proxy_nodes，共 426 行）纯移动到 store_proxies.c；PROXY_SELECT 移入 store_internal.h，read_proxy_record、validate_proxy、fingerprint_of 由 static 改为外部链接并在私有头声明；store.c 降到 2321 行（起点 3626，累计减少约 36%）。构建命令带失败即停检查，-Werror 构建后全量 ctest 28/28，ASan 下 store、proxy、subscription、http_admin、control_plane 8/8 通过。store.c 现已拆出 store_wg_import.c、store_captures.c、store_host_commands.c、store_subscriptions.c、store_enrollment.c、store_proxies.c。

更新（S5 续，分支 fix/agent-ui-hardening，commit f5056cf）：store.c 中的 WireGuard 对端与一次性链接（find/list/create/update/delete/set_enabled peer、next_wireguard_address、create_one_time_link，共 219 行）纯移动到 store_wireguard.c；备份导出与恢复（export_backup、restore_subscription、restore_node、restore_backup）仍留在 store.c，因为它们依赖更多私有辅助函数。移动前脚本校验 find_peer_locked 与 reload_peer 在被移动范围之外没有其他引用。store.c 降到 2101 行（起点 3626，累计减少约 42%）。

更新（S5 续，分支 fix/agent-ui-hardening，commit aa67e63）：store.c 中的配置档、主机、诊断报告与主机出站（find/list/create/update/delete profile 与 host、save/list diagnostic report、host_outbounds、rotate_agent_token，共 446 行）纯移动到 store_hosts.c；PROFILE_SELECT 移入 store_internal.h，read_profile、jv_str、find_profile_locked 由 static 改为外部链接并在私有头声明（render_request 仍在 store.c 使用 find_profile_locked）。store.c 降到 1650 行（起点 3626，累计减少约 54%）。

更新（S5 续，分支 fix/agent-ui-hardening，commit 5da9828）：store.c 末尾的渲染请求组装（sb_store_render_request_for_host，共 101 行）纯移动到 store_render.c；`controller_address`、`read_nodes` 由 static 改为外部链接并在 store_internal.h 声明。store.c 降到 1554 行（起点 3626，累计减少约 57%）。构建命令带失败即停检查，-Werror 构建后全量 ctest 28/28，ASan 下 store、http_hosts、http_proxy、config_renderer、http_admin、control_plane 6/6 通过。store.c 现已拆出 9 个文件：store_wg_import.c、store_captures.c、store_host_commands.c、store_subscriptions.c、store_enrollment.c、store_proxies.c、store_wireguard.c、store_hosts.c、store_render.c。

决定（S5，proxy_parser.c 暂不拆）：apple/CMakeLists.txt、apple/project.yml、windows/CMakeLists.txt 与 apple.yml 的路径过滤都按文件名显式列出 c/src/proxy_parser.c，Apple 构建还对该文件单独定义 __APPLE__。拆分必须同步修改这些构建文件，而它们无法在 archlinux 上验证，因此留待能构建 Apple 与 Windows 的环境再做。

更新（S5 续，http_server.c，分支 fix/agent-ui-hardening，commit 5e8aad0）：http_server.c 里的托管自管 sing-box 循环（self_singbox_render/main/start/request_stop/join、capability_flag、stop_requested，共 198 行）纯移动到 http_self_singbox.c；self_singbox_start、self_singbox_request_stop、self_singbox_join 由 static 改为外部链接并在 http_internal.h 声明，http_server.c 里两处前向声明已删除。http_server.c 由 2547 行降到 2359 行。构建命令带失败即停检查，-Werror 构建后全量 ctest 28/28，ASan 下 http、control_plane、singbox_supervisor、proxy_runtime 8/8 通过。决定（http_server.c 静态文件/SPA 段暂不拆）：该段（约 325 行）依赖 wire_response、http_exchange、M_* 方法常量和约 8 个 wire_* 辅助函数，都是 http_server.c 的 static。要拆必须先把这些类型与辅助函数提到 http_wire.h，这已不是纯移动，需单独一次改动。仍待办：http_wire.h 抽取后再拆静态文件、store.c 剩余部分。

更新（S5 续，wireguard.c，分支 fix/agent-ui-hardening，commit b6eb9cd）：wireguard.c 末尾的内核接口部分（create_directories、write_server_config、sync、startup、shutdown、remove_peer，共 156 行）纯移动到 wireguard_kernel.c；新增私有头 wireguard_internal.h，放 `struct sb_wireguard`、`S` 宏，并把 `run`、`subnet_cidr` 由 static 改为外部链接。确认没有其他构建文件按名列出 wireguard.c（仅 Linux glob）。wireguard.c 由 1325 行降到 1165 行。构建命令带失败即停检查，-Werror 构建后全量 ctest 28/28，ASan 下 wireguard、wg_migration、store、http_admin、control_plane 5/5 通过。

决定（S6，(ptr,len) 接口）：sbq_bind_text_n、sb_json_assign_string_n 等 _n 变体共 53 处，几乎都是结构体里相邻的 `name`/`name_len` 字段（store_hosts.c 占 21 处），而且 sb_host 等结构体在公共头 include/sb/store.h 中。引入 span 类型会改公共结构体布局和头文件，违反接口不变的约束，对安全性收益很小，所以不改。长度字段与指针成对出现，并带有 NUL 字节测试（control_plane_e2e 覆盖）。保持现状。

更新（S9 续，implicit-widening-of-multiplication-result 复核）：对 30 条告警逐行抽查（auth_security.c、http_routes_agent.c、http_routes_proxy_users.c、http_self_singbox.c、store_captures.c、preferences_sync.c、agent_client.c、proxy_runtime.c、clash_websocket.c 等），乘法的两个操作数都是编译期常量或宏限额（如 1024 * 1024、128*1024*1024、768*1024），不含运行时输入，不会溢出。结论：无真实缺陷，不改代码，该检查保持报告模式。

更新（S9 续，clang-tidy 高价值项复核）：逐项读了 unchecked-string-to-number（util.c 三处 sscanf，返回值均已检查）、not-null-terminated-result（clash_websocket.c close 帧载荷是二进制，不需要结尾 NUL）、suspicious-string-compare（5 处，均为有意的 !strcmp / strcmp 条件写法）、narrowing-conversions（observability.c 的 int64 转 double 延迟阈值、proxy_parser.c 的 ASCII 字符 int 转 char）、misplaced-widening-cast（preferences_sync.c 已在 02d0914 修复）。结论：没有真实缺陷，不改代码，也不把这些检查转为阻塞。其余 widening-of-multiplication、multi-level-pointer-conversion、macro-parentheses、assignment-in-if-condition 属风格类，保持报告模式。

更新（W7，分支 fix/agent-ui-hardening，commit a7c27db）：windows/tests/core_process_test.c 里 283 行的 wmain 拆成 14 个 scenario_* 函数，共享状态放进 test_state 结构体，用场景表顺序执行，失败时打印场景名；场景内容与顺序不变。第一次编译被 /W4 /WX 拦下（两个场景多声明了未使用的 exit_code），已修正。验证：默认 Windows 构建链接成功，clang-format 干净，windows_core_process 通过，ctest 35/36（唯一失败仍是改动前就存在的 windows_plugin_sandbox）。其余入口见下一段。

更新（W7 续，分支 fix/agent-ui-hardening，commit a6c8b09、27fd03f、198b0ca、d3b2697、bcff49c）：按同样方式拆完其余五个测试入口。secure_store_test.c 拆成 7 个场景（a6c8b09）；routing_groups_test.c 的 192 行 main 拆成 7 个场景（27fd03f）；connection_test.c 的 203 行 wmain 拆成 6 个场景（198b0ca）；runtime_config_test.c 的 wmain 拆成 8 个场景，CHECK 改为返回 false 并打印失败的场景名，done: 清理块保持不变（d3b2697）；apple/Tests/core_test.c 的 115 行 main 拆成 7 个场景，并把重复的拒绝检查提成小函数（bcff49c）。断言、夹具与顺序不变。验证：Windows 默认构建链接成功，windows_routing_groups、windows_connection、windows_runtime_config 通过，ctest 35/36（唯一失败仍是改动前就存在的 windows_plugin_sandbox）；Apple core_test 在 archlinux 上普通构建和 ASan/UBSan 下 apple_core_contract 均通过。W7 至此完成。

更新（parse_port 回归用例，分支 fix/agent-ui-hardening，commit cad1069）：windows/tests/capture_test.c 新增用例，向 sbw_capture_observe 传入空串、0、65536、带符号、带尾随文本的端口，只应保留两条合法 flow；为此在 capture.c/capture.h 增加只读测试接口 sbw_capture_test_flow_count（加锁读取 flow_count，不改变行为）。验证状态：未运行。windows_capture_test 只在 SB_EASY_BUILD_CAPTURE_EXTENSION=ON 时构建，需要 build/capture-deps（libpcap、WinDivert），本机没有，WinDivert 压缩包又被 Defender 拦截，我没有绕过。只确认了 capture_test.c 通过 MSVC /Zs /W4 /WX 语法检查；capture.c 因缺少 pcap.h 无法编译检查，新断言（预期保留 2 条）的实际结果未知。默认 Windows 构建 ctest 仍是 35/36，该用例不在其中。待办：在有 capture-deps 的环境里跑一次 windows_capture。

更新（W6 起步，分支 fix/agent-ui-hardening，commit 3ef4f81）：update_transaction.c 的 sbw_update_helper_main（259 行，goto 事务流）只抽出三个无副作用的判断函数：job_rejected（job 文件校验）、health_confirms（健康确认，两处共用）、service_binary_trusted（服务二进制签名校验，顺带删掉不再需要的 installation 变量）。goto 主流程、journal 顺序与错误码不变。验证：默认 Windows 构建链接成功，windows_update_files、windows_update_version 通过，ctest 35/36（唯一失败仍是 windows_plugin_sandbox）。该函数要求已安装的 SYSTEM 服务，没有任何测试会执行它，所以抽出的代码只经过编译器检查。主流程本身没有拆：在没有运行时验证的情况下重写这条更新与回滚的安全路径风险大于收益。

更新（W6 续，分支 fix/agent-ui-hardening，commit 04f7110）：route_probe.c 的 sbw_route_probe（187 行）把响应组装（url、状态、耗时、错误码、evidence 与关联日志）抽成 probe_result，接管 observed 的所有权；WinHTTP 流程、goto 结构、清理顺序与输出 JSON 不变。验证：默认 Windows 构建链接成功，windows_route_probe 通过，ctest 35/36（唯一失败仍是 windows_plugin_sandbox）。

更新（W6 续，分支 fix/agent-ui-hardening，commit 2f8cf35）：subscription_parser.c 的 sbw_subscription_parse（139 行）按输入格式拆成 import_json_nodes、import_yaml_nodes、import_uri_lines 三个函数，并用共享的 node_from_import 替换两处重复的节点构造；节点上限、告警、跳过计数、错误文案与 SecureZeroMemory 清理不变。验证：默认 Windows 构建链接成功，windows_subscriptions 通过，ctest 35/36（唯一失败仍是 windows_plugin_sandbox）。

更新（W6 续，分支 fix/agent-ui-hardening，commit de1b28c）：subscriptions.c 的 fetch_run（135 行）只抽出 fetch_target（URL 拆解：协议检查、拒绝内嵌凭据、宽字符 host 与 path+query、端口与 TLS 标志）。WinHTTP 流程、goto 清理与错误码不变。验证：默认 Windows 构建链接成功，windows_subscriptions 通过，ctest 35/36（唯一失败仍是 windows_plugin_sandbox）。没有任何测试会执行 fetch_run 本身（需要联网下载），所以抽出的代码只经过编译器检查。

更新（W6 续，分支 fix/agent-ui-hardening，commit e317ea0）：controller.c 的 sbw_controller_background_tick 抽出两段自包含代码：kill_switch_refresh（每 5 秒复查防泄漏规则并在缺失时恢复）和 report_status_to_center（向中心上报状态，cycle_error 改为指针传入）。加锁顺序、goto done 流程、错误传播与上报字段不变，diff 已逐行核对。验证：默认 Windows 构建链接成功，windows_controller 通过，ctest 35/36（唯一失败仍是 windows_plugin_sandbox）。主体（网络变化重连、恢复、订阅刷新、同步周期）未拆。

更新（W6 续，分支 fix/agent-ui-hardening，commit 83cac66）：controller.c 的 connection_activate 抽出 activation_commit（成功路径下把已启动并已持久化的配置发布为 active / last-good，next 改为指针传入）和 stop_failed_core（启动失败后的核清理，含 TUN 强制停止检查与合并后的失败文案）。锁范围、回滚流程、错误码与文案不变，diff 已逐行核对。验证：默认 Windows 构建链接成功，windows_connection、windows_controller 通过，ctest 35/36（唯一失败仍是 windows_plugin_sandbox）。回滚段（rollback 的 prepare/preflight/launch）未拆。

更新（W6 续，分支 fix/agent-ui-hardening，commit b291fdc）：control_plane.c 的 parse_server 抽出 valid_dns_host（DNS 主机名校验）和 canonical_path（路径段规范化）。canonical_path 返回 1 表示路径非法（原 goto invalid），返回 -1 表示错误已设置（原 goto done），两个出口行为与原来一致；接受与拒绝的输入、错误码、规范化输出不变，diff 已逐行核对。第一次构建因 canonical 已是指针却仍写 &canonical 被 /W4 /WX 拦下，已修正。验证：默认 Windows 构建链接成功，windows_control_plane 通过，ctest 35/36（唯一失败仍是 windows_plugin_sandbox）。W6 列出的七个长函数至此都已处理（部分只抽出自包含片段，主体未拆）。

更新（W1 起步，分支 fix/agent-ui-hardening，commit 1325217）：controller.c 的 sbw_controller_dispatch 把最长的两个分支抽成 routing_set_handle（routing.set）和 routing_gpt_handle（routing.gpt_default/server/node）。两个函数各自保留 goto done 与 new_identity 的清理，加锁、实时切换回滚、错误码与文案不变。第一次执行时同一脚本被重复发送，导致函数重复定义（C2084），已用 git checkout 恢复后只执行一次。验证：默认 Windows 构建链接成功，windows_controller、windows_connection、windows_routing、windows_routing_groups 通过，ctest 35/36（唯一失败仍是 windows_plugin_sandbox）。未做：dispatch 的方法分发表等其余分支仍在原函数中。

更新（W1 续，分支 fix/agent-ui-hardening，commit fce1fb1）：controller.c 的 sbw_controller_dispatch 再抽出 updates_handle（updates.*）、enrollment_apply_handle（enrollment.apply）和 enrollment_forget_handle（enrollment.forget）。三个函数体与原分支逐行一致（diff 已核对），goto done 以及 new_identity、enrollment target 的清理随分支搬进各自函数，加锁、持久化顺序、错误码与文案不变。验证：默认 Windows 构建链接成功，windows_update_files、windows_update_version、windows_connection、windows_controller 通过，ctest 35/36（唯一失败仍是 windows_plugin_sandbox）。updates.health 与 enrollment.apply 没有端到端测试覆盖，只经编译器和现有控制器测试把关。仍未做：方法分发表（method 字符串到处理函数的表）。

更新（TSan 完整运行，archlinux，commit 1294b5e）：用 -fsanitize=thread 构建 c/ 并跑全部 ctest，12 个 HTTP 相关测试失败（agent_ui、http_admin、http_core、http_hosts、http_proxy、http_security、observability、preferences_sync、proxy_runtime、proxy_users、subscription_service、wg_migration），共 43 条 data race 报告。逐条归类：86 个访问帧中 81 个直接在 civetweb 内（consume_socket、mg_stop、master_thread_run、worker_thread），其余 5 个栈顶是 free 的拦截帧，完整栈显示另一侧是 civetweb master 线程在 close_all_listening_sockets 释放监听端口数组，对端是主线程在 mg_start2 之后立即调用一次 mg_get_server_ports（http_server.c:1426、agent_ui.c:1003）。该读取发生在 mg_stop 之前很久，实际不并发；TSan 报告是因为 civetweb 使用自带的 volatile 标志同步，TSan 看不到先后关系。结论：没有发现我们自己数据结构上的竞争，全部是 civetweb 内部或其 API 的误报/已知问题，不改代码。未做：没有给 TSan 加 suppression 文件，因此这 12 个测试在 TSan 构建下仍会失败；这是已知限制，不是回归。

更新（/analyze 复核，分支 fix/agent-ui-hardening，commit 9edc33d）：SB_EASY_ANALYZE=ON 构建得到 53 条唯一告警。已处理 3 条：update_transaction.c 与 server_identity.c 的 QueryServiceConfigW 先探测缓冲区大小的调用加 (void) 标明有意忽略返回值；capture_proxy.c 的 sbw_capture_configure 在写 c->enabled 前补 c 非空判断。其余已逐条看过，不改：SDK 头文件的 SAL 注解告警（wincrypt.h、winreg.h、ws2tcpip.h）、C6262 栈用量提示、tests/ 下仅测试用的句柄判空、proxy_parser.c 的 intro 缓冲区告警（unget 次数不超过已读入字符数，used 不会为负）、subscriptions.c:737 的移位（最多左移 6 位，不会溢出）。core_process.c、updater.c、update_files.c 中 "句柄可能为 0" 的几条（C6387）后来已逐条核对：sbw_secure_directory_file 所有失败路径都返回 INVALID_HANDLE_VALUE，从不返回 NULL，updater.c:582/584 与 update_files.c:92 的 CloseHandle 前都有 != INVALID_HANDLE_VALUE 判断；core_process.c 的 check.process / child.process 只在 launch() 成功后使用。结论为误报，不改代码。验证：clang-format 干净，默认 Windows 构建链接成功，ctest 35/36（唯一失败仍是 windows_plugin_sandbox）。

更新（W1 续，分支 fix/agent-ui-hardening，commit 1294b5e）：controller.c 的 sbw_controller_dispatch 再抽出 extensions_handle（extensions.*）和 traffic_handle（traffic.snapshot/clear）。调用方仍负责加锁与释放，处理函数只返回结果，提前返回路径不再重复写释放；sbw_fail 只写调用方的 error，不碰受保护状态，所以先释放锁再 sbw_fail 与现在的顺序等价。diff 已逐行核对，错误码与文案不变。第一次脚本因切片边界算错把文件改坏（编译失败），已用 git checkout 恢复后重写。验证：默认 Windows 构建链接成功，windows_traffic、windows_extension_store、windows_connection、windows_controller 通过，ctest 35/36（唯一失败仍是 windows_plugin_sandbox）。

更新（W1 续，分支 fix/agent-ui-hardening，commit c77acc4）：controller.c 的 sbw_controller_dispatch 再抽出 connection_handle（connection.start/stop）、subscriptions_fetch_handle、subscriptions_import_handle（import/refresh）和 identity_change_handle（subscriptions.save/remove 与 routing.group_save/remove）。函数体与原分支逐行一致（diff 已核对），new_identity 的清理随分支搬进各自函数，加锁、错误码与文案不变。验证：默认 Windows 构建链接成功，windows_subscriptions、windows_connection、windows_controller 通过，ctest 35/36（唯一失败仍是 windows_plugin_sandbox）。

更新（W5，分支 fix/agent-ui-hardening，commit a3bba34）：apple/Core/core.c 的 sba_build_runtime 把 tun_tag、names、leafs 提前声明并初始化为空，bad: 成为唯一清理点，删除了每个失败分支里手写的 free 组合（27 处），成功路径的 3 处提前释放保留并置空以避免重复释放。输出 JSON 与错误文案不变。验证在 archlinux 上完成：apple/ 的 -Werror 构建通过，apple_core_contract 1/1，ASan/UBSan 加泄漏检测下同样通过。未做：build_ctx 结构体与 validate_inputs 等阶段函数的完整拆分、魔法数字命名常量、core_test.c main 的用例拆分，这些不改变清理行为，留待后续。

更新（W5 续，分支 fix/agent-ui-hardening，commit 5bea484）：apple/Core/core.c 的 sba_build_runtime 再抽出两个阶段函数：add_control_host_rules（控制服务器直连与 bootstrap DNS 规则）和 set_platform_sections（TUN、log、cache 段）。tun_tag 的所有权与 bad: 清理路径仍在 sba_build_runtime 内，生成的 JSON 不变，diff 已逐行核对。验证在 archlinux 上完成：普通构建与 ASan/UBSan 下 apple_core_contract 均通过。仍未做：build_ctx 结构体、validate_inputs 等其余阶段的拆分。

更新（W5 续，分支 fix/agent-ui-hardening，commit 00e486a）：apple/Core/core.c 把 15 处裸数字限额（32/256/512）换成 SBA_MAX_* 具名常量（嵌套深度、节点 tag、outbound tag、每订阅节点数、订阅数、outbound 总数、endpoint 数、本地分组数、分组域名数、rule set 数），常量集中定义在文件顶部，数值不变；脚本对每处替换都断言只匹配一次。

更新（clang-tidy 复核续，archlinux，commit 00e486a）：重跑 clang-tidy 仍是 380 条。本轮读了 clang-analyzer 的几处：agent_client.c:218/224（unix.Malloc“重复释放”）各提前返回路径只释放一次 origin/prefix，判为误报；clash_client.c:83（“释放后使用”）失败路径释放后立即返回，成功路径不释放，判为误报；json.c:319/337（NullDereference）found 为真意味着对象非空，vals 不会为空，判为误报。以上只是读代码得出的判断，没有用其他工具交叉验证。其余 clang-analyzer 发现（agent_clash.c、agent_config.c、agent_main.c、clash_websocket.c、http_routes_observability.c、http_routes_proxy.c、http_server.c、main_server.c、proxy_users.c、util.c、wireguard.c 等）这一轮尚未逐条读，不能当作已排除；202 条 DeprecatedOrUnsafeBufferHandling 与其余风格类检查保持报告模式。

更新（clang-tidy 复核续）：读了 agent_main.c:1199/1207/1306 与 agent_clash.c:919/926 的 NullDereference/NonNullParam，并核对 value_string 的契约（agent_main.c:221、agent_clash.c:118）：成功返回时 *out 要么是调用处传入的字符串字面量 fallback，要么是 sbj_is_string 为真的 found->v.str.ptr，均非 NULL；判为分析器看不到契约造成的误报。http_routes_observability.c:45 在 number() 成功后 id 已赋值，判为误报；proxy_users.c:374 的 rc 在 377 行被覆盖，是无害的死存储。以上同样只来自读代码。本轮又读了 agent_main.c:427、main_server.c:70（括号后下标均已被 index+2 <= size / at+1 < len 的检查限定）、http_server.c:293（pos < len 保证）、util.c:152（sb_buf_append 先扩容再写）、util.c:505（fread 循环后检查 ferror 再 fclose），判断为误报，同样只来自读代码。仍未读：clash_websocket.c:195/196/252、agent_config.c、http_routes_proxy.c:150（需确认 request_clash 成功时已初始化 response）、util.c:322/370、wireguard.c:224/596、json.c:127，不能当作已排除。

更新（clang-tidy 复核收尾）：以上"仍未读"的几处现已读完，均判为误报，不改代码。clash_websocket.c:195/196 在 sb_starts_with 为真之后才做 base+7/+8，base 非空；:252 的 t.p 在 drogon_url_encode 之后由 sb_buf_append 保证非空。http_routes_proxy.c:150 的 request_clash 入口先把 out->status/body 置零，失败路径返回非零，成功才走到 sb_resp_json。util.c:322 的 sb_hex_encode 分配 n*2+1，下标不越界；util.c:370 的 sb_url_encode 遍历到 NUL 为止。wireguard.c:224 的 slash 已判非空；:596 的 fields/lengths 受 count < 8 限定。json.c:127 在 cap 为 len 的前提下按 len+1 分配并拷贝，len 为 0 时循环不执行。agent_config.c:168/279/297 后来已读：均在 value_string 成功后才 strcmp，agent_config.c:49 的 value_string 成功时 *out 为字面量 "" 或非空字符串指针，判为误报。agent_clash.c:1074 后来已读：destination.host 来自 parse_url，成功返回前 887 行已拒绝空主机名，out->host 为非空分配字符串，判为误报。至此本轮列出的 clang-analyzer 高价值发现均已读过，没有真实缺陷（判断均来自读代码）。

更新（clang-tidy 复核，202 条 DeprecatedOrUnsafeBufferHandling）：按函数分布为 memset 121、memcpy 26、snprintf 19、memmove 15、fprintf 15、vsnprintf 3、sscanf 3。该检查对所有带长度参数的标准函数给出同一句建议（改用 C11 Annex K 的 _s 版本），而 Annex K 在 glibc 等主流平台上不可用，不是可移植的修复方式，因此不改代码，保持报告模式。注意：这 202 处调用点我没有逐条读过，结论只来自函数分布和检查项性质，不代表每个调用点都核对过。结论：已读过的 clang-analyzer 发现没有真实缺陷，但这批并未全部读完；202 条 DeprecatedOrUnsafeBufferHandling 及风格类检查保持报告模式。以上判断均来自读代码，未用其他工具交叉验证。验证在 archlinux 上完成：普通构建与 ASan/UBSan 下 apple_core_contract 均通过。

更新（W2、W4、W8 CI，分支 fix/agent-ui-hardening，commit 213fdd1、26ed207、823520a、1d8d123）：W2 已对 windows/ 的 113 个 .c/.h 做纯格式化（213fdd1，新增 windows/.clang-format，ColumnLimit 100、禁止单行 if/循环/块，SortIncludes: Never，因为 Windows 头文件有顺序依赖，根 .clang-format 不动），hash 记入 .git-blame-ignore-revs（26ed207），使用前需执行 git config blame.ignoreRevsFile .git-blame-ignore-revs。格式化后默认构建链接成功，ctest 35/36（唯一失败仍是改动前就存在的 windows_plugin_sandbox）。Windows CI 新增 clang-format --dry-run -Werror 检查（823520a），本机对全部文件预跑 0 个不干净。W4：wide_copy 统一为 sbw_wide_copy（1d8d123，两处重复定义删除，8 处调用改名）；Windows 侧已无重复 hex 辅助函数。决定（W4 其余不合并）：base64 三份实现（plugin_catalog.c 的严格解码加重新编码比对、preferences.c 的编码与解码、c/src/util.c）在填充与非法字符上的行为各不相同，且 Windows 目标不链接 util.c，合并要搬 util.c 的实现并逐项核对，涉及插件签名与偏好归档的安全解码路径，收益只是少几十行，不值得；URL 解析（control_plane.c 的 parse_server 带 secure/prefix 语义，route_probe.c 的 parse_url 用于探测）返回结构与允许的 scheme 不同，合并等于重写，不做。

更新（W8，分支 fix/agent-ui-hardening，commit 5c7776d）：windows/CMakeLists.txt 新增选项 SB_EASY_ANALYZE（默认 OFF）。打开后给所有 Windows 目标加 /analyze，并且不加 /WX，只报告不失败；默认发行构建完全不变（关闭时重跑默认构建，链接成功，ctest 35/36，唯一失败仍是 windows_plugin_sandbox，与改动前一致）。开启后 sb_windows_controller 库编译通过，报告 44 条 C6xxx 告警，尚未逐条复核。W8 的另一半（CI 里把 /WX 设为必选、加入 clang-format 检查）依赖 W2 的整体格式化，未做。

更新（Windows 验证，分支 fix/agent-ui-hardening，commit d23138f、aa25733）：在本机（Windows 11、VS 2026 MSVC 14.50、Ninja）用 windows/scripts/build.ps1 跑了默认构建（-SkipUi 复跑；Python 用 uv 的 3.13，OpenSSL CLI 用 cmder 自带的 Git for Windows，只改了当前会话的 PATH）。发现并修复一处回归：bf0418b 让 proxy_parser.c 调用 util.c 里的 sb_hex_value，而 Windows（以及 Apple）构建只编译 proxy_parser.c、不链接 util.c，导致 sb-easy-service 和全部测试链接失败（LNK2019）；d23138f 让 proxy_parser.c 的 hex_value 重新自包含。修复后默认构建链接成功，ctest 35/36 通过，Linux 侧 28/28 不变。唯一失败的 windows_plugin_sandbox（创建 AppContainer profile 时 HRESULT 0x80070005）在 bf0418b 之前的提交 af17d79 上同样失败（用临时 worktree 对照，已删除并 prune），属本机权限问题，不是本次改动引入。W3：capture.c 的 atoi 端口解析改为严格的 parse_port（空串、非数字、0、超过 65535 的流直接丢弃，不再截断），aa25733。capture.c 只在可选的捕获扩展里编译，默认发行构建不受影响；本机 Defender 拦截了 WinDivert-2.2.2-A.zip（Get-FileHash 被判含病毒或潜在垃圾软件），没有改 Defender 设置，所以带捕获扩展的完整构建未在本机编译，parse_port 用 MSVC /W4 /WX 单独编译并通过 12 个边界用例（0、65536、70000、abc、空串、-5、80x、前导空格、溢出等）。回归用例尚未加入 capture_test.c。

更新（S9 续，CI 报告模式，分支 fix/agent-ui-hardening，commit 13a12f2）：新增 .github/workflows/c-static-analysis.yml，clang-tidy（bugprone-*、clang-analyzer-*，排除 easily-swappable-parameters）与 cppcheck 以报告模式运行（continue-on-error，只上传报告，不阻塞 CI）。在 archlinux 上用同一条 clang-tidy 命令试跑，共 380 条告警：multi-level-implicit-pointer-conversion 58、implicit-widening-of-multiplication-result 30、macro-parentheses 26、assignment-in-if-condition 13，其余各 4 条及以下。cppcheck 在 archlinux 上未安装，该步骤未试跑，只在 CI 里首次运行。这 380 条尚未分类处理，先按高价值检查（widening、narrowing、unchecked-string-to-number、not-null-terminated-result）逐项复核，再决定是否转为阻塞。

更新（S9 与令牌，分支 fix/agent-ui-hardening，commit 0846020、4ff43bf、2357b8b、10394d6、02d0914）：共享警告策略加入 -Wformat=2 与 -Wconversion。-Wformat=2 在项目代码里只有 util.c 的 fmt_utc 一处 -Wformat-nonliteral（只接收字面量格式，用局部 pragma 抑制）；-Wconversion 只有 preferences_sync.c 一处符号转换，已加显式转换。-Werror 构建通过，全量 ctest 28/28。令牌：GET /api/hosts/{id}/token 不再返回明文，只返回 has_token 与 server；兑换注册码时在同一事务内轮换令牌（明文与哈希一并更新）；对应测试与 control_plane_e2e.py 已改为跟随轮换后的令牌，ASan 下 11/11 通过。阶段 3（清空明文列）仍暂缓，因为回滚基线 Rust 后端依赖明文列。

更新（S5 续，http_server.c 第四次，分支 fix/agent-ui-hardening，commit a7f0641 + 修正 8e5760d）：服务器日志环（SB_HTTP_LOG_CAPACITY、log_ring_append、log_sink、parse_log_level 以及进程级 g_sink_owner/g_sink_owner_mutex）移到 http_log.c。全局 sink 所有权不再散落在生命周期代码里：http_server.c 里两处直接操作 g_sink_owner 的代码改为调用 sb_http_log_attach / sb_http_log_detach，parse_log_level 改名为 sb_http_parse_log_level，三者在 http_internal.h 声明。这一步不是严格的纯移动（多了 attach/detach 封装），行为不变，log_sink_ownership 测试覆盖。http_server.c 由 1618 行降到 1559 行。过程中 a7f0641 在 archlinux 构建失败（sed 插入头文件声明时多出一个 `n` 字符），8e5760d 修正；失败即停的构建检查正确拦下了它。修正后 -Werror 构建通过，全量 ctest 28/28，ASan 下 http、control_plane、agent_ui 7/7 通过。

更新（S5 续，http_routes_hosts.c，分支 fix/agent-ui-hardening，commit 048415a + 修正 da7443f）：agent 与设备注册段（agent_token、resolve_agent_host、optional_field、/api/agent/* 全部处理函数、pcap 校验、主机抓包处理函数，共 405 行）纯移动到 http_routes_agent.c（442 行含文件头与注册函数）；新增私有头 http_routes_hosts_internal.h，声明两个文件共用的 fail_json_aware、json_value_string、json_string_has_nul、respond_ok、route_param、render_config、commands_to_json、managed_render_request（均由 static 改为外部链接）以及 sb_http_register_agent_routes。路由注册顺序保持不变：抓包路由先于 /api/hosts/profiles/{id} 注册（先注册者优先），在 sb_http_register_hosts_routes 开头调用 sb_http_register_agent_routes，agent 路由整体前移，但这些路径与其余路径没有重叠，不影响匹配结果。http_routes_hosts.c 由 1310 行降到 891 行。过程中 048415a 在 archlinux 上构建失败（managed_render_request 为被两边共用的 static 函数，以及头文件注释里的 `/*` 触发 -Werror=comment），da7443f 修正；失败即停的构建检查正确拦下了它。修正后 -Werror 构建通过，全量 ctest 28/28，ASan 下 http、control_plane、agent 共 11/11 通过。

更新（S5 续，store.c 第二次，分支 fix/agent-ui-hardening，commit ea4c77c）：用户、审计、应用设置段（find_user_locked、ensure_default_admin、list/find/create/delete/reset 用户、exec_changes、record/list_audit、app_settings 系列，共 310 行）纯移动到 store_users.c（319 行含文件头）。read_user 由 static 改为外部链接并在 store_internal.h 声明；移动前用守卫脚本确认 find_user_locked 在被移动范围之外没有引用，read_user 在范围外仅有定义一处。exec_changes 本来就是外部链接，随段移动。store.c 由 1299 行降到 989 行。-Werror 构建通过，全量 ctest 28/28，ASan 下 auth、store、http_admin、http_core、http_hosts、control_plane 8/8 通过。store.c 现在只剩结构体辅助、行读取、JSON 取值辅助和 store 打开/关闭。仍待办：proxy_parser.c（受 Apple/Windows 构建文件按名列出的限制）、日志环可再拆。

更新（S5 续，store.c，分支 fix/agent-ui-hardening，commit 71954ed）：备份导出与恢复（sb_store_export_backup、restore_subscription、restore_node、restore_peer、sb_store_restore_backup，共 254 行）纯移动到 store_backup.c。restore_peer 本来就是外部链接（store_wg_import.c 在用）；它依赖的 jv_bool、jv_int、jv_opt_str 由 static 改为外部链接并在 store_internal.h 声明。移动前用守卫脚本确认 restore_subscription、restore_node 在被移动范围之外没有引用。store.c 由 1554 行降到 1299 行。-Werror 构建通过，全量 ctest 28/28，ASan 下 store、wireguard、wg_migration、http_admin、control_plane、subscription 6/6 通过。仍待办：用户、审计、设置段可再拆，proxy_parser.c（受 Apple/Windows 构建文件按名列出的限制）。

更新（S5 续，http_server.c 第三次，分支 fix/agent-ui-hardening，commit adfb80f + 空行修正 e922cb7）：遥测与诊断段（default_telemetry、json_int64、bounded_string、normalize_domain_stats、truncate_json_string、tail_strings、normalize_telemetry、diagnostic_*、normalize_diagnostic_report、telemetry_put/get、log_lines，共 267 行含文件头）纯移动到 http_telemetry.c。移动前用守卫脚本确认这些 static 辅助函数在被移动范围之外没有引用；SB_HTTP_MAX_DOMAIN_STATS 随遥测段移走，civetweb 连接参数宏仍留在 http_server.c。http_server.c 由 1880 行降到 1618 行。-Werror 构建通过，全量 ctest 28/28，ASan 下 http_hosts、agent_ui、http_admin、http_core、control_plane 等 7/7 通过。仍待办：日志环（server log ring）可再拆，store.c 剩余部分，proxy_parser.c。

更新（S5 续，http_server.c 第二次，分支 fix/agent-ui-hardening，commit d8159ea + 修正 bf580f0）：落实上面「静态文件/SPA 段暂不拆」的前置条件。新增私有头 http_wire.h，放 `http_exchange`、`M_*` 方法枚举、`wire_response` 以及 wire_*、ascii_lower_dup、http_date、exchange_header、static_file_response、safe_static_relative_path、static_router 的声明（`exchange_of` 改为 static inline）；wire_* 辅助函数纯移动到 http_wire.c（104 行），静态文件/SPA 段（MIME 表、Range、预压缩变体、文档根回退，约 325 行）纯移动到 http_static.c（335 行）。http_server.c 由 2359 行降到 1880 行。过程中 d8159ea 在 archlinux 上构建失败（http_wire.c 里 `wire_header` 去掉 static 的 sed 没有匹配到，触发 -Werror=unused-function 与 static 声明冲突），bf580f0 一行修正；失败即停的构建检查正确拦下了它。修正后 -Werror 构建通过，全量 ctest 28/28，ASan 下 http_hosts、agent_ui、http_admin、http_core、control_plane 等 7/7 通过。仍待办：日志环/遥测可再拆，store.c 剩余部分，proxy_parser.c（受 Apple/Windows 构建文件按名列出的限制）。

更新（S5 续，agent_main.c，分支 fix/agent-ui-hardening，commit 33fa58d）：agent_main.c 中的外部命令辅助（split_command_line、process_result/run_program、read_existing、proxy_test_tags，共 129 行）纯移动到 agent_commands.c；c_space、path_exists_or_fail、read_stream、parse_json_lenient 由 static 改为外部链接，连同 process_result 类型在 agent_main_internal.h 声明。确认没有其他构建文件按名列出 agent_main.c（仅 Linux glob）。agent_main.c 由 1463 行降到 1369 行。构建命令带失败即停检查，-Werror 构建后全量 ctest 28/28，ASan 下 agent、control_plane 6/6 通过。仍待办：store.c 剩余（users、审计、设置、备份恢复）可再拆，以及 http_server.c、proxy_parser.c、agent_main.c、wireguard.c。构建命令带失败即停检查，-Werror 构建后全量 ctest 28/28，ASan 下 auth、store、http_hosts、http_admin、http_core、control_plane 8/8 通过。store.c 现已拆出 store_wg_import.c、store_captures.c、store_host_commands.c、store_subscriptions.c、store_enrollment.c、store_proxies.c、store_wireguard.c、store_hosts.c。仍待办：store.c 剩余（users、审计、设置、备份恢复、render_request）按领域拆分，以及 http_server.c、proxy_parser.c、agent_main.c、wireguard.c。构建命令带失败即停检查，-Werror 构建后全量 ctest 28/28，ASan 下 store、wireguard、wg_migration、http_admin、control_plane 5/5 通过。仍待办：store.c 其余（users、profiles、hosts、备份恢复）按领域拆分，以及 http_server.c、proxy_parser.c、agent_main.c、wireguard.c。仍待办：store.c 其余按领域拆分（users、hosts、profiles、wireguard），以及 http_server.c、proxy_parser.c、agent_main.c、wireguard.c。构建命令带失败即停检查，-Werror 构建后全量 ctest 28/28，ASan 下 auth、store、http_hosts、http_admin、control_plane 7/7 通过。仍待办：store.c 其余按领域拆分（users、hosts、proxy），以及 http_server.c、proxy_parser.c、agent_main.c、wireguard.c。构建命令带失败即停检查，-Werror 构建后全量 ctest 28/28，ASan 下 store、subscription、http_admin、control_plane 4/4 通过。仍待办：store.c 其余按领域拆分（users、hosts、proxy、enrollment），以及 http_server.c、proxy_parser.c、agent_main.c、wireguard.c。构建命令带失败即停检查，-Werror 构建后全量 ctest 28/28，ASan 下 store、http_hosts、http_admin、control_plane 4/4 通过。仍待办：store.c 其余按领域拆分（users、hosts、proxy、subscription、enrollment），以及 http_server.c、proxy_parser.c、agent_main.c、wireguard.c。构建命令带失败即停检查，-Werror 构建后全量 ctest 28/28，ASan 下 store、http_hosts、http_admin、control_plane 4/4 通过。仍待办：store.c 其余按领域拆分（users、hosts、proxy、subscription、enrollment），以及 http_server.c、proxy_parser.c、agent_main.c、wireguard.c。构建命令已带失败即停的检查，-Werror 构建后全量 ctest 28/28，ASan 下 store、wireguard、wg_migration、http_admin、control_plane 5/5 通过。仍待办：store.c 其余按领域拆分（users、hosts、proxy、subscription、enrollment）、http_server.c、proxy_parser.c、agent_main.c、wireguard.c 的拆分。仍待办：重放/冲突判定拆分、其他长函数、S5、S6、W1–W8、令牌哈希阶段 2/3（需契约决策）、-Wformat=2/-Wconversion、clang-tidy/cppcheck、TSan 全量、PR。

更新（Windows 分发表，分支 fix/agent-ui-hardening，commit 6a73858）：windows/service/controller.c 的 sbw_is_mutating_method 末尾那条 26 个 sb_streq 用 || 连接的长链改为静态名单表加循环，名称与顺序不变，匹配语义不变（仍是精确字符串比较）；其上面按前缀判断和 httpdebug.* 的分支未动。本机用 build.ps1 -SkipUi 构建，ctest 35/36，windows_controller 与 windows_connection 通过，唯一失败仍是改动前就存在的 windows_plugin_sandbox。sbw_controller_dispatch 里的对象参数检查和分支链仍是各自独立的名称列表，尚未统一成表，仍待办；Apple sba_build_runtime 剩余阶段的拆分也仍待办。

更新（Windows 分发表续，分支 fix/agent-ui-hardening，commit 701daaf）：windows/service/controller.c 的 sbw_controller_dispatch 里「该方法是否允许带参数」的长条件（updates./preferences./subscriptions./extensions./capture. 五个前缀，加 enrollment.apply、mode.set、management.settings.set、routing.health.set、routing.automatic.set、routing.group_save、routing.group_remove、routing.probe、routing.delay、routing.gpt_node、routing.set 共 11 个名称）抽成 method_accepts_params()，用前缀表与名称表实现，接受的方法集合与原条件一致；is_apply 变量保留，后面分支仍在使用。第一次替换时误删了 is_apply 的定义，构建前已发现并补回，没有提交过有问题的版本。本机 build.ps1 -SkipUi 构建，ctest 35/36，windows_controller 与 windows_connection 通过，唯一失败仍是改动前就存在的 windows_plugin_sandbox。这次只靠现有测试验证，没有新增专门覆盖「空对象才允许」边界的用例。sbw_controller_dispatch 里按名称分支的 if 链仍未统一成表（各分支加锁与错误处理不同，合并风险较高），仍待办；Apple sba_build_runtime 剩余阶段拆分也仍待办。

更新（Apple sba_build_runtime 续，分支 fix/agent-ui-hardening，commit f555fc1）：apple/Core/core.c 把「已选择节点设为默认出口」阶段抽成 select_default_node()，两处 goto bad 改为 return false，错误信息经 message 指针传出，文案与判定条件不变。验证在 archlinux 上完成：普通构建与 ASan/UBSan 下 apple_core_contract 均通过。注意：apple 工程的 CMake 不识别 SB_EASY_WARNINGS_AS_ERRORS（CMake 提示该变量未被使用），所以这两次构建没有按 -Werror 编译，不能据此说明 apple 目标在 -Werror 下无告警；此前几步 Apple 重构的验证同样如此，需要要么给 apple 工程接入该选项，要么单独用 -Wall -Wextra -Werror 编译确认。sba_build_runtime 仍有 DNS 服务器、本地分组规则、出站合并等阶段未拆，仍待办。

更正（Apple -Werror）：上一条写「apple 工程没有按 -Werror 编译」不准确。apple/CMakeLists.txt 第 13 行已对 sbeasy_apple_core 目标加了 -Wall -Wextra -Wshadow -Werror，所以 core.c 在 archlinux 的 CMake 构建里本来就是 -Werror 编译，且通过。CMake 提示的只是 SB_EASY_WARNINGS_AS_ERRORS 这个开关没有被 apple 工程使用，它没有影响实际告警级别。另外在 archlinux 上用 cc -std=c11 -Wall -Wextra -Werror -Wformat=2 -Wconversion -fsyntax-only 单独检查 core.c，编译器退出码 0、无告警；support.c 与 Tests/core_test.c 未做同样的严格检查（测试目标本身没有带 -Werror）。以上结论只覆盖 core.c。

更新（Apple sba_build_runtime 续，分支 fix/agent-ui-hardening，commit 939a18c）：apple/Core/core.c 把「本地域名分组规则」阶段抽成 add_local_group_rules()，一处 goto bad 改为 return false，错误文案经 message 指针传出，规则与 DNS 服务器的插入顺序和判定条件不变。验证在 archlinux 上完成：普通构建与 ASan/UBSan 下 apple_core_contract 均通过（该目标本身带 -Wall -Wextra -Wshadow -Werror）。该测试只有一个契约用例，覆盖面有限，不能证明所有本地分组分支都被执行过。sba_build_runtime 仍有 DNS 服务器、出站合并等阶段未拆，仍待办。

更新（Apple sba_build_runtime 续，分支 fix/agent-ui-hardening，commit b5b7b82）：apple/Core/core.c 把「WireGuard endpoints 校验」阶段抽成 endpoints_valid()，两处 goto bad 改为 return false，该段没有 message 赋值，判定条件不变（类型必须是 wireguard、不允许 system、不允许 listen_port 非 0、数量不超过 SBA_MAX_ENDPOINTS）。验证在 archlinux 上完成：普通构建与 ASan/UBSan 下 apple_core_contract 均通过（目标本身带 -Wall -Wextra -Wshadow -Werror）。该测试只有一个契约用例，不能证明每个 endpoints 拒绝分支都被执行过。sba_build_runtime 仍有 DNS 服务器、出站合并、订阅节点合并等阶段未拆，仍待办。

更新（Apple sba_build_runtime 续，分支 fix/agent-ui-hardening，commit c1d77a7）：apple/Core/core.c 把「已有出站标签登记 + 订阅节点合并」阶段抽成 merge_subscription_nodes()，四处 goto bad 改为 return false，该段没有 message 赋值，判定条件与节点标签格式 local-<id>/<tag> 不变。names 与 leafs 仍由调用方持有，失败时由 bad: 统一释放。leafs 现在在出站标签检查之前创建（原来在其之后），出站标签检查失败时 bad: 里的 sbj_free(leafs) 会释放它，没有泄漏路径。验证在 archlinux 上完成：普通构建与 ASan/UBSan 下 apple_core_contract 均通过（目标带 -Wall -Wextra -Wshadow -Werror）。该测试只有一个契约用例，不能证明每个拒绝分支都被执行过。sba_build_runtime 仍有 DNS 服务器、直连出站与路由默认值等阶段未拆，仍待办。

更新（Apple sba_build_runtime 续，分支 fix/agent-ui-hardening，commit 7a25bb3）：apple/Core/core.c 把「DNS 服务器」阶段抽成 add_dns_servers()（保留前缀检查、加入引导 DNS、默认域名解析器、独立模式的远程 DNS），一处 goto bad 改为 return false，该段没有 message 赋值，判定条件与插入顺序不变。验证在 archlinux 上完成：普通构建与 ASan/UBSan 下 apple_core_contract 均通过（目标带 -Wall -Wextra -Wshadow -Werror）。该测试只有一个契约用例，不能证明每个拒绝分支都被执行过。sba_build_runtime 仍有直连出站与路由默认值、final 出口解析等阶段未拆，仍待办。

更新（Apple sba_build_runtime 续，分支 fix/agent-ui-hardening，commit 6c798cf）：apple/Core/core.c 把「独立模式 selector」阶段抽成 add_standalone_selector()，把「route.final 出口查找」抽成 find_final_outbound()。selector 阶段的一处 goto bad 改为 return false，文案「独立模式需要至少一个订阅节点」经 message 指针传出；leafs 改用 sbj ** 传递，成功时 selector 接管所有权并把调用方的 leafs 置 NULL，失败时调用方 bad: 仍释放 leafs。find_final_outbound 先查 outbounds 再查 endpoints，找不到时设置「默认出口不存在」，顺序与文案不变。验证在 archlinux 上完成：普通构建与 ASan/UBSan 下 apple_core_contract 均通过（目标带 -Wall -Wextra -Wshadow -Werror）。该测试只有一个契约用例，不能证明每个拒绝分支都被执行过。至此 sba_build_runtime 里按阶段可拆的校验与合并逻辑已全部抽成辅助函数；主函数仍保留解析、清理和各阶段的串联，以及 hijack/sniff 规则插入这几行，未再拆。

更新（Windows 分发处理函数，分支 fix/agent-ui-hardening，本条对应的提交见 git log 中 "Extract inline dispatch branches into handlers"）：windows/service/controller.c 的 sbw_controller_dispatch 里仍内联的 7 个分支（mode.set、management.settings.set、routing.health.check、routing.health.set、routing.automatic.set、routing.probe/delay、config.validate）抽成独立处理函数。加锁与 done: 收尾仍在调用方；这些分支里的 goto done 发生时 result 都还是 NULL，所以处理函数直接 return NULL。new_identity 由 health.set 与 automatic.set 两个处理函数自己释放，done: 里的 sbj_free(new_identity) 对这条路径变为空操作，没有改动。本机 build.ps1 -SkipUi 构建，ctest 35/36，windows_controller 与 windows_connection 通过，唯一失败仍是改动前就存在的 windows_plugin_sandbox。按名称分支的 if 链本身没有合并成一张表：各分支的参数、加锁与错误处理各不相同，现在每个分支只剩一行调用，再合并收益很小，决定不做。仍无法验证或被阻塞的项：windows_capture 的 parse_port 用例（本机无 capture-deps）、MSI 打包与签名脚本、202 条 DeprecatedOrUnsafeBufferHandling 未逐条读过、PR 未创建（gh pr create 被拒绝）。

更新（DeprecatedOrUnsafeBufferHandling 逐点复核，分支 fix/agent-ui-hardening，只读，无代码改动）：在 archlinux 上重跑 clang-tidy，共 202 个调用点（按文件与行号去重）。这次实际读了源码的是带变长长度或固定容量的 memcpy/memmove/snprintf：agent_ui.c:742-743（外层 lower_starts_with 保证 path_len >= 8，减法不会下溢）、clash_websocket.c:442/591/679/821（head_len 来自 memmem 命中位置，next_frame 保证 offset + head + n 不超过 in->len，close_payload 限制 reason 至 123 字节、目标 125 字节）、proxy_parser.c:73/1061/1073（utf8_decode 返回长度不超过剩余字节）、json.c:58/128/264/273/349-353/368-370/442/452/801（目标缓冲区按拷贝长度分配或先 reserve）、util.c:74/152、wireguard.c:142/1034-1035（目标 36 字节、拷贝 32 字节；名称缓冲区按 6+name_len 分配）、auth_security.c:365（out[9]，最多 8 位数字加结尾符）、http_routes_security.c:50（65 字节缓冲，32 字节各写 2 位十六进制）、http_server.c:152（memmove 长度为 strlen+1）。这些点没有发现越界。唯一的小问题：store_captures.c:82 在 blob 长度为 0 时 sqlite3_column_blob 可能返回 NULL 并传给 memcpy，严格说是未定义行为，不会越界，尚未修改。没有逐条读的：约 130 处 memset(x, 0, sizeof *x) 和 FINISH_LIST/DEFINE_VEC 宏展开出的 memset/memcpy（长度由 sizeof 或宏内部决定，宏本身没有读）、各处 fprintf(stderr, ...)、其余 snprintf（json.c 的 tmp 缓冲、wireguard.c:481、agent_clash.c:943、clash_websocket.c:461/927 等，只看了源码行没有核对缓冲区大小）、util.c 的 sscanf 与 vsnprintf。这部分保持报告模式，不能写成已复核。

更新（DeprecatedOrUnsafeBufferHandling 逐点复核，续，只读，无代码改动）：补读了上一条列为未读的 snprintf 与 sscanf 调用点，均带 sizeof 上限或宽度限制，没有发现越界。json.c:474/533/534/549/553（tmp[32] 与 t[16] 足够容纳 \uXXXX、%lld、%llu、指数）、wireguard.c:481（module[48] 足够，且用返回值追加）、agent_clash.c:943（service[8] 装端口）、clash_websocket.c:461（port[16]）与 927（b->kind 带 sizeof，最多截断）、http_static.c:233/242（128 与 64 字节足够三个 unsigned long long）、util.c:456/460/472（sscanf 只写 int，带 %4d/%2d 宽度）。util.c 的 vsnprintf（两次调用，先测长再按长度分配）读过 sb_vasprintf，长度处理正确。仍然没有逐条读的：约 130 处 memset(x, 0, sizeof *x)、FINISH_LIST/DEFINE_VEC 宏展开出的 memset/memcpy（宏体本身没读）、各处 fprintf(stderr, ...)（不涉及缓冲区）。agent_main.c、types.c、wireguard.c 里的其余 memset 只看了源码行。结论：已读的调用点没有发现越界，唯一的小问题仍是 store_captures.c:82 在 blob 长度为 0 时可能把 NULL 传给 memcpy（严格说是未定义行为，不越界），未修改。该检查整体保持报告模式。

更新（store_captures.c，分支 fix/agent-ui-hardening，commit 90e8d35）：sb_store_get_capture 在 blob 长度为 0 时跳过 memcpy（sqlite3_column_blob 对零长度 blob 返回 NULL，向 memcpy 传 NULL 属未定义行为），非空 blob 的结果不变。第一次推送因访问权限错误失败，archlinux 上当时检出的仍是 fc88558，那次 28/28 不覆盖本改动；重试推送成功后，在 archlinux 检出 90e8d35 重新构建，全量 ctest 28/28 通过。没有新增针对零长度 blob 的专门用例。

更新（DeprecatedOrUnsafeBufferHandling 逐点复核，收尾，只读，无代码改动）：补读了 memset 与宏展开部分。用 grep 列出全部 memset(x, 0, sizeof ...) 调用，每处的被清零对象与 sizeof 操作数一致（x 配 sizeof *x，&x 配 sizeof x）；操作数是裸数组名的两处已读声明确认：agent_main.c:259 的 hostname 为 char[256]，http_server.c:1425 的 bound 为 struct mg_server_port[4]，sizeof 取整块数组大小，正确。宏展开部分读了 store.c 的 DEFINE_VEC 与 store_internal.h 的 VEC_APPEND_MOVE/FINISH_LIST：先扩容到 dst->len + src->len 再拷贝，拷贝长度为 src->len * sizeof 元素，拷贝前判断 src->len 非 0，之后 free(src->items) 再 memset(src)，没有越界或重复释放路径。该批宏展开出的 memset/memcpy（store_host_commands.c、store_hosts.c、store_proxies.c、store_subscriptions.c、store_users.c、store_wireguard.c）因此已核对。仍未逐条读的只有各处 fprintf(stderr, ...)（不涉及缓冲区）；其余 memset 调用点只核对了 sizeof 与对象的配对，没有逐个读上下文确认对象已正确分配。结论：该检查没有发现真实缺陷，唯一的小问题（store_captures.c:82）已在 90e8d35 修复；检查整体仍保持报告模式，不转为阻塞。

更新（DeprecatedOrUnsafeBufferHandling 逐点复核，fprintf 部分，只读，无代码改动）：列出 c/src 下全部 fprintf 调用点（agent_main.c、main_server.c、main_render.c、util.c），格式串均为字面量；%s 的参数来自 sb_asprintf（agent_main.c:785、1030，util.c:613，sb_vasprintf 先 vsnprintf 量长度再按 n+1 分配，必以 NUL 结尾）或 err.msg（sb_fail 用 vsnprintf 按 sizeof e->msg 写入）；唯一的 %u 参数带 (unsigned) 转换。没有发现问题。至此该检查的 202 个调用点均已按类别核对：变长 memcpy/memmove、snprintf/sscanf、宏展开读了上下文；memset 只核对了 sizeof 与对象配对，未逐个确认对象已正确分配。检查整体仍保持报告模式。

更新（TSan 测试夹具，分支 fix/agent-ui-hardening，commit a036b7c）：c/tests/http_test_support.h 的 sb_fixture.stop 原为 volatile int，主线程在 sb_fixture_stop 写、accept 线程在 sb_fixture_main 读，属测试夹具自身的数据竞争（TSan 顶层帧落在 http_test_support.h:332/335/406，共约 20 条）。改为 atomic_int 并用 atomic_load/atomic_store 访问。在 archlinux 检出 a036b7c 后：普通构建下 5 个 HTTP 测试通过；TSan 构建下 5 个 HTTP 测试的报告由 75 条降到 65 条，顶层帧落在 civetweb 与 libtsan 之外的为 0。剩余 65 条全部在 civetweb 内部（主要是 mg_stop、consume_socket，以及 mg_start2 里的 calloc/mutex_init/pthread_create 关联栈），这些仍会让 TSan 下的 HTTP 测试失败，尚未加 suppression，也没有判断它们是否为 civetweb 的良性竞争（只确认了双方访问都在 civetweb 内部）。TSan 完整运行与其余测试未在本次重跑。

更新（TSan suppression，分支 fix/agent-ui-hardening，commit 4edcd6c）：新增 c/tsan.supp，只列 civetweb 函数名（mg_stop、consume_socket、master_thread_run、push_inner、mg_get_server_ports、close_all_listening_sockets、mg_poll）。依据：测试夹具修复后剩余 65 条报告，双方访问都在 civetweb 内部（mg_stop 无锁写 stop_flag，consume_socket 持锁读取）。使用方式：TSAN_OPTIONS=suppressions=<repo>/c/tsan.supp。在 archlinux 检出 4edcd6c 后，TSan 构建下 5 个 HTTP 测试全部通过，报告 0 条。注意：TSan 的 race: 规则按「调用栈上任意一帧匹配函数名」生效，因此这些规则会压掉栈中含这些函数的所有报告，范围比「只有 civetweb 内部访问」更宽；我没有判断这些竞争是否为 civetweb 的良性竞争，只确认了位置。suppression 默认不启用，CI 尚未接入。

更新（TSan 接入 CI，分支 fix/agent-ui-hardening）：.github/workflows/ci.yml 的 C 任务矩阵新增 tsan 档（-fsanitize=thread，TSAN_OPTIONS 带 c/tsan.supp 与 halt_on_error=1），并在运行前执行 sysctl vm.mmap_rnd_bits=28，避免 GitHub runner 上 TSan 因 ASLR 熵过高而无法启动。注意：ctest 超时由 180 秒提高到 300 秒，三档都生效。本地用 python 确认了 YAML 可解析、矩阵为 [release, sanitizers, tsan]；这一档没有在 GitHub runner 上运行过，首次结果未知（archlinux 上同样的 TSan 构建加 suppression 为 28/28、0 条报告，但环境与 runner 不同，control_plane_e2e 有 50 ms 的 QuickJS 时限，在较慢的 runner 上可能不稳定）。

更新（Windows 打包验证，分支 fix/agent-ui-hardening，HEAD 3e18ca6，无代码改动）：更正此前"这条分支没有可用的打包工程"的说法。该说法只查了 windows/installer/，漏看了 windows/scripts/package.ps1 与 package-msi.ps1，它们才是本分支的打包流程（scripts/build-windows-installer.ps1 属于 rewrite/cpp-quickjs 的 C++ 客户端，与本分支无关）。按 README 固定版本安装 WiX 5.0.2 及 UI 扩展到 build/wix（build/ 已被忽略，不进 git），然后运行 ./windows/scripts/package.ps1 -Msi -WixPath ./build/wix/wix.exe（不签名、不带 core）：成功生成 sb-easy-0.7.0-windows-x64.msi（970752 字节）与 sb-easy-0.7.0-windows-x64-portable.zip（1003260 字节），worktree 仍干净。这只证明 MSI 能构建，不代表安装后可用。未做：installer-smoke.ps1（安装、升级、修复、降级拒绝、卸载）。该脚本自述要在一次性 Windows 机器上以管理员运行，会安装 LocalSystem 服务并写入 Program Files 与 ProgramData，我没有在这台开发机上运行；它还需要带 core 的包（-IncludeCore 会下载 sing-box）和一个更早版本的 MSI。已签名发布（-TrustedRelease）需要证书，未做。

更新（windows_capture 实跑，分支 fix/agent-ui-hardening，HEAD 3e18ca6，无代码改动）：用户关闭 Defender 后，运行 windows/scripts/prepare-capture.ps1（按固定 SHA-256 下载 WinDivert 与 flex，不启动驱动），再用 ./windows/scripts/build.ps1 -SkipUi -CaptureExtension 构建。此前默认构建不带 -CaptureExtension，SB_EASY_BUILD_CAPTURE_EXTENSION 为 OFF，所以 windows_capture 从未被构建，这也是之前它不在 ctest 清单里的原因。带捕获扩展后 capture.c、capture_test.c 以 MSVC /W4 /WX 编译并链接成功，ctest 36/37：windows_capture 通过（含 parse_port 回归用例），唯一失败仍是改动前就存在的 windows_plugin_sandbox（HRESULT 0x80070005）。本次没有验证真实抓包：未启动 WinDivert 驱动，未做 capture 端到端测试。

更新（MSI 安装生命周期实跑，分支 fix/agent-ui-hardening，HEAD 3e18ca6，无代码改动）：经用户授权（选 A）并确认已备份 ProgramData\sb-easy 到用户目录，通过 UAC 卸载了本机原有的 sb-easy 0.7.1（msiexec /x，退出码 0），随后把残留的 Program Files\sb-easy 与 ProgramData\sb-easy 改名为 sb-easy-preserved-20261105（未删除，可还原）。用 package.ps1 -Msi -IncludeCore 打出带 core 的 0.7.0 MSI，并按 CI 做法用 package-msi.ps1 -Version 0.3.99 打出旧版 MSI，在提权会话运行 installer-smoke.ps1，结果 PASS，receipt.json 的 checks 为 install-previous、upgrade、repair、reject-downgrade、uninstall、data-retained，success=true。本次验证的是未签名包；未验证签名发布、WebView2 桌面界面检查（未带 -WaitForDesktopCheck）、真实抓包。注意：本机目前没有安装 sb-easy，原 0.7.1 安装已被卸载，其数据在 sb-easy-preserved-20261105 与用户目录备份中，尚未还原。

更新（windows_plugin_sandbox 提权复测，分支 fix/agent-ui-hardening，HEAD 3e18ca6，无代码改动）：此前该测试在未提权会话中一直失败（创建 AppContainer profile 返回 HRESULT 0x80070005）。经 UAC 在提权会话运行 ctest -R windows_plugin_sandbox，结果 1/1 通过（0.47 秒）。因此该失败是本机未提权造成的环境问题，不是代码缺陷，也不是本次改动引入。只复测了这一个测试，没有在提权会话重跑整套 ctest。

更新（提权下的捕获测试，分支 fix/agent-ui-hardening，HEAD 3e18ca6，无代码改动）：经 UAC 在提权会话运行 ctest -R windows_capture，windows_capture_broker 与 windows_capture 均通过（2/2）。这只是单元与 broker 级测试，没有走签名商店安装路径，也没有端到端抓真实流量：开发构建的 config/plugin-catalog-keys.json 为空，不信任任何目录；要走商店路径需要本地 HTTPS 服务器加受信任证书、带临时公钥的宿主构建，以及 statistics 与 http-debug 两个尚未构建的插件。该路径未做。已生成的一次性 RSA 密钥对在 %TEMP%\sb-trial-catalog，不在仓库内，可删除。

更新（本机安装验证，分支 fix/agent-ui-hardening，HEAD 3e18ca6，无代码改动）：用 package.ps1 -Msi -IncludeCore 打出的未签名 0.7.0 MSI 在本机提权安装成功（msiexec 退出码 0），sb-easy 服务以 LocalSystem、自动启动运行，sb-easy.exe、sb-easy-service.exe、sb-easy-update.exe、WebView2Loader.dll、ui\index.html、core\sing-box.exe 均在位，控制管道对 status.get 返回 ok:true。首次安装曾返回 1603（服务启动失败，系统无法打开指定的设备或文件）。根因是此前步骤留下的空目录 C:\ProgramData\sb-easy，所有者为普通用户账户，secure_store.c 的 sbw_trusted_storage_owner 只接受服务账户、SYSTEM 或 Administrators，因此判为 UNSAFE_STORAGE_PATH 并以 ERROR_OPEN_FAILED 退出；不是代码缺陷。已把该空目录改名为 sb-easy-wrongowner-empty-20261105（未删除）后重装成功。当前本机运行的是新装的 0.7.0（全新数据目录，未注册），原 0.7.1 的数据仍在 sb-easy-preserved-20261105 与用户目录备份中，未恢复。未验证：签名包、WebView2 桌面界面、真实抓包。
