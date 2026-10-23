# 代理用户与节点租约 v1（未发布）

本接口用于受管理的 `2022-blake3-aes-128-gcm` Shadowsocks 入站，不对其它代理协议宣称额度执行。代理用户、设备凭证和节点绑定独立于面板账户与 WireGuard Peer。中心业务使用 C11/SQLite；引擎仅负责认证、转发计数、额度和期限执行。

## 节点交换

`POST /api/agent/proxy-leases` 使用该 host 的 agent Bearer token。仅中心自身可直接以 `self` 调用相同业务函数。所有时间为 Unix 秒；所有数字为整数且不超过 JavaScript 安全整数。请求不接受客户端指定 host_id。

请求最多 512 KiB、reports 最多 4096 项；响应只包括最多 256 个活跃用户。报告可包含已退休 lease 的最后计数。C 收到并验证匹配的成功响应后调用 `SBEasyProxyAcknowledgeReports(jsonReports)`，引擎仅对累计计数与确认值精确一致的已退休 lease 丢弃统计，活跃 lease 始终保留。本次请求仍在重试时不得提前确认或丢弃统计。

```json
{"version":1,"boot_id":"random-process-uuid","request_seq":1,"reports":[{"lease_id":"lease-uuid","used_bytes":1234}]}
```

`boot_id` 在每次进程启动时随机生成且禁止跨进程复用。`request_seq` 从 1 开始，每次收到并验证匹配的响应后递增；丢响应时原样重发。中心持久保存该 boot 的最后响应：相同序号且请求内容相同仅返回原快照，旧序号或同序号不同内容拒绝，不延长期限。重试响应如果已经过期，引擎保持拒绝转发，C 客户端立即以新序号取得新快照，不能卡在旧序号重试。请求必须串行。报告是本 boot/host 所拥有租约的双向有效载荷累计字节，非增量；不能回退、不能超过累计授权值。请求和响应均应在内存中处理，日志不得包含密钥。

```json
{
  "version":1,"host_id":"node-1","boot_id":"random-process-uuid","request_seq":1,
  "generated_at":1792742400,"expires_at":1792742460,
  "node":{"listen":"0.0.0.0","listen_port":8388,"method":"2022-blake3-aes-128-gcm","password":"base64-16-byte-server-key"},
  "users":[{
    "id":"proxy-user-uuid","epoch":1,
    "lease":{"id":"lease-uuid","grant_bytes":67108864,"used_bytes":1234,"expires_at":1792742460},
    "devices":[{"id":"device-uuid","password":"base64-16-byte-device-key","expires_at":0}]
  }]
}
```

没有启用的节点配置时 `node` 为 null，`users` 为空。没有授权、已停用、已到期或处于额度重置等待期的用户不出现在快照中。没有有效设备的用户不分配额度。设备 `expires_at` 必填，0 表示没有额外设备期限，正整数表示设备独立 Unix 到期时间。有效连接期限取设备期限与用户/租约期限较早值；设备到期时引擎独立关闭已有流量，不能等下次中心刷新。到期设备不占设备限额，也不出现在后续快照。入站账号名称使用 device.id，用户级额度由该用户所有设备共享；出站客户端密码为 `server-key:device-key`。节点监听配置通过管理员 API 显式建立和启用，不能依据订阅请求隐式开放端口。

桥接接口约定 `SBEasyProxyApplyPolicy(json)` 接收上述完整快照，`SBEasyProxyStats()` 返回请求中的 reports 数组（`[{"lease_id":...,"used_bytes":...}]`），错误使用桥接现有 error string/free 约定。C 负责 boot_id、request_seq、HTTP 和续租调度。每 10 秒续租，失败不能延长租约；接近额度时可提前续租，但仍须串行。引擎检查 host/boot/序号、schema、期限；重复快照不得降低已用计数，也不得回退过期/撤销状态。

引擎必须把绝对期限转换为不随系统时钟回拨延长的单调计时期限。在有效载荷交给路由器或写回客户端前，先在同一用户锁下保留额度；连接和数据报均计入上行+下行。TCP 上行先解密到私有缓冲区，再保留额度并只向路由器交付获准的前缀，避免等待中的读取占住全部下行额度。下行先保留额度再写出；协议层可能在已经发送部分明文后返回无法反映该部分的错误计数，因此失败或短写仍保守计入整个已保留部分，不重新发放这部分额度。UDP 没有足够的整包额度时丢弃整个数据报；已授权发送后无法确认的错误也保守计费。已经接收入站并交给路由器的字节计入使用量，后续目标连接失败不会退回。故 reported_bytes 是本地执行的使用计数，可能包括这些失败路径的保守计费。额度耗尽、租约到期、快照移除用户/设备时停止已有 TCP/UDP 并拒绝新流量。新快照不得重新归零同一 lease 的本地计数。无有效租约、快照解析失败或 bridge 不支持时默认拒绝；错误不允许退化为普通无配额入站。

## 全局配额与重启

中心以 `BEGIN IMMEDIATE` 原子预留累计 grant。所有节点、所有 boot 在同一用户 epoch 下的 grant 总和始终不超过 quota_bytes。0 表示不限制总额度，但仍需限时租约。每次最多追加 64 MiB，剩余额度按已启用且运行时上报有效的绑定节点数保守分片；剩余授权大于 `min(累计授权/2, 32 MiB)` 时不追加，无流量不会逐次吃掉全部配额。已分配 grant 永不因为失联、过期或重启而自动回收；未报告/未使用部分计为保守预留耗额。这样旧节点在短期失联期间继续使用现有授权，也不会与新节点额度重叠超售。

面板分别显示 reported_bytes（实际报告）和 allocated_bytes（已授权/含保守耗额）。重启可能损失未使用的额度；管理员可主动重置。重置增加 epoch，并将新周期的 not_before 设为旧 epoch 最晚租约到期时刻；等待期间全部拒绝发放新周期租约。停用、撤销和配置修改通过下次快照生效，失联节点最迟在 60 秒租约到期时关闭已有流量，不能宣称瞬时全网撤销。

## 中心管理与自助 API

管理员：`GET/POST /api/proxy-users`、`GET/PUT/DELETE /api/proxy-users/{id}`；PUT 包括 name、enabled、quota_bytes、expires_at（0不限期）、max_devices（1..32）、host_ids（最多32）。`POST .../{id}/reset` 重置额度周期；`POST .../{id}/claim-token` 生成替代领取密钥（仅返回一次，库中保存 SHA-256）；`POST .../{id}/devices` 可管理端领取设备；`DELETE .../{id}/devices/{device_id}` 撤销。`GET /api/proxy-ingress` 和 `PUT /api/proxy-ingress/{host_id}` 管理节点的 enabled、server（公开域名/IP）、listen（IP）、listen_port；server key 由服务端随机生成，不在普通列表返回。

自助：`POST /api/proxy-self/status`、`POST /api/proxy-self/devices` 使用独立的领取 Bearer token；管理员和自助创建设备 body 为 `{"name":"手机","expires_at":0}`，expires_at 可省略（默认0）或为未来时间，返回设备与 subscription_token 一次。`DELETE /api/proxy-self/devices/{id}` 仅能撤销自己的设备。`GET /api/proxy-self/subscription?token=...` 使用设备订阅 token，返回只含该设备有效 SS2022 节点的 sing-box `{"outbounds":[...]}`。领取密钥不会赋予面板/agent 权限。所有响应 `Cache-Control: no-store`，自助页 token 放内存/URL fragment，禁止 localStorage。订阅 token 是访问凭证，不得记录查询字符串或经 Referer 外泄。

自助设备限额指服务器维护的独立凭证数量，不代表可识别同一凭证被复制到多少台物理设备。撤销凭证会删除它在后续完整快照中的认证权限；订阅失效仅是额外防护，数据面仍必须独立执行租约。

## 运行时能力门禁

只有经本 host agent token 认证的 `POST /api/agent/status` 才可报告顶层 `"capabilities":["proxy_users_v1"]`。中心写入独立 `proxy_runtime_reports` 表；管理员可编辑的 `hosts.capabilities` 不能影响此表。缺失或空 capabilities 清除支持标记。启用入口要求最近 180 秒有支持报告；订阅节点和新租约也以同一条件过滤，过期或不再支持时下发 `node:null,users:[]`。列表返回 `runtime_supported` 和 `runtime_seen_at`。

中心自身仅在编译内嵌桥接、对应 API 可用时调用 `sb_proxy_runtime_report(db,"self",capabilities,now,err)` 上报同一能力。外部未修改的 sing-box、旧版 agent、Android 和 Windows 客户端不得冒报此能力。真实数据面运行仍由租约执行；能力上报只表明协议实现可用，不等价于监听成功或防火墙可达。

## 使用与验证

在面板「代理用户」中先配置节点的公开地址、监听地址与端口；在支持此功能的运行时上报后勾选启用。给用户设置字节配额（0不限量）、期限和设备凭证数量，再分配节点。管理员可以直接创建设备订阅，也可以生成只显示一次的领取链接。领取链接通过 HTTPS 打开独立自助页，支持创建有独立期限的设备和撤销已有设备。每个设备得到自己的 sing-box JSON 订阅链接。更换领取链接不会撤销已领取设备，需要另行撤销设备。

备份完整 SQLite 数据库及其一致性快照以保留用户、设备密钥、租约累计授权与去重记录；偏好导入和旧配置备份不包含这些表。不得只恢复旧额度计数而继续运行持有更新租约的节点：恢复数据库前停用节点，等待旧租约到期，再以新的 boot_id 启动。SQL 中的密码和缓存策略属于敏感配置，备份应加密并限制访问。

中心自动测试 `proxy_users_test` 覆盖两个独立数据库连接并发分配、重复请求、计数回退、跨节点报告拒绝、重启保守预留、周期重置等待、能力真实性/新鲜度、设备独立到期和并发设备限额。`store_test` 和 `http_hosts_test` 验证迁移与已有主机接口兼容。

```sh
cmake -S c -B build/c-proxy-users
cmake --build build/c-proxy-users --target proxy_users_test sb-easy-c-server
ctest --test-dir build/c-proxy-users -R proxy_users_test --output-on-failure
npm --prefix frontend run build
# 需要已安装的 Playwright package / Chromium；可通过环境变量指定本地路径。
SB_EASY_PLAYWRIGHT_PACKAGE=/path/to/playwright-core \
SB_EASY_CHROMIUM=/path/to/chrome \
node scripts/test-proxy-users-ui.cjs build/c-proxy-users/sb-easy-c-server
```

浏览器用例在临时数据库和独立 localhost 面板中验证管理员入口、移动视口自助领取、订阅读取/撤销、周期重置与删除，不使用已有账户；能力上报是测试 fixture，不能代替 TCP/UDP 数据面联调验收。

### 客户端单调时钟期限

数据面调用 `SBEasyProxyRequestBegin(requestJSON)`，在该 boot/seq 的第一次 HTTP 发送前记录本机单调时钟起点。相同序号的网络重试不得刷新起点。`SBEasyProxyApplyPolicy` 只接受存在匹配 Begin 的响应，将每个租约的本机期限设为 `requestBegin + (lease.expires_at - response.generated_at - 1)` 秒；设备期限再取租约剩余时间与 `device.expires_at - response.generated_at - 1` 的较小值（设备 `expires_at=0` 表示没有独立期限）。额外减去一秒补偿服务端 Unix 整秒向下取整，否则请求发起点可能比 `generated_at` 晚不足一秒并越过额度重置边界。响应在网络中消耗的时间因此会减少可用授权时间，主机墙钟回拨也不能延长授权。此约定依赖中心作为时间权威；节点本机墙钟不参与授权期限换算。

已过期的幂等缓存响应仍是成功的协议响应：客户端确认服务端已接收该序号后推进序号并立即请求新快照，数据面拒绝启用过期租约。没有匹配 Begin、负期限或在 Apply 时已经消耗完期限的响应不得启用流量。服务端 JSON 格式保持不变。

节点的授权时钟使用 Linux `CLOCK_BOOTTIME`，包括系统休眠经过的时间；时钟不可用时拒绝启用租约，不退回墙钟。每次有效载荷及最终加密传输写出前检查该期限，并以最长 250ms 的检查周期在恢复后关闭空闲连接，避免休眠节点复用中心已经过期的授权。Go 的普通单调时钟在 Linux 不计入休眠，不能用作此处的授权依据。时钟语义见 [Linux clock_gettime 手册](https://man7.org/linux/man-pages/man2/clock_gettime.2.html)。服务端租约能力目前只在 Linux 内嵌构建中上报，桌面客户端仅消费设备订阅。

`SBEasyProxyReset()` 只供新的 C 运行时所有者初始化：先停止入口并等待在途写入完成，再清理本地 boot/序号/计数，以便生成新的 boot 身份。中心不会因此收回旧 boot 已预留的额度。普通核心重载和同一续租线程的停止/恢复只调用 Stop，保留原有请求与计数；同一进程禁止同时创建两个原生租约所有者。

### 引擎实现与回归

受管理入口由 `singbox-bridge/proxy_*.go` 实现，使用固定版本引擎的 SS2022 多用户认证，认证索引为稳定设备标识及凭证摘要，转发使用当前核心的路由器。核心停止或替换时关闭入口；本进程计数保留给下一次中心交换。每个设备最多 256 个已认证连接，节点最多 4096 个；退休报告最多保留 4096 项，未确认满额时拒绝增加新租约。JSON 拒绝未知/缺失/重复字段、非整数和超限值。重复响应只确认既有结果，不会重新启用已关闭入口。

固定依赖的 UDP 队列原来可能在队列已满且流关闭时阻塞。`singbox-bridge/prepare-overlay.py` 校验该依赖版本与源文件 SHA-256，复制到构建目录并作两处队列关闭修补；不写 Go 模块缓存或上游仓库。生成的 `.mod/.sum` 用于构建，JSON 文件记录来源及修补摘要。Docker 与 Linux 桌面构建已接入此步骤。构建时需使用生成的 `-modfile`，不能省略。

```sh
# 在 runtime-versions.json 固定的 sing-box 源码目录中执行；
# 先把仓库 singbox-bridge/*.go 复制到 cmd/sb-easy-bridge/。
python3 /path/to/sb-easy/singbox-bridge/prepare-overlay.py --output ../bridge-overlay.json
go test -modfile ../bridge-overlay.mod -race -count=1 -timeout 60s \
  -tags with_clash_api ./cmd/sb-easy-bridge
```

真实 loopback SS2022 TCP/UDP 用例覆盖双向计数、两设备共享硬配额、追加授权不归零、UDP 整包限额、设备独立到期、现有连接撤销、过期缓存响应、重复快照、并发连接、核心停止，以及拒绝路由后的处理线程释放。单独的队列饱和用例验证依赖修补，模式/序号与报告容量用例验证失败关闭。所有地址和端口均为隔离测试资源。

### C 运行时与进程联调

`c/src/proxy_runtime.c` 为每个所有者生成随机 boot ID，保存序号及待重试请求的原始字节，并在首次发送前调用 Begin。收到匹配的完整响应后，先 Apply，再确认本次已发送的报告；本地监听应用失败也推进服务端已经接收的序号。HTTP、响应校验或连接失败保留原请求。请求与响应分别限制为 512 KiB 和 4 MiB，禁止 HTTP 重定向，每次 HTTP 调用最多 5 秒，公开错误不包含凭证。请求年龄使用 Linux `CLOCK_BOOTTIME`，包含系统休眠时间；授权时钟不可用时关闭入口。

只有 Linux 内嵌构建且桥接同时提供 Begin、Apply、Stats、AcknowledgeReports、Stop、Reset 六个接口时才启用能力。agent 还要求 `SINGBOX_MANAGED=true`；其续租线程每 10 秒独立运行，能力每 60 秒独立上报，不受 `AGENT_INTERVAL` 影响。注册设备使用保存的 host ID 校验响应；直接配置旧式 `AGENT_TOKEN` 时可额外设置 `AGENT_HOST_ID`，未设置则在首个完整有效响应后固定本进程的 host。已有注册信息与显式 host 不匹配时拒绝启动。普通核心重载、工作线程停止再启动都保留同一 boot、序号、待重试请求与累计计数；仅新的运行时所有者调用 Reset，旧所有者必须先停止并释放。

中心的受管理 self 核心使用同一运行时和 SQLite 租约业务，续租独立于 `SELF_SINGBOX_INTERVAL`。关闭中心时先停止续租并关闭受管理代理入口，再释放核心与数据库，最终清除 self 能力报告。进程被强制终止后，旧授权仍按中心的保守预留规则保留。外部原版 sing-box 与不完整桥接不会上报能力。

`proxy_runtime_test` 使用真实 HTTP 服务验证精确重试、过期缓存序号推进、身份/类型/重复字段拒绝、报告确认、停止期间的迟到响应与 self 生命周期。完整进程用例启动临时 SQLite 面板、两个内嵌 agent 和原版 sing-box SS2022 客户端，验证真实双向流量、并发超额流量关闭、全局授权上限、重启后的保守预留、设备独立到期与撤销、中心 self 监听和关闭，以及中心离线后远端已有连接在租约到期时关闭。两个常规轮询间隔均设为 300 秒，以证明 10 秒租约线程独立工作。所有监听均为新分配的 loopback 端口，不改系统路由、TUN 或防火墙。

```sh
# 先按上文构建带修补依赖的桥接；客户端使用 runtime-versions.json 固定的上游版本。
cmake -S c -B build/c-proxy-runtime-embedded \
  -DSB_EASY_EMBED_SINGBOX=ON \
  -DSB_EASY_SINGBOX_BRIDGE_LIBRARY=/absolute/path/libsb_easy_singbox.a \
  -DSB_EASY_SINGBOX_BRIDGE_INCLUDE_DIR=/absolute/path \
  -DSB_EASY_PROXY_TEST_CLIENT=/absolute/path/sing-box
cmake --build build/c-proxy-runtime-embedded --target \
  sb-easy-c-server sb-easy-c-agent proxy_runtime_test agent_client_test
ctest --test-dir build/c-proxy-runtime-embedded \
  -R '^(proxy_runtime_test|agent_client_test|proxy_runtime_e2e)$' --output-on-failure
```

### 中心重置与恢复的单调时钟门禁

中心不以 Unix `not_before` 单独决定是否发放新周期额度。数据库连接拥有进程内的代理时钟状态；指向同一数据库文件（设备号/inode）的连接共享状态和互斥锁，`:memory:` 连接独立。状态在数据库打开时读取已有 epoch；存在未耗尽的持久化租约时，启动后按本机单调时钟至少等待 60 秒再发放新的租约快照。最后一个连接关闭后状态释放，重新打开会重新执行恢复等待，不能通过重开数据库绕过。

重置事务增加持久化 epoch，并在该事务中为新 epoch 设置至少 60 秒的单调等待。其他进程无法比较这个进程的单调时间，所以首次观察到改变的 epoch（包括倒退）时，从自己的观察时刻起再等待 60 秒；未知且大于 1 的 epoch 采用相同规则。首次创建的 epoch=1 用户无需额外等待。所有新授权仍在同一个 `BEGIN IMMEDIATE` 事务中读取 epoch、检查门禁并预留 grant；跨连接和跨进程的墙钟前跳不能提前放行。Unix `not_before` 保留为额外保守条件，普通重置至少设为 `now+60`，不允许覆盖单调门禁。

管理员用户响应的 `lease_wait_seconds` 是本中心当前剩余单调等待时间，界面据此显示等待；多中心首次观察时间和节点续租可能产生额外延迟。原请求的幂等响应仍逐字节返回，但节点必须保留首次 RequestBegin，重复响应不能刷新旧授权期限。测试使用只可在状态尚未使用前安装的时钟依赖注入，HTTP 和设置不能改变这个时钟来源。

中心读取单调时钟失败、值越界或倒退时停止发放新授权；故障期间发生的重置，在首次有效读取时开始完整的 60 秒等待。中心时钟不包含休眠只会延长这个等待，节点授权时钟则必须包含休眠，保证休眠恢复不会延长旧租约。
