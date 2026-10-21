# 中心 IP 检测（0.7.0）

IP 检测是内置功能，不再安装插件。中心 Docker 镜像包含探测引擎和公开资料数据库，网页与 Windows 使用同一个中心任务接口。

## 使用

网页进入「IP 检测」，选择设备对应的中心配置；Windows 直接进入「IP 检测」。按订阅/名称筛选并选择最多 100 个节点，开始后中心逐个检测 IPv4，可同时请求 IPv6。客户端退出不影响任务，同一配置和节点参数共享结果；重新检测替换上一批结果。一次只运行一个批次，可取消。结果保存到中心数据目录，重启后仍可查看；中断任务明确标记失败。

客户端只提交节点标签和 IPv6 选项。中心从自己的配置读取节点及凭据，不接受本地配置、网卡或执行路径。本地独有订阅不会自动上传。每个检测节点使用独立 sing-box 进程和回环入口，不切换任何客户端的代理或中心正在运行的代理。结果代表中心在显示时间测得的出口；动态出口、按来源或目标分流的节点，可能在其他设备测出不同出口。

## 运维与接口

- Docker 默认启动 C 服务和内置检测进程；不增加公开监听端口。
- C 服务在认证后通过私有 Unix socket 调用检测引擎。设备调用 `POST /api/agent/ipcheck/{catalog,start,snapshot,cancel}`；管理员调用 `POST /api/hosts/{id}/ipcheck/{action}`。
- `start` 请求仅允许 `{"tags":["节点标签"],"ipv6":true}`，其他操作提交 `{}`。
- 缓存位于 `/app/data/ipcheck-results`，最多保留 128 个配置快照，不存节点凭据。
- 固定探测核心 `/usr/local/bin/sing-box`，默认上联网卡 `eth0`；特殊部署可用中心环境变量 `IPCHECK_INTERFACE` 指定。客户端不能覆盖。
- 若宿主机透明代理会接管容器出站连接，管理员可显式设置 `IPCHECK_ROUTING_MARK` 为该代理已有的绕过标记（如 sing-box 默认输出标记 `0x2024`）。只给检测进程的套接字打标，不增删系统路由或代理规则。Linux 5.14 等内核需要容器已有 `NET_ADMIN` 能力；不要在未确认标记用途时套用。默认不设置标记。
- 对会在跨网络命名空间时清除标记的 Docker 桥接环境，可让同一镜像的内置检测引擎作为 `network_mode: host` 的伴随服务运行，入口为 `python3 /usr/share/sb-easy/ip-check/center.py`，并共享 `/app/data` 和仅 root 可访问的 `/run/sb-easy`。面板设置 `IPCHECK_EXTERNAL=true` 后只通过该私有 Unix socket 调用引擎。引擎不开放公网控制端口，每个临时探测入口仅监听回环且有随机认证。面板与 WireGuard 仍使用原来的桥接网络，无须修改宿主机代理规则。
- 上述部署示例见 `c/compose.ipcheck-host.yml`。部署前在 Compose 项目目录创建权限 `0700` 的 `ipcheck-run` 目录，并显式指定同版镜像和已确认的绕过标记。普通无透明代理的服务器仍使用单容器默认模式。
- 构建：`docker build -t sb-easy:0.7.0 .`。数据构建失败会终止镜像构建，不会静默发布空库。

低内存生产机不要直接并行构建完整镜像。可在开发机完成网页构建与数据校验，分别放入独立构建目录的 `prebuilt/frontend` 和 `prebuilt/data`，再使用 `c/Dockerfile.center-prebuilt` 更新同一 Debian 版本的既有中心镜像。该路径串行编译并运行 C 测试；按文件顶部示例限制构建内存和 CPU。它继承既有镜像的 sing-box 和 Agent UI，因此仅适用于这些组件未变化的更新。不要把临时下载代理配置保存为运行时环境变量。

## 本地公开数据源

| 项目 | 来源 | 许可与范围 |
| --- | --- | --- |
| 国家/地区 | [DB-IP Lite Country](https://db-ip.com/db/download/ip-to-country-lite) | CC BY 4.0；IPv4、IPv6 |
| ASN、网络组织 | [DB-IP Lite ASN](https://db-ip.com/db/download/ip-to-asn-lite)，通过 [sapics 转换镜像](https://github.com/sapics/ip-location-db/tree/main/dbip-asn) 获取 | CC BY 4.0；IPv4、IPv6；固定提交 |
| 机房、VPN 名单 | [X4BNet lists_vpn](https://github.com/X4BNet/lists_vpn) 的独立名单 | MIT；IPv4、IPv6；不保证完整 |
| Tor 出口记录 | [Tor Project CollecTor](https://metrics.torproject.org/collector.html) | CC0；仅覆盖快照记录的地址类型 |

每个结果显示来源、日期和覆盖类型。名单区分「命中」「未命中」「不可用」「过期」「地址类型不支持」。未命中不代表住宅 IP、纯净 IP 或安全。国家/ASN 数据超过 60 天、X4B 超过 7 天、Tor 超过 2 天会提示过期。不提供城市级定位、商业欺诈评分或服务解锁承诺。

数据出处、获取地址和摘要记录在 `data-sources.json` 及生成的 `data/manifest.json`。国家镜像的解压内容通过 DB-IP 官方校验值核对；ASN 转换镜像校验固定 Git 提交的 blob 和 SHA-256，不冒称原始 CSV 校验通过。数据整理为范围索引，Tor 仅提取观测出口地址，完整署名与许可随中心镜像分发。

当前数据库随中心镜像发布，检测时不后台更新。维护者更新来源锁文件的 URL、日期与哈希后，运行 `python extensions/ip-check/build_data.py`；加 `--offline` 可使用已校验缓存重复构建。生成的数据库与清单位于 `build/windows-release/extensions/ip-check/data/`。下载、解压、行数及大小有上限，范围重叠或摘要不符会失败并保留旧库。Tor recent 文件短期保留，所以源码附带已校验的 CC0 压缩快照。修改数据后须重新构建中心镜像；此版本尚无单独的数据库在线更新按钮。

实际出口由 [ipify](https://www.ipify.org/) 的 IPv4/IPv6 专用回显接口测量，HTTPS 连接强制经过被测节点。IPv6 失败只能表示本次路径未测通；同一节点也可能针对不同目的站使用不同出口。

## 验证

运行 `python -m unittest discover -s extensions/ip-check/tests -v` 验证隔离探测、数据解析和中心共享缓存。C HTTP 测试覆盖认证与请求边界；Windows 原生测试验证只传中心节点标签、不上传本地订阅、不改动主连接。冻结的旧 Windows worker 和打包脚本仅供历史开发回归，不再作为 0.7.0 安装流程。
