# sb-easy 部署与运维（生产拓扑）

> 反映实际生产部署：**服务器 = 面板 + WireGuard hub + 配置同步**；**每个端点 = agent**
> （跑 sing-box、用 WireGuard 连进服务器内网、从服务器下载配置做代理）。
> 改一次服务器的配置画像（Profile）→ 所有 agent 自动同步。

## 拓扑

```
                ┌──────────────────────────────────────────┐
                │  服务器 (公网, 例: 39.108.98.208)           │
                │  sb-easy 容器:                              │
                │   - 面板 / 配置同步 (:51821)                 │
                │   - WireGuard hub (:51820, 10.59.32.1/24)   │
                │   - SINGBOX_MANAGED=false (服务器不跑代理)    │
                └───────────────┬──────────────────────────┘
                                │ WireGuard 内网 10.59.32.0/24
                ┌───────────────┴──────────────────────────┐
                │  端点 (agent, 例: 本机 10.59.32.2)          │
                │  `sb-easy agent` 容器:                      │
                │   - 拉取服务器下发的配置                       │
                │   - 跑 sing-box: 用 WireGuard endpoint 连入   │
                │     内网 + 按配置做代理出站                    │
                └────────────────────────────────────────────┘
```

- 面板 = wg-easy 的替代（组内网 + 客户端/配置管理），外加 sing-box 代理的中心化管理。
- agent 一个进程搞定"连内网 + 代理 + 拉配置"，**无需手动 wg-quick**（sing-box 用
  `endpoints` 里的 WireGuard 自己连）。

## 一、部署服务器端（Docker）

镜像本机构建后传输（小内存服务器别在上面编译，会 OOM）：

```sh
# 本机构建（Docker Hub 不通就加 --build-arg 指镜像源，见 README）
docker build -t sb-easy:latest .
# 传到服务器
docker save sb-easy:latest | gzip -1 | ssh root@SERVER 'gunzip | docker load'
```

服务器上 `/root/workspace/sb-easy/`：

`.env`（密钥，勿入库）：
```
JWT_SECRET=<openssl rand -hex 32>
ADMIN_PASSWORD=<强密码>
```

`docker-compose.yml`（面板 + WG hub，**不跑 sing-box**）：
```yaml
services:
  sb-easy:
    image: sb-easy:latest
    container_name: sb-easy
    restart: unless-stopped
    cap_add: [NET_ADMIN, SYS_MODULE]
    ports:
      - "51821:51821/tcp"   # 面板
      - "51820:51820/udp"   # WireGuard
    volumes: [ ./data:/app/data ]
    env_file: [ .env ]
    environment:
      - SINGBOX_MANAGED=false        # 服务器只做面板 + WG hub
      - SELF_SINGBOX_CONFIG_PATH=    # 关掉自管 sing-box
      - WG_ENABLED=true
      - WG_PORT=51820
      - WG_ADDRESS=10.59.32.1/24
      - EXTERNAL_HOSTNAME=SERVER_PUBLIC_IP
```
```sh
cd /root/workspace/sb-easy && docker compose up -d
```
面板：`http://SERVER:51821`（admin / 你设的密码）。
> 若服务器在跑 wg-easy，先停掉（占用 51820/51821）：`docker stop wg-easy && docker update --restart=no wg-easy`。

## 二、加一个 agent 端点

1. **面板里建主机**：Hosts → 添加 → 勾选"运行 sing-box"+"WG 成员"。保存后它会自动分配一个
   WG 内网地址（10.59.32.x）和 per-host token。给它分配一个**配置画像（Profile）**。
2. **拿 token**：主机卡片 → 安装命令，复制 `AGENT_TOKEN`。
3. **端点上跑 agent**（Docker，同一镜像）：
   ```sh
   docker run -d --name sb-easy-agent --restart unless-stopped \
     --network host --cap-add NET_ADMIN --device /dev/net/tun \
     -e SB_EASY_SERVER=http://SERVER:51821 \
     -e AGENT_TOKEN=<该主机 token> \
     -v "$PWD/agent-data:/app/data" \
     sb-easy:latest sb-easy agent
   ```
   注意命令是 `sb-easy agent`（容器 CMD 整体替换，需带上 `sb-easy`）。
4. agent 启动后从服务器拉配置、跑 sing-box；sing-box 的配置里含一条连服务器的 WireGuard
   `endpoint` → 自动进内网。面板 Hosts 页该主机变在线。

### agent 的 sing-box 如何连内网（WireGuard endpoint）
在该主机的 Profile（full 模式）配置里放一条 sing-box endpoint：
```json
"endpoints": [{
  "type": "wireguard", "tag": "wg-internal",
  "address": ["10.59.32.X/24"],
  "private_key": "<该主机 WG 私钥>",
  "peers": [{
    "address": "SERVER_PUBLIC_IP", "port": 51820,
    "public_key": "<服务器 WG 公钥>", "pre_shared_key": "<psk>",
    "allowed_ips": ["0.0.0.0/0"], "persistent_keepalive_interval": 25
  }]
}]
```
（密钥来自面板为该主机分配的 WG peer / 主机的 WG 配置下载。）

## 三、节点只能国内解析（GeoDNS）时——让 agent 经服务器中转

若代理节点是只在国内能解析/连接的域名（GeoDNS），而 agent 在国际线路：让节点的
**DNS 解析 + 连接都经 `wg-internal` 走服务器（国内）出去**，agent 即表现得像在国内。
在该 Profile 里：

- DNS 加一个经隧道的解析器，并把节点域名指给它：
  ```json
  "dns": { "servers": [
    {"type":"udp","tag":"cn-dns","server":"223.5.5.5"},
    {"type":"udp","tag":"cn-server","server":"223.5.5.5","detour":"wg-internal"}
  ], "rules": [ {"domain_suffix":[".你的节点域名后缀"],"server":"cn-server"} ] }
  ```
- 每个节点出站加 `"detour": "wg-internal"`（连接经服务器）。
- 远程 rule-set 加 `"download_detour": "direct"`（否则启动时 WG 未就绪→下载失败→崩溃重启循环）。

> 这套都写在服务器的 Profile 里，**改一次服务器即同步到 agent**。

## 四、中心化配置同步
agent 每 ~10s 用 ETag 轮询 `/api/agent/config`；改了服务器的 Profile，agent 自动拉取并
reload sing-box。改一处 → 全端点生效，无需逐个登录。

## 五、运维
- **凭据**：服务器 `/root/workspace/sb-easy/.env`（JWT_SECRET / ADMIN_PASSWORD）。首次登录后在
  Users 页改密码。
- **备份**：DB 在 `./data/sb-easy.db`；`scripts/backup.sh`（在线备份+轮转，见脚本头 cron 示例）。
- **安全**：随机 `JWT_SECRET`；强 admin 密码；Clash API 监听 `127.0.0.1`；公网部署收紧
  `CORS_ORIGINS` 与防火墙。
- **健康**：容器 healthcheck + `restart: unless-stopped`，重启/宕机自恢复。
