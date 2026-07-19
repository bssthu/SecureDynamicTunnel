# 极简三端内网穿透加密隧道 (SDT-3)

本方案用于在没有公网 IP、没有 VPN 的情况下，通过一台公网中转机器 B，实现 A 机器服务向 C 机器的映射。

### 角色定义
- **A (Service Source)**: 内网机器，提供原始服务（如 Web、数据库）。
- **B (Public Bridge)**: 拥有公网 IP 的 Linux 机器，充当流量中转站。
- **C (End User)**: 需要访问服务的机器。访问自身的 localhost 即可穿透到 A。

### 快速开始
1. **统一配置**: 修改 `config.py` 中的 `SHARED_KEY`、B 地址、端口和 worker 等参数。生成强密钥：`python -c "import secrets;print(secrets.token_urlsafe(32))"`。然后在三台机器上各执行 `pip install -r requirements.txt` 安装 `cryptography` 依赖。
2. **部署 B (Linux)**:
   - 运行 `python3 server_b.py`
   - 确保云主机关联的安全组已开放 TCP `9001` 端口。
3. **部署 A (Windows/Linux)**:
   - 修改 `config.py` 中的 `B_SERVER_IP` 为 B 的公网地址。
   - 按需调整 `A_WORKERS`；HTTP/SSE 并发越高，建议保持多条 A 连接常驻等待。
   - 运行 `python client_a.py`。
4. **部署 C (Windows)**:
   - 修改 `config.py` 中的 `B_SERVER_IP`；如需局域网内其他机器访问，把 `C_BIND_IP` 改为 `0.0.0.0` 或具体网卡地址。
   - 运行 `python client_c.py`。
   - 打开浏览器访问 `http://127.0.0.1:8080`（或 `config.py` 中配置的 `C_BIND_IP:C_LOCAL_LISTEN_PORT`）。

### 核心安全机制
1. **X25519 + ChaCha20-Poly1305 端到端加密**：A↔B、C↔B 在 TCP 握手阶段交换临时 X25519 公钥与随机 nonce，并用预共享密钥 `SHARED_KEY` 通过 HMAC-SHA256 互相验证（防 MITM）；随后用 HKDF-SHA256 派生两个方向独立的 ChaCha20-Poly1305 会话密钥，所有应用帧均加密 + 鉴权，自带递增 seq 防重放。即使 B 被攻陷或链路被抓包，也无法解密历史/未来流量（Forward Secrecy）。
2. **零开放端口**: A 机器不需要在防火墙开启任何入站端口，通过主动外连 B 实现穿透。
3. **隔离性**: 中转机器 B 不解密业务流量，仅负责帧透传与配对管理。
4. **SHARED_KEY 校验**：`crypto.py` 在导入时强制 `SHARED_KEY` 长度 ≥ 16 字节且不得为常见占位值（空串 / `CHANGE_ME` / 旧 README 默认值等），否则进程立即退出，避免误用弱密钥。

### 链路与协议
- 握手：`8B 角色名 + 32B X25519 临时公钥 + 16B nonce + 32B HMAC` 双向交换；任一字段被篡改 / MAC 不匹配，B 立即关闭连接。
- 帧协议（`framing.py`）：`1B 类型 + 4B 密文长度 + AEAD 密文(含 16B tag)`，类型包括 `DATA / PING / PONG / CLOSE / STREAM_OPEN / STREAM_DATA / STREAM_CLOSE / PAIR_REQUEST`。AAD = 报头；nonce = `4B 0x00 || 8B seq`。
- 心跳：每条 TCP 链路每 `HEARTBEAT_INTERVAL=15s` 发一次 PING；`HEARTBEAT_TIMEOUT=45s` 内未收到任何帧即判定对端死亡，主动关闭链路。
- 断线重连：A、C 均支持自动重连。`config.py` 中的 `A_RECONNECT_MAX_RETRIES` / `C_RECONNECT_MAX_RETRIES` 为 `0` 表示无限重连；>0 时连续失败超过该次数即放弃（A worker 退出；C 关闭对应的本地用户连接）。A 默认失败重连间隔为 `A_RECONNECT_INTERVAL=0.5s`，一次业务隧道结束后会立即重连补位。
- 配对策略：A 启动后会按 `A_WORKERS=4` 主动拨号到 B，B 维护等待 A 队列；C 仅在本地端口收到业务请求时才按需连 B。若业务请求到达时 B 暂无可用 A，B 会等待最多 `C_WAIT_TIMEOUT=10s`；期间有 A 补位则立即配对，否则通过 C 侧帧协议返回 `HTTP 503`，再关闭本次连接，避免上游只看到 EOF。

### 注意事项
- B 现在感知应用层帧（用于配对管理与心跳），但仍**不解密业务数据**——`DATA` 帧的 payload 原样透传。
- 三端必须同时升级到当前版本，新旧版本之间的握手/帧格式不兼容。
- `config.py` 负责集中配置；`tunnel_common.py` 负责三端复用的角色名、握手收发和认证辅助逻辑。
- B 的 A 等待队列上限默认为 `WAITING_A_MAX=64`；超过后会拒绝新的 A 挂机连接。
- 本脚本为双向同步长连接设计。若需极高并发，建议把 B 的转发循环改为异步 IO 实现。
- 建议使用 `nohup` 或 `screen` 在 B 机器后台运行。
