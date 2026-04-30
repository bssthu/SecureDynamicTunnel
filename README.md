# 极简三端内网穿透加密隧道 (SDT-3)

本方案用于在没有公网 IP、没有 VPN 的情况下，通过一台公网中转机器 B，实现 A 机器服务向 C 机器的映射。

### 角色定义
- **A (Service Source)**: 内网机器，提供原始服务（如 Web、数据库）。
- **B (Public Bridge)**: 拥有公网 IP 的 Linux 机器，充当流量中转站。
- **C (End User)**: 需要访问服务的机器。访问自身的 localhost 即可穿透到 A。

### 核心安全机制
1. **动态 HMAC 校验**: `secret_tool.py` 使用 SHA256 算法。Token 包含当前时间戳，每 60 秒自动失效。
2. **零开放端口**: A 机器不需要在防火墙开启任何入站端口，通过主动外连 B 实现穿透。
3. **隔离性**: 中转机器 B 不解密业务流量，仅负责帧透传与配对管理。

### 链路与协议
- A、C 都通过 8 字节角色名 + 32 字节 HMAC 完成与 B 的握手认证。
- 认证后所有通信走 `framing.py` 定义的应用层帧协议：`1B 类型 + 4B 长度 + payload`，类型包括 `DATA / PING / PONG / CLOSE`。
- 心跳：每条 TCP 链路每 `HEARTBEAT_INTERVAL=15s` 发一次 PING；`HEARTBEAT_TIMEOUT=45s` 内未收到任何帧即判定对端死亡，主动关闭链路。
- 断线重连：A、C 均支持自动重连。`RECONNECT_MAX_RETRIES = 0` 表示无限重连；>0 时连续失败超过该次数即放弃（A 退出进程；C 关闭对应的本地用户连接）。
- 配对策略：A 启动后会主动拨号到 B 并挂机等待；C 仅在本地端口收到业务请求时才按需连 B。若业务请求到达时 B 上没有可用的 A，B 会立即向 C 回送 `CLOSE` 帧，C 随即关闭本次本地用户连接，避免浏览器等到超时。三个进程的启动顺序无关，只要业务请求发起的瞬间 A、B、C 三端都在线即可正常穿透。

### 快速开始
1. **统一配置**: 修改 `secret_tool.py` 中的 `SHARED_KEY`。
2. **部署 B (Linux)**:
   - 运行 `python3 server_b.py`
   - 确保云主机关联的安全组已开放 TCP `9001` 端口。
3. **部署 A (Windows/Linux)**:
   - 修改 `client_a.py` 中的 `B_SERVER_IP` 为 B 的公网地址。
   - 运行 `python client_a.py`。
4. **部署 C (Windows)**:
   - 修改 `client_c.py` 中的 `B_SERVER_IP`；如需局域网内其他机器访问，把 `BIND_IP` 改为 `0.0.0.0` 或具体网卡地址。
   - 运行 `python client_c.py`。
   - 打开浏览器访问 `http://127.0.0.1:8080`（或上面配置的 `BIND_IP:LOCAL_LISTEN_PORT`）。

### 注意事项
- B 现在感知应用层帧（用于配对管理与心跳），但仍**不解密业务数据**——`DATA` 帧的 payload 原样透传。
- 三端必须同时升级到当前版本，新旧版本之间的握手/帧格式不兼容。
- 本脚本为双向同步长连接设计。若需极高并发，建议把 B 的转发循环改为异步 IO 实现。
- 建议使用 `nohup` 或 `screen` 在 B 机器后台运行。
