# 极简三端内网穿透加密隧道 (SDT-3)

本方案用于在没有公网 IP、没有 VPN 的情况下，通过一台公网中转机器 B，实现 A 机器服务向 C 机器的映射。

### 角色定义

- **A (Service Source)**：内网机器，提供原始 TCP 服务（如 Web、数据库）。
- **B (Public Bridge)**：拥有公网 IP 的中转机器，负责认证、配对、心跳和密文转发。
- **C (End User)**：需要访问服务的机器。连接 C 的本地监听端口即可穿透到 A。

### 快速开始

1. **安装依赖**：在三台机器上分别执行 `python -m pip install -r requirements.txt`。
2. **创建本地配置**：把 `config_example.py` 复制为不会被 Git 跟踪的 `config.py`。
   - Windows PowerShell：`Copy-Item config_example.py config.py`
   - Linux/macOS：`cp config_example.py config.py`
3. **生成并分发两个独立密钥**：可分别执行 `python -c "import secrets;print(secrets.token_urlsafe(32))"` 生成。
   - `B_AUTH_KEY`：A、B、C 必须相同，用于认证并加密 A↔B、C↔B 外层链路。
   - `A_C_E2E_KEY`：只能部署到 A、C，二者必须相同；B 上应保持为空，也不要与 `B_AUTH_KEY` 复用。
4. **部署 B**：设置 `B_LISTEN_HOST`、`B_LISTEN_PORT`、`B_AUTH_KEY` 和 `A_MULTI_STREAM`，运行 `python server_b.py`；同时在安全组/防火墙开放对应 TCP 端口（默认 `9001`）。
5. **部署 A**：设置 `B_SERVER_IP`、`B_SERVER_PORT`、`LOCAL_SERVICE_ADDR`、两个密钥和 `A_MULTI_STREAM`，运行 `python client_a.py`。A 与 B 的 `A_MULTI_STREAM` 必须一致。
6. **部署 C**：设置 B 地址、两个密钥和本地监听参数，运行 `python client_c.py`。默认可访问 `http://127.0.0.1:8080`；若代理的不是 HTTP 服务，请使用对应的 TCP 客户端。

### 核心安全机制

1. **外层链路加密**：A↔B、C↔B 使用临时 X25519、`B_AUTH_KEY` HMAC 认证、HKDF-SHA256 和 ChaCha20-Poly1305。B 会终止这两类外层会话，以处理角色、心跳、配对和多流路由。
2. **A↔C 端到端业务加密**：每个业务流都会通过 B 交换临时 X25519 公钥和随机 nonce，并使用仅 A/C 持有的 `A_C_E2E_KEY` 认证握手。随后双方派生两个方向独立的 ChaCha20-Poly1305 密钥；业务字节在进入外层 `DATA` 帧前已经加密。
3. **B 的信任边界**：B 可以看到连接、帧类型、长度、时序和 `stream_id`，也可以丢弃、重放、破坏或中断连接；只要 B 没有 `A_C_E2E_KEY`，它不能解密业务数据，也不能在不被 A/C 检测的情况下篡改或伪造业务数据。
4. **前向保密**：外层链路和每个 A↔C 业务流均使用临时 X25519 密钥。后来单独泄露预共享密钥，不能直接解密此前记录的会话；密钥泄露后的新会话不再安全，应立即轮换密钥。
5. **零开放端口**：A 不需要开放入站端口，通过主动连接 B 实现穿透。
6. **密钥校验**：相关进程启动时要求所需密钥至少 16 个字符且不能是常见占位值。长度校验不能代替高熵要求，建议始终使用至少 32 个字符的随机密钥。

### 链路与协议

- 外层握手：A/C→B 为 `8B 角色名 + 32B X25519 公钥 + 16B nonce + 32B HMAC`；B→A/C 为 `32B X25519 公钥 + 16B nonce + 32B HMAC`。认证失败时，检测到问题的一端关闭连接。
- 外层帧：`1B 类型 + 4B 密文长度 + AEAD 密文（含 16B tag）`。类型包括 `DATA / PING / PONG / CLOSE / PAIR / PAIR_ACK / STREAM_CLOSE / ERROR`；报头作为 AAD，nonce 为 `4B 0x00 || 8B seq`。
- 端到端数据：`DATA` 的业务部分是 A↔C AEAD 密文。多流模式下，B 使用的 2B `stream_id` 位于端到端密文之外、外层 AEAD 之内，因此 B 可以路由但不能读取业务内容。
- 心跳：链路按 `HEARTBEAT_INTERVAL=15s` 发送 PING；`HEARTBEAT_TIMEOUT=45s` 内未收到任何帧则关闭链路。
- 断线重连：重试上限为 `0` 时无限重试。当前 A 的正数上限表示初次失败后的最大重试次数；C 的正数上限表示总连接尝试次数，两者语义暂不完全一致。
- 配对策略：默认 `A_MULTI_STREAM=True`，一条 A 连接可承载多个并发 C，B 在可用 A 连接间轮询分配；单流模式下，一条 A 连接一次只服务一个 C。没有 A 时最多等待 `C_WAIT_TIMEOUT=10s`。

### 注意事项

- 三端必须同时升级到当前协议版本；旧版不支持密钥拆分和内层端到端数据格式。
- 无可用 A 时，B 通过外层 `ERROR` 帧返回 HTTP 503。该响应只适用于 HTTP；代理数据库等其他 TCP 协议时，客户端会收到不属于其协议的错误数据。
- `A_WORKERS` 在多流模式下主要用于冗余和分担连接，在单流模式下也决定可同时服务的 C 数量。
- `WAITING_A_MAX=64` 限制 B 接受的等待 A 数量；在多流模式下，它限制常驻 A 连接池大小。
- `C_BIND_IP=0.0.0.0` 会把本地代理暴露给可访问 C 的其他机器。远端应连接 C 的实际网卡地址，而不是 `0.0.0.0`。
- B 当前采用线程式并发，尚未提供极高并发场景的性能基准。
- 生产环境可使用 systemd、容器或其他进程管理器托管三个进程。
