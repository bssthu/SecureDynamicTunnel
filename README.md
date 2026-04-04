# 极简三端内网穿透加密隧道 (SDT-3)

本方案用于在没有公网 IP、没有 VPN 的情况下，通过一台公网中转机器 B，实现 A 机器服务向 C 机器的映射。

### 角色定义
- **A (Service Source)**: 内网机器，提供原始服务（如 Web、数据库）。
- **B (Public Bridge)**: 拥有公网 IP 的 Linux 机器，充当流量中转站。
- **C (End User)**: 需要访问服务的机器。访问自身的 localhost 即可穿透到 A。

### 核心安全机制
1. **动态 HMAC 校验**: `secret_tool.py` 使用 SHA256 算法。Token 包含当前时间戳，每 60 秒自动失效。
2. **零开放端口**: A 机器不需要在防火墙开启任何入站端口，通过主动外连 B 实现穿透。
3. **隔离性**: 中转机器 B 不解密流量，仅做二进制转发。

### 快速开始
1. **统一配置**: 修改 `secret_tool.py` 中的 `SHARED_KEY`。
2. **部署 B (Linux)**: 
   - 运行 `python3 server_b.py`
   - 确保云主机关联的安全组已开放 TCP `9001` 端口。
3. **部署 A (Windows/Linux)**:
   - 修改 `client_a.py` 中的 `B_SERVER_IP` 为 B 的公网地址。
   - 运行 `python client_a.py`。
4. **部署 C (Windows)**:
   - 修改 `client_c.py` 中的 `B_SERVER_IP`。
   - 运行 `python client_c.py`。
   - 打开浏览器访问 `http://127.0.0.1:8080`。

### 注意事项
- 本脚本为双向同步长连接设计。若需极高并发，建议将 B 机器的 `bridge` 函数改为异步 IO 实现。
- 建议使用 `nohup` 或 `screen` 在 B 机器后台运行。
