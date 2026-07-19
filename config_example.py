# -*- coding: utf-8 -*-

# Outer-link authentication key. Keep this identical on A, B, and C.
# 用于保护 A↔B、C↔B 链路；必须是 >= 16 字符的高熵随机串。
B_AUTH_KEY = ""

# End-to-end business-data key. Keep this identical on A and C only.
# 不要把该密钥部署到 B；B 的 config.py 中可保持为空。
# 建议为两个密钥分别执行：python -c "import secrets;print(secrets.token_urlsafe(32))"
A_C_E2E_KEY = ""

# B server listen config.
B_LISTEN_HOST = "0.0.0.0"
B_LISTEN_PORT = 9001
B_SERVER_BACKLOG = 100

# Address used by A and C when dialing B.
B_SERVER_IP = "B_MACHINE_PUBLIC_IP"
B_SERVER_PORT = 9001

# A-side local service and worker pool.
LOCAL_SERVICE_ADDR = ("127.0.0.1", 80)
A_CONNECT_TIMEOUT = 5
A_RECONNECT_INTERVAL = 0.5
A_RECONNECT_MAX_RETRIES = 0
A_WORKERS = 4
# Multi-stream mode: one A connection serves multiple concurrent C clients.
# Set to True on both A and B to enable; False keeps the original 1-A-per-C behavior.
A_MULTI_STREAM = True

# C-side local proxy.
C_BIND_IP = "127.0.0.1"
C_LOCAL_LISTEN_PORT = 8080
C_LISTEN_BACKLOG = 128
C_CONNECT_TIMEOUT = 5
C_RECONNECT_INTERVAL = 2
C_RECONNECT_MAX_RETRIES = 0
C_ACCEPT_POLL = 0.5
E2E_HANDSHAKE_TIMEOUT = 10

# B pairing behavior.
C_WAIT_TIMEOUT = 10
WAITING_A_MAX = 64
KEEPER_JOIN_TIMEOUT = 5

# Framing and heartbeat behavior.
FRAME_MAX_PAYLOAD = 1 << 20
RECV_CHUNK_SIZE = 64 * 1024
MULTI_STREAM_PENDING_LIMIT = 8 * 1024 * 1024
HEARTBEAT_ENABLED = True
HEARTBEAT_INTERVAL = 15
HEARTBEAT_TIMEOUT = 45
RECV_POLL = 1.0
ALLOW_RAW_C_COMPAT = False

# Log behavior.
LOG_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
