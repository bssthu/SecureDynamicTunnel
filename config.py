# -*- coding: utf-8 -*-

# Shared authentication key. Keep this identical on A, B, and C.
SHARED_KEY = "Your_Super_Strong_Random_Secret_Key_2026"

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

# C-side local proxy.
C_BIND_IP = "127.0.0.1"
C_LOCAL_LISTEN_PORT = 8080
C_LISTEN_BACKLOG = 10
C_CONNECT_TIMEOUT = 5
C_RECONNECT_INTERVAL = 2
C_RECONNECT_MAX_RETRIES = 0
C_ACCEPT_POLL = 0.5

# B pairing behavior.
C_WAIT_TIMEOUT = 10
WAITING_A_MAX = 64
KEEPER_JOIN_TIMEOUT = 5

# Framing and heartbeat behavior.
FRAME_MAX_PAYLOAD = 1 << 20
HEARTBEAT_ENABLED = True
HEARTBEAT_INTERVAL = 15
HEARTBEAT_TIMEOUT = 45
RECV_POLL = 1.0
ALLOW_RAW_C_COMPAT = False

# Log behavior.
LOG_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
