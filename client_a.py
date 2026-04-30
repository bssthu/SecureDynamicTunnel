# -*- coding: utf-8 -*-

import socket
import time
import threading
from secret_tool import generate_token
from framing import (
    FramedConn, FrameError, run_endpoint, safe_close_sock,
    FRAME_DATA, FRAME_PING, FRAME_PONG, FRAME_CLOSE,
)

# 配置
B_SERVER_IP = "B_MACHINE_PUBLIC_IP"   # 填写 B 的公网 IP
B_PORT = 9001
LOCAL_SERVICE_ADDR = ("127.0.0.1", 80)  # A 机器上服务的真实地址

# 断线重连配置
CONNECT_TIMEOUT = 5            # 单次连接超时(秒)
RECONNECT_INTERVAL = 5         # 重试间隔(秒)
RECONNECT_MAX_RETRIES = 0      # 0 = 无限重连；>0 时连续失败超过该次数即退出


def _wait_first_data(framed):
    """
    在隧道刚建立、还没有真正业务流量的"挂机"阶段：
    阻塞等待 B 推过来的第一帧 DATA（说明 C 已经接入并发了第一份数据）。
    期间也要正确响应 PING，丢弃 PONG。
    返回首份 payload。
    """
    framed.sock.settimeout(None)  # 等 C 接入可能很久
    while True:
        ftype, payload = framed.recv_frame()
        if ftype == FRAME_DATA:
            return payload
        elif ftype == FRAME_PING:
            framed.send(FRAME_PONG)
        elif ftype == FRAME_PONG:
            continue
        elif ftype == FRAME_CLOSE:
            raise FrameError("挂机阶段收到 CLOSE")
        else:
            raise FrameError(f"挂机阶段未知帧类型: {ftype}")


def _one_round():
    """完成一次：连 B → 等 C → 连本地服务 → 帧化双向转发（含心跳）。"""
    b_sock = None
    local_sock = None
    framed = None
    try:
        # 1. 拨号到 B
        b_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        b_sock.settimeout(CONNECT_TIMEOUT)
        b_sock.connect((B_SERVER_IP, B_PORT))

        # 2. 握手认证（裸字节，与帧协议无关）
        b_sock.sendall("ROLE_A  ".encode())
        b_sock.sendall(generate_token("ROLE_A"))
        b_sock.settimeout(None)

        # 3. 切换为帧化连接，等 C 的第一份业务数据
        framed = FramedConn(b_sock, name="A<->B")
        b_sock = None  # 所有权移交 framed
        print("[A] 已挂载，等待 C 接入...")
        first_payload = _wait_first_data(framed)

        # 4. 连接本地服务，把第一份数据投递过去
        local_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        local_sock.settimeout(CONNECT_TIMEOUT)
        local_sock.connect(LOCAL_SERVICE_ADDR)
        local_sock.settimeout(None)
        local_sock.sendall(first_payload)

        # 5. 进入双向帧化转发循环（含 PING/PONG 心跳与看门狗）
        run_endpoint(framed, local_sock, role_label="A")
        framed = None
        local_sock = None
    finally:
        if framed is not None:
            framed.close()
        safe_close_sock(b_sock)
        safe_close_sock(local_sock)


def connect_loop():
    fail_count = 0
    try:
        while True:
            try:
                _one_round()
                fail_count = 0  # 一次完整会话成功后重置
            except Exception as e:
                fail_count += 1
                if RECONNECT_MAX_RETRIES and fail_count > RECONNECT_MAX_RETRIES:
                    print(f"[x] 连续 {fail_count - 1} 次重连失败 ({e})，放弃并退出。")
                    return
                print(f"[!] 链路中断 ({e})，{RECONNECT_INTERVAL} 秒后第 {fail_count} 次重试...")
                time.sleep(RECONNECT_INTERVAL)
    except KeyboardInterrupt:
        print("\n[*] 收到退出信号，正常断开。")


if __name__ == "__main__":
    connect_loop()
