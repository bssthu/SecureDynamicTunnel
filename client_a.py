# -*- coding: utf-8 -*-

import socket
import time
import threading

from config import (
    A_CONNECT_TIMEOUT,
    A_RECONNECT_INTERVAL,
    A_RECONNECT_MAX_RETRIES,
    A_WORKERS,
    B_SERVER_IP,
    B_SERVER_PORT,
    LOCAL_SERVICE_ADDR,
)
from framing import (
    FramedConn, FrameError, run_endpoint, safe_close_sock,
    FRAME_DATA, FRAME_PING, FRAME_PONG, FRAME_CLOSE,
)
from log_utils import log
from tunnel_common import ROLE_A, send_role_handshake

_shutdown_event = threading.Event()


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


def _one_round(worker_id=1):
    """完成一次：连 B → 等 C → 连本地服务 → 帧化双向转发（含心跳）。"""
    b_sock = None
    local_sock = None
    framed = None
    try:
        # 1. 拨号到 B
        b_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        b_sock.settimeout(A_CONNECT_TIMEOUT)
        b_sock.connect((B_SERVER_IP, B_SERVER_PORT))

        # 2. 握手认证（裸字节，与帧协议无关）
        send_role_handshake(b_sock, ROLE_A)
        b_sock.settimeout(None)
        log(f"[A-{worker_id}] connected_to_b {B_SERVER_IP}:{B_SERVER_PORT}")

        # 3. 切换为帧化连接，等 C 的第一份业务数据
        framed = FramedConn(b_sock, name=f"A-{worker_id}<->B")
        b_sock = None  # 所有权移交 framed
        log(f"[A-{worker_id}] 已挂载，等待 C 接入...")
        first_payload = _wait_first_data(framed)
        log(f"[A-{worker_id}] paired first_payload_bytes={len(first_payload)}")

        # 4. 连接本地服务，把第一份数据投递过去
        local_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        local_sock.settimeout(A_CONNECT_TIMEOUT)
        try:
            local_sock.connect(LOCAL_SERVICE_ADDR)
        except Exception as e:
            log(f"[A-{worker_id}] local_service_failed {LOCAL_SERVICE_ADDR}: {e}")
            raise
        local_sock.settimeout(None)
        log(f"[A-{worker_id}] local_service_connected {LOCAL_SERVICE_ADDR}")
        local_sock.sendall(first_payload)

        # 5. 进入双向帧化转发循环（含 PING/PONG 心跳与看门狗）
        run_endpoint(framed, local_sock, role_label=f"A-{worker_id}")
        log(f"[A-{worker_id}] session_closed")
        framed = None
        local_sock = None
    finally:
        if framed is not None:
            framed.close()
        safe_close_sock(b_sock)
        safe_close_sock(local_sock)


def connect_loop(worker_id=1):
    fail_count = 0
    try:
        while not _shutdown_event.is_set():
            try:
                _one_round(worker_id)
                fail_count = 0  # 一次完整会话成功后重置
            except Exception as e:
                fail_count += 1
                if A_RECONNECT_MAX_RETRIES and fail_count > A_RECONNECT_MAX_RETRIES:
                    log(f"[x] A-{worker_id} 连续 {fail_count - 1} 次重连失败 ({e})，放弃并退出。")
                    return
                log(f"[!] A-{worker_id} 链路中断 ({e})，{A_RECONNECT_INTERVAL} 秒后第 {fail_count} 次重试...")
                _shutdown_event.wait(A_RECONNECT_INTERVAL)
    except KeyboardInterrupt:
        log("\n[*] 收到退出信号，正常断开。")


def main():
    _shutdown_event.clear()
    worker_count = max(1, int(A_WORKERS))
    threads = []
    log(
        f"[*] A 客户端启动，file={__file__} "
        f"workers={worker_count} reconnect_interval={A_RECONNECT_INTERVAL}s"
    )
    for worker_id in range(1, worker_count + 1):
        t = threading.Thread(target=connect_loop, args=(worker_id,), daemon=True)
        t.start()
        threads.append(t)

    try:
        while any(t.is_alive() for t in threads):
            time.sleep(0.5)
    except KeyboardInterrupt:
        _shutdown_event.set()
        log("\n[*] 收到退出信号，正在停止 A workers...")


if __name__ == "__main__":
    main()
