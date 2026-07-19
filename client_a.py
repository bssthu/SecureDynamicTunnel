# -*- coding: utf-8 -*-

import socket
import time
import threading

from config import (
    A_CONNECT_TIMEOUT,
    A_MULTI_STREAM,
    A_RECONNECT_INTERVAL,
    A_RECONNECT_MAX_RETRIES,
    A_WORKERS,
    B_SERVER_IP,
    B_SERVER_PORT,
    LOCAL_SERVICE_ADDR,
)
from framing import (
    FramedConn, FrameError, run_endpoint, run_multi_stream_a_endpoint,
    safe_close_sock,
    FRAME_DATA, FRAME_PING, FRAME_PONG, FRAME_CLOSE,
)
from e2e import accept_client_hello
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
    framed.sock.settimeout(None)
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


def _one_round_single(worker_id=1):
    """单流模式：连B → 等C → 连本地服务 → 帧化双向转发。"""
    b_sock = None
    local_sock = None
    framed = None
    try:
        b_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        b_sock.settimeout(A_CONNECT_TIMEOUT)
        b_sock.connect((B_SERVER_IP, B_SERVER_PORT))
        send_cipher, recv_cipher = send_role_handshake(b_sock, ROLE_A)
        b_sock.settimeout(None)
        log(f"[A-{worker_id}] connected_to_b {B_SERVER_IP}:{B_SERVER_PORT}")

        framed = FramedConn(
            b_sock, name=f"A-{worker_id}<->B",
            send_cipher=send_cipher, recv_cipher=recv_cipher,
        )
        b_sock = None
        log(f"[A-{worker_id}] 已挂载，等待 C 接入...")
        client_hello = _wait_first_data(framed)
        server_hello, e2e_channel = accept_client_hello(client_hello)
        log(f"[A-{worker_id}] paired e2e_client_hello_bytes={len(client_hello)}")

        local_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        local_sock.settimeout(A_CONNECT_TIMEOUT)
        try:
            local_sock.connect(LOCAL_SERVICE_ADDR)
        except Exception as e:
            log(f"[A-{worker_id}] local_service_failed {LOCAL_SERVICE_ADDR}: {e}")
            raise
        local_sock.settimeout(None)
        log(f"[A-{worker_id}] local_service_connected {LOCAL_SERVICE_ADDR}")
        framed.send(FRAME_DATA, server_hello)

        run_endpoint(
            framed,
            local_sock,
            role_label=f"A-{worker_id}",
            data_channel=e2e_channel,
        )
        log(f"[A-{worker_id}] session_closed")
        framed = None
        local_sock = None
    finally:
        if framed is not None:
            framed.close()
        safe_close_sock(b_sock)
        safe_close_sock(local_sock)


def _one_round_multi(worker_id=1):
    """多流模式：连B后保持长连接，通过 run_multi_stream_a_endpoint 处理多个并发 C。"""
    b_sock = None
    framed = None
    try:
        b_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        b_sock.settimeout(A_CONNECT_TIMEOUT)
        b_sock.connect((B_SERVER_IP, B_SERVER_PORT))
        send_cipher, recv_cipher = send_role_handshake(b_sock, ROLE_A)
        b_sock.settimeout(None)
        log(f"[A-{worker_id}] connected_to_b(multi) {B_SERVER_IP}:{B_SERVER_PORT}")

        framed = FramedConn(
            b_sock, name=f"A-{worker_id}<->B",
            send_cipher=send_cipher, recv_cipher=recv_cipher,
        )
        b_sock = None
        log(f"[A-{worker_id}] 已挂载(多流模式)，等待 C 接入...")

        run_multi_stream_a_endpoint(
            framed, LOCAL_SERVICE_ADDR, A_CONNECT_TIMEOUT,
            role_label=f"A-{worker_id}",
        )
        log(f"[A-{worker_id}] multi_stream_session_closed")
        framed = None
    finally:
        if framed is not None:
            framed.close()
        safe_close_sock(b_sock)


def connect_loop(worker_id=1):
    one_round = _one_round_multi if A_MULTI_STREAM else _one_round_single
    fail_count = 0
    try:
        while not _shutdown_event.is_set():
            try:
                one_round(worker_id)
                fail_count = 0
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
        f"mode={'multi-stream' if A_MULTI_STREAM else 'single-stream'} "
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
