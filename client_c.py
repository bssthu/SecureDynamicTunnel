# -*- coding: utf-8 -*-

import socket
import threading
import time
from itertools import count

from config import (
    A_MULTI_STREAM,
    B_SERVER_IP,
    B_SERVER_PORT,
    C_ACCEPT_POLL,
    C_BIND_IP,
    C_CONNECT_TIMEOUT,
    C_LISTEN_BACKLOG,
    C_LOCAL_LISTEN_PORT,
    C_RECONNECT_INTERVAL,
    C_RECONNECT_MAX_RETRIES,
    E2E_HANDSHAKE_TIMEOUT,
)
from framing import (
    FramedConn, run_endpoint, safe_close_sock,
    FRAME_CLOSE, FRAME_DATA, FRAME_ERROR, FRAME_PING, FRAME_PONG,
)
from e2e import E2EClientHandshake, E2EError
from log_utils import log
from tunnel_common import ROLE_C, send_role_handshake

_shutdown_event = threading.Event()
_active_socks = set()
_conn_id_counter = count(1)
_active_lock = threading.Lock()


def _establish_e2e(framed, c_user_conn):
    """Run the C↔A handshake through B and return the C-side data channel."""
    handshake = E2EClientHandshake()
    framed.sock.settimeout(E2E_HANDSHAKE_TIMEOUT)
    framed.send(FRAME_DATA, handshake.initial_packet)
    while True:
        ftype, payload = framed.recv_frame()
        if ftype == FRAME_DATA:
            return handshake.finish(payload)
        if ftype == FRAME_ERROR:
            if payload:
                c_user_conn.sendall(payload)
            raise E2EError("B 返回外层错误，端到端通道未建立")
        if ftype == FRAME_PING:
            framed.send(FRAME_PONG)
            continue
        if ftype == FRAME_PONG:
            continue
        if ftype == FRAME_CLOSE:
            raise E2EError("端到端握手期间链路关闭")
        raise E2EError(f"端到端握手期间收到意外帧: {ftype}")


def _track_sock(sock):
    if sock is not None:
        with _active_lock:
            _active_socks.add(sock)
    return sock


def _untrack_sock(sock):
    if sock is not None:
        with _active_lock:
            _active_socks.discard(sock)


def _close_active_socks():
    with _active_lock:
        socks = list(_active_socks)
        _active_socks.clear()
    for sock in socks:
        safe_close_sock(sock)


def connect_to_b():
    """尝试连接并认证到 B。成功返回 (sock, send_cipher, recv_cipher)；全部失败返回 None。"""
    last_err = None
    attempt = 0
    while not _shutdown_event.is_set():
        attempt += 1
        b_sock = None
        try:
            b_sock = _track_sock(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            b_sock.settimeout(C_CONNECT_TIMEOUT)
            b_sock.connect((B_SERVER_IP, B_SERVER_PORT))

            # 外层链路握手：X25519 ECDH + HMAC(B_AUTH_KEY)。
            send_cipher, recv_cipher = send_role_handshake(b_sock, ROLE_C)

            b_sock.settimeout(None)
            return b_sock, send_cipher, recv_cipher
        except Exception as e:
            last_err = e
            _untrack_sock(b_sock)
            safe_close_sock(b_sock)
            if C_RECONNECT_MAX_RETRIES:
                log(f"[!] 第 {attempt}/{C_RECONNECT_MAX_RETRIES} 次连接 B 失败: {e}")
                if attempt >= C_RECONNECT_MAX_RETRIES:
                    log(f"[x] 已达到最大重试次数，放弃连接 B (最后错误: {last_err})")
                    return None
            else:
                log(f"[!] 第 {attempt} 次连接 B 失败: {e}，{C_RECONNECT_INTERVAL}s 后重试")
            _shutdown_event.wait(C_RECONNECT_INTERVAL)
    return None


def bridge_handler(c_user_conn):
    cid = next(_conn_id_counter)
    started = time.monotonic()
    try:
        peer = c_user_conn.getpeername()
    except Exception:
        peer = ("?", 0)
    log(f"[C#{cid}] user_connected from={peer}")
    _track_sock(c_user_conn)
    result = connect_to_b()
    if result is None:
        log(f"[C#{cid}] no_b_connection, closing")
        _untrack_sock(c_user_conn)
        safe_close_sock(c_user_conn)
        return
    b_sock, send_cipher, recv_cipher = result

    framed = FramedConn(
        b_sock, name=f"C#{cid}<->B",
        send_cipher=send_cipher, recv_cipher=recv_cipher,
    )
    try:
        # 认证后的第一个包必须进入帧协议；先发一个 PING 作为协议标记帧。
        framed.send(FRAME_PING)
        log(f"[C#{cid}] tunnel_open b={b_sock.getpeername()}")
        # B↔C 始终是一条 TCP、一个流，无论 B 端运行单流还是多流模式：
        # 多流模式下 B 内部按 stream_id 复用 A 链路，对 C 暴露的依旧是干净的
        # FRAME_DATA / PING / PONG / CLOSE，因此 C 端无需感知模式差异。
        e2e_channel = _establish_e2e(framed, c_user_conn)
        log(f"[C#{cid}] e2e_established")
        run_endpoint(
            framed,
            c_user_conn,
            role_label=f"C#{cid}",
            data_channel=e2e_channel,
        )
    except Exception as e:
        log(f"[!] [C#{cid}] 隧道转发异常: {e}")
        framed.close()
        safe_close_sock(c_user_conn)
    finally:
        dur_ms = int((time.monotonic() - started) * 1000)
        log(f"[C#{cid}] closed duration_ms={dur_ms}")
        _untrack_sock(b_sock)
        _untrack_sock(c_user_conn)


def main():
    _shutdown_event.clear()
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _track_sock(ls)
    try:
        ls.bind((C_BIND_IP, C_LOCAL_LISTEN_PORT))
    except OSError as e:
        _untrack_sock(ls)
        safe_close_sock(ls)
        if e.errno in (98, 10048):
            log(f"[x] 本地监听端口 {C_BIND_IP}:{C_LOCAL_LISTEN_PORT} 已被占用，请先结束旧的 client_c 进程或占用该端口的程序")
            return
        raise
    ls.listen(C_LISTEN_BACKLOG)
    ls.settimeout(C_ACCEPT_POLL)
    log(
        f"[*] 客户端代理启动，file={__file__} "
        f"listen=http://{C_BIND_IP}:{C_LOCAL_LISTEN_PORT} "
        f"mode={'multi-stream' if A_MULTI_STREAM else 'single-stream'}"
    )

    try:
        while not _shutdown_event.is_set():
            try:
                c_user, _ = ls.accept()
            except socket.timeout:
                continue
            threading.Thread(target=bridge_handler, args=(c_user,), daemon=True).start()
    except KeyboardInterrupt:
        log("\n[*] 收到退出信号，关闭监听...")
    finally:
        _shutdown_event.set()
        _untrack_sock(ls)
        safe_close_sock(ls)
        _close_active_socks()


if __name__ == "__main__":
    main()
