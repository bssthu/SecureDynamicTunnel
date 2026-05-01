# -*- coding: utf-8 -*-

import socket
import threading

from config import (
    B_SERVER_IP,
    B_SERVER_PORT,
    C_ACCEPT_POLL,
    C_BIND_IP,
    C_CONNECT_TIMEOUT,
    C_LISTEN_BACKLOG,
    C_LOCAL_LISTEN_PORT,
    C_RECONNECT_INTERVAL,
    C_RECONNECT_MAX_RETRIES,
)
from framing import FramedConn, run_endpoint, safe_close_sock, FRAME_PING
from log_utils import log
from tunnel_common import ROLE_C, send_role_handshake

_shutdown_event = threading.Event()
_active_socks = set()
_active_lock = threading.Lock()


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
    """尝试连接并认证到 B。失败按配置重试，全部失败返回 None。"""
    last_err = None
    attempt = 0
    while not _shutdown_event.is_set():
        attempt += 1
        b_sock = None
        try:
            b_sock = _track_sock(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            b_sock.settimeout(C_CONNECT_TIMEOUT)
            b_sock.connect((B_SERVER_IP, B_SERVER_PORT))

            # 握手认证（裸字节，与帧协议无关）
            send_role_handshake(b_sock, ROLE_C)

            b_sock.settimeout(None)
            return b_sock
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
    _track_sock(c_user_conn)
    b_sock = connect_to_b()
    if b_sock is None:
        # 一直重连不上：正确断开本地连接
        _untrack_sock(c_user_conn)
        safe_close_sock(c_user_conn)
        return

    framed = FramedConn(b_sock, name="C<->B")
    try:
        # 认证后的第一个包必须进入帧协议；先发一个 PING 作为协议标记帧。
        framed.send(FRAME_PING)
        # 用户裸字节 <-> 帧化的 B 链路。心跳/看门狗由 run_endpoint 内部处理。
        run_endpoint(framed, c_user_conn, role_label="C")
    except Exception as e:
        log(f"[!] 隧道转发异常: {e}")
        framed.close()
        safe_close_sock(c_user_conn)
    finally:
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
        f"listen=http://{C_BIND_IP}:{C_LOCAL_LISTEN_PORT}"
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
