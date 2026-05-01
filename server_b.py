# -*- coding: utf-8 -*-

import socket
import threading
import time
from collections import deque
from itertools import count

from config import (
    B_LISTEN_HOST,
    B_LISTEN_PORT,
    B_SERVER_BACKLOG,
    C_WAIT_TIMEOUT,
    KEEPER_JOIN_TIMEOUT,
    WAITING_A_MAX,
)
from framing import (
    FramedConn, run_bridge, safe_close_sock, waiting_keepalive,
    FRAME_DATA,
)
from log_utils import log
from tunnel_common import ROLE_A, verify_role_handshake

_NO_A_BODY = b'{"error":"no available tunnel peer A"}'
NO_A_HTTP_RESPONSE = b"".join([
    b"HTTP/1.1 503 Service Unavailable\r\n",
    b"Content-Type: application/json; charset=utf-8\r\n",
    b"Connection: close\r\n",
    b"Content-Length: ",
    str(len(_NO_A_BODY)).encode("ascii"),
    b"\r\n\r\n",
    _NO_A_BODY,
])

_active_bridge_count = 0
_active_bridge_lock = threading.Lock()


def _inc_active_bridge_count():
    global _active_bridge_count
    with _active_bridge_lock:
        _active_bridge_count += 1
        return _active_bridge_count


def _dec_active_bridge_count():
    global _active_bridge_count
    with _active_bridge_lock:
        _active_bridge_count -= 1
        return _active_bridge_count


def _get_active_bridge_count():
    with _active_bridge_lock:
        return _active_bridge_count


def _start_bridge(framed_a, framed_c, a_id):
    """在独立线程中跑 run_bridge，避免阻塞连接处理线程。"""
    active = _inc_active_bridge_count()
    started_at = time.monotonic()
    log(f"[***] A-C 配对完成: a_id={a_id} active_bridge_count={active}")

    def _run():
        try:
            run_bridge(framed_a, framed_c)
        finally:
            duration_ms = int((time.monotonic() - started_at) * 1000)
            active_after = _dec_active_bridge_count()
            log(
                f"[***] A-C 隧道已关闭: a_id={a_id} "
                f"bridge_duration_ms={duration_ms} active_bridge_count={active_after}"
            )

    threading.Thread(target=_run, daemon=True).start()


def _send_no_a_response(framed_c):
    """通过 C 侧帧协议返回 HTTP 503，避免上游只看到 EOF。"""
    try:
        framed_c.send(FRAME_DATA, NO_A_HTTP_RESPONSE)
    except Exception as e:
        log(f"[!] 发送 no-A HTTP 503 失败: {e}")
    finally:
        framed_c.close()


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((B_LISTEN_HOST, B_LISTEN_PORT))
    server.listen(B_SERVER_BACKLOG)
    log(
        f"[*] 中转机器 B 已启动，file={__file__} "
        f"listen={B_LISTEN_HOST}:{B_LISTEN_PORT}"
    )

    waiting_a = deque()
    waiting_cond = threading.Condition()
    next_a_id = count(1)

    def _stats_locked():
        return (
            f"waiting_a_count={len(waiting_a)} "
            f"active_bridge_count={_get_active_bridge_count()}"
        )

    def _remove_waiting_a_locked(item, reason="", close=False):
        try:
            waiting_a.remove(item)
        except ValueError:
            return False

        if reason:
            log(f"[!] 释放等待中的 A: a_id={item['id']} reason={reason}")
        item["event"].set()
        if close:
            item["framed"].close()
        waiting_cond.notify_all()
        return True

    def _prune_closed_waiting_a_locked():
        for item in list(waiting_a):
            if item["framed"].closed:
                _remove_waiting_a_locked(item, reason="连接已关闭", close=False)

    def _release_all_waiting_a_locked(reason=""):
        for item in list(waiting_a):
            _remove_waiting_a_locked(item, reason=reason, close=True)

    def _pop_waiting_a_locked():
        while waiting_a:
            item = waiting_a.popleft()
            item["event"].set()
            if item["framed"].closed:
                log(f"[!] 跳过已关闭的 A: a_id={item['id']} {_stats_locked()}")
                continue
            waiting_cond.notify_all()
            return item
        return None

    def _claim_waiting_a(deadline):
        with waiting_cond:
            while True:
                item = _pop_waiting_a_locked()
                if item is not None:
                    log(f"[+] C 获取到等待中的 A: a_id={item['id']} {_stats_locked()}")
                    return item

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None

                log(
                    f"[*] C 接入但暂无可用 A，最多等待 {remaining:.1f}s "
                    f"{_stats_locked()}"
                )
                waiting_cond.wait(timeout=remaining)

    def _handle_role_a(framed):
        """ROLE_A 上线：加入等待队列，启动等待期心跳守护线程。"""
        promote_event = threading.Event()
        item = {
            "id": next(next_a_id),
            "framed": framed,
            "event": promote_event,
            "thread": None,
        }

        def _keeper():
            alive = waiting_keepalive(framed, promote_event, label=f"B<->A#{item['id']}")
            if not alive:
                with waiting_cond:
                    removed = _remove_waiting_a_locked(
                        item,
                        reason="等待期断开",
                        close=False,
                    )
                    if removed:
                        log(f"[-] A 等待连接已断开: a_id={item['id']} {_stats_locked()}")

        with waiting_cond:
            _prune_closed_waiting_a_locked()
            if len(waiting_a) >= WAITING_A_MAX:
                log(
                    f"[!] A 等待队列已满，拒绝新 A: "
                    f"a_id={item['id']} {_stats_locked()}"
                )
                framed.close()
                return

            t = threading.Thread(target=_keeper, daemon=True)
            item["thread"] = t
            waiting_a.append(item)
            waiting_cond.notify()
            log(f"[+] A 已挂机: a_id={item['id']} {_stats_locked()}")

        t.start()

    def _handle_role_c(framed_c):
        """ROLE_C 上线：等待可用 A，抢占后桥接；超时则返回 HTTP 503。"""
        started_at = time.monotonic()
        deadline = started_at + C_WAIT_TIMEOUT

        while True:
            item = _claim_waiting_a(deadline)
            if item is None:
                waited_ms = int((time.monotonic() - started_at) * 1000)
                log(
                    f"[!] C 等待 A 超时，返回 503: "
                    f"c_wait_timeout_ms={waited_ms} "
                    f"waiting_a_count=0 active_bridge_count={_get_active_bridge_count()}"
                )
                _send_no_a_response(framed_c)
                return

            framed_a = item["framed"]
            thread_a = item["thread"]

            # 通知 A 的 keeper 退出（让出 socket 控制权），并等其结束。
            item["event"].set()
            if thread_a is not None:
                thread_a.join(timeout=KEEPER_JOIN_TIMEOUT)
                if thread_a.is_alive():
                    log(f"[!] A keeper 未及时退出，关闭并尝试下一个 A: a_id={item['id']}")
                    framed_a.close()
                    continue

            if framed_a.closed:
                log(f"[!] A 在配对瞬间已断开，尝试下一个 A: a_id={item['id']}")
                continue

            _start_bridge(framed_a, framed_c, item["id"])
            return

    def _handle_connection(conn, addr):
        try:
            role, ok = verify_role_handshake(conn)
            if not ok:
                log(f"[!] 拒绝非法连接: {addr} role={role!r}")
                safe_close_sock(conn)
                return

            log(f"[+] {role} 认证成功: {addr}")
            framed = FramedConn(conn, name=f"B<->{role}")

            if role == ROLE_A:
                _handle_role_a(framed)
            else:
                _handle_role_c(framed)

        except Exception as e:
            log(f"[!] 处理连接时出错: {addr} {e}")
            safe_close_sock(conn)

    try:
        while True:
            conn, addr = server.accept()
            log(f"[*] TCP 接入: {addr}")
            threading.Thread(
                target=_handle_connection,
                args=(conn, addr),
                daemon=True,
            ).start()
    except KeyboardInterrupt:
        log("\n[*] 收到退出信号，关闭服务...")
    finally:
        with waiting_cond:
            _release_all_waiting_a_locked(reason="服务退出")
        safe_close_sock(server)


if __name__ == "__main__":
    main()
