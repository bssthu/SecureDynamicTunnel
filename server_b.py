# -*- coding: utf-8 -*-

import socket
import threading
import time
from collections import deque
from itertools import count

from config import (
    A_MULTI_STREAM,
    B_LISTEN_HOST,
    B_LISTEN_PORT,
    B_SERVER_BACKLOG,
    C_WAIT_TIMEOUT,
    HEARTBEAT_ENABLED,
    HEARTBEAT_TIMEOUT,
    KEEPER_JOIN_TIMEOUT,
    RECV_POLL,
    WAITING_A_MAX,
)
from framing import (
    FramedConn, run_bridge, safe_close_sock, waiting_keepalive,
    FRAME_DATA, FRAME_ERROR, FRAME_PING, FRAME_PONG, FRAME_CLOSE,
    FRAME_PAIR, FRAME_PAIR_ACK, FRAME_STREAM_CLOSE,
    STREAM_ID_STRUCT, STREAM_ID_LEN,
    _heartbeat_loop,
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
    """通过外层 ERROR 帧返回 HTTP 503，不冒充 A↔C 端到端业务数据。"""
    try:
        framed_c.send(FRAME_ERROR, NO_A_HTTP_RESPONSE)
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
        f"listen={B_LISTEN_HOST}:{B_LISTEN_PORT} "
        f"multi_stream={'on' if A_MULTI_STREAM else 'off'}"
    )

    waiting_a = deque()      # 单流模式：等待被 C 取走的 A
    multi_a = deque()        # 多流模式：常驻的 A（不会被取走）
    waiting_cond = threading.Condition()
    next_a_id = count(1)

    def _stats_locked():
        return (
            f"waiting_a_count={len(waiting_a)} "
            f"multi_a_count={len(multi_a)} "
            f"active_bridge_count={_get_active_bridge_count()}"
        )

    # ---- 单流模式的队列管理 ----

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

    # ---- 多流模式的 A 队列管理 ----

    def _remove_multi_a_locked(item, reason="", close=False):
        try:
            multi_a.remove(item)
        except ValueError:
            return False
        if reason:
            log(f"[!] 移除多流 A: a_id={item['id']} reason={reason}")
        if close:
            item["framed"].close()
        waiting_cond.notify_all()
        return True

    def _release_all_multi_a_locked(reason=""):
        for item in list(multi_a):
            _remove_multi_a_locked(item, reason=reason, close=True)

    def _pick_multi_a_locked():
        for _ in range(len(multi_a)):
            item = multi_a.popleft()
            if item["framed"].closed:
                log(f"[!] remove_closed_multi_a a_id={item['id']} {_stats_locked()}")
                continue
            multi_a.append(item)
            return item
        waiting_cond.notify_all()
        return None

    def _claim_multi_a(deadline):
        with waiting_cond:
            while True:
                item = _pick_multi_a_locked()
                if item is not None:
                    return item
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                log(
                    f"[*] C 接入但暂无可用多流 A，最多等待 {remaining:.1f}s "
                    f"{_stats_locked()}"
                )
                waiting_cond.wait(timeout=remaining)

    # ---- 单流 A 处理 ----

    def _handle_role_a_single(framed):
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
                        item, reason="等待期断开", close=False,
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
            log(f"[+] A 已挂机(单流): a_id={item['id']} {_stats_locked()}")

        t.start()

    # ---- 多流 A 处理 ----

    def _new_b_stream_stats():
        return {
            "started_at": time.monotonic(),
            "c_to_a_bytes": 0,
            "a_to_c_bytes": 0,
            "close_reason": "",
            "exception_type": "",
        }

    def _set_b_stream_close_reason_locked(a_item, sid, reason="", exception_type=""):
        stats = a_item["stream_stats"].get(sid)
        if stats is None:
            return
        if reason and not stats["close_reason"]:
            stats["close_reason"] = reason
        if exception_type and not stats["exception_type"]:
            stats["exception_type"] = exception_type

    def _add_b_stream_bytes(a_item, sid, key, size):
        with a_item["streams_lock"]:
            stats = a_item["stream_stats"].get(sid)
            if stats is not None:
                stats[key] += size

    def _log_b_stream_closed(a_item, sid, stats):
        duration_ms = int((time.monotonic() - stats["started_at"]) * 1000)
        log(
            f"[B] multi_stream_closed a_id={a_item['id']} stream_id={sid} "
            f"close_reason={stats['close_reason'] or 'closed'} "
            f"exception_type={stats['exception_type'] or ''} "
            f"duration_ms={duration_ms} "
            f"c_to_a_bytes={stats['c_to_a_bytes']} "
            f"a_to_c_bytes={stats['a_to_c_bytes']} "
            f"{_stats_locked()}"
        )

    def _close_stream_on_a(a_item, sid, notify_a=True, reason="", exception_type=""):
        with a_item["streams_lock"]:
            framed_c = a_item["streams"].pop(sid, None)
            _set_b_stream_close_reason_locked(
                a_item,
                sid,
                reason=reason,
                exception_type=exception_type,
            )
        if framed_c is not None:
            framed_c.close()
        if notify_a:
            try:
                a_item["framed"].send(FRAME_STREAM_CLOSE, STREAM_ID_STRUCT.pack(sid))
            except Exception as e:
                with a_item["streams_lock"]:
                    _set_b_stream_close_reason_locked(
                        a_item,
                        sid,
                        reason="notify_a_failed",
                        exception_type=type(e).__name__,
                    )

    def _handle_role_a_multi(framed, a_id):
        item = {
            "id": a_id,
            "framed": framed,
            "streams": {},
            "stream_stats": {},
            "streams_lock": threading.Lock(),
            "next_stream_id": count(1),
            "stop": threading.Event(),
        }

        with waiting_cond:
            if len(multi_a) >= WAITING_A_MAX:
                log(f"[!] 多流 A 队列已满，拒绝: a_id={a_id} {_stats_locked()}")
                framed.close()
                return
            multi_a.append(item)
            waiting_cond.notify_all()
            log(f"[+] A 已挂机(多流): a_id={a_id} {_stats_locked()}")

        stop = item["stop"]
        framed.sock.settimeout(RECV_POLL)

        def watchdog():
            while not stop.wait(RECV_POLL):
                if time.time() - framed.last_recv > HEARTBEAT_TIMEOUT:
                    log(f"[B] 多流 A#{a_id} 心跳超时")
                    stop.set()
                    safe_close_sock(framed.sock)
                    return

        if HEARTBEAT_ENABLED:
            threading.Thread(target=_heartbeat_loop, args=(framed, stop), daemon=True).start()
            threading.Thread(target=watchdog, daemon=True).start()

        try:
            while not stop.is_set():
                try:
                    ftype, payload = framed.recv_frame()
                except socket.timeout:
                    continue
                except Exception as e:
                    if not stop.is_set():
                        log(f"[B] 多流 A#{a_id} recv 异常: {e}")
                    break

                if ftype == FRAME_PAIR_ACK:
                    if len(payload) >= STREAM_ID_LEN:
                        sid = STREAM_ID_STRUCT.unpack_from(payload)[0]
                        log(f"[B] 多流 A#{a_id} PAIR_ACK stream_id={sid}")
                elif ftype == FRAME_DATA:
                    if len(payload) < STREAM_ID_LEN:
                        continue
                    sid = STREAM_ID_STRUCT.unpack_from(payload)[0]
                    data = payload[STREAM_ID_LEN:]
                    with item["streams_lock"]:
                        framed_c = item["streams"].get(sid)
                    if framed_c is not None and data:
                        try:
                            framed_c.send(FRAME_DATA, data)
                            _add_b_stream_bytes(item, sid, "a_to_c_bytes", len(data))
                        except Exception as e:
                            _close_stream_on_a(
                                item,
                                sid,
                                notify_a=True,
                                reason="send_to_c_failed",
                                exception_type=type(e).__name__,
                            )
                elif ftype == FRAME_STREAM_CLOSE:
                    if len(payload) >= STREAM_ID_LEN:
                        sid = STREAM_ID_STRUCT.unpack_from(payload)[0]
                        log(f"[B] 多流 A#{a_id} 通知关闭 stream_id={sid}")
                        _close_stream_on_a(
                            item,
                            sid,
                            notify_a=False,
                            reason="a_stream_close",
                        )
                elif ftype == FRAME_PING:
                    try:
                        framed.send(FRAME_PONG)
                    except Exception:
                        break
                elif ftype == FRAME_PONG:
                    pass
                elif ftype == FRAME_CLOSE:
                    log(f"[B] 多流 A#{a_id} 收到 CLOSE")
                    break
                else:
                    log(f"[B] 多流 A#{a_id} 未知帧: {ftype}")
                    break
        finally:
            stop.set()
            with item["streams_lock"]:
                for sid in item["streams"]:
                    _set_b_stream_close_reason_locked(
                        item,
                        sid,
                        reason="a_connection_closed",
                    )
                c_conns = list(item["streams"].values())
                item["streams"].clear()
            for fc in c_conns:
                fc.close()
            framed.close()
            with waiting_cond:
                _remove_multi_a_locked(item, reason="A 连接已断开", close=False)
            log(f"[-] 多流 A#{a_id} 已退出 {_stats_locked()}")

    # ---- C 处理 ----

    def _handle_role_c_single(framed_c):
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

    def _handle_role_c_multi(framed_c):
        started_at = time.monotonic()
        deadline = started_at + C_WAIT_TIMEOUT
        a_item = _claim_multi_a(deadline)
        if a_item is None:
            waited_ms = int((time.monotonic() - started_at) * 1000)
            log(
                f"[!] C 等待多流 A 超时，返回 503: "
                f"c_wait_timeout_ms={waited_ms} {_stats_locked()}"
            )
            _send_no_a_response(framed_c)
            return

        sid = next(a_item["next_stream_id"])
        stats = _new_b_stream_stats()
        with a_item["streams_lock"]:
            a_item["streams"][sid] = framed_c
            a_item["stream_stats"][sid] = stats

        framed_a = a_item["framed"]
        a_id = a_item["id"]

        try:
            framed_a.send(FRAME_PAIR, STREAM_ID_STRUCT.pack(sid))
        except Exception as e:
            log(f"[B] 多流 A#{a_id} 发送 PAIR 失败: {e}")
            with a_item["streams_lock"]:
                a_item["streams"].pop(sid, None)
                stats = a_item["stream_stats"].pop(sid, stats)
                stats["close_reason"] = "send_pair_failed"
                stats["exception_type"] = type(e).__name__
            framed_c.close()
            _log_b_stream_closed(a_item, sid, stats)
            return

        log(f"[B] 多流 A#{a_id} 分配 stream_id={sid} {_stats_locked()}")

        framed_c.sock.settimeout(RECV_POLL)
        prefix = STREAM_ID_STRUCT.pack(sid)
        c_to_a_bytes = 0
        close_reason = "c_loop_exit"
        exception_type = ""
        try:
            while True:
                try:
                    ftype, payload = framed_c.recv_frame()
                except socket.timeout:
                    if time.time() - framed_c.last_recv > HEARTBEAT_TIMEOUT:
                        close_reason = "c_heartbeat_timeout"
                        log(f"[B] C stream_id={sid} 心跳超时")
                        break
                    continue
                except Exception as e:
                    close_reason = "c_recv_error"
                    exception_type = type(e).__name__
                    log(f"[B] C stream_id={sid} recv 异常: {e}")
                    break
                if ftype == FRAME_DATA:
                    try:
                        framed_a.send(FRAME_DATA, prefix + payload)
                        c_to_a_bytes += len(payload)
                        _add_b_stream_bytes(a_item, sid, "c_to_a_bytes", len(payload))
                    except Exception as e:
                        close_reason = "send_to_a_failed"
                        exception_type = type(e).__name__
                        break
                elif ftype == FRAME_PING:
                    try:
                        framed_c.send(FRAME_PONG)
                    except Exception as e:
                        close_reason = "send_pong_failed"
                        exception_type = type(e).__name__
                        break
                elif ftype == FRAME_PONG:
                    pass
                elif ftype == FRAME_CLOSE:
                    close_reason = "c_close"
                    break
                else:
                    close_reason = "unexpected_c_frame"
                    break
        finally:
            try:
                framed_a.send(FRAME_STREAM_CLOSE, STREAM_ID_STRUCT.pack(sid))
            except Exception as e:
                if close_reason == "c_loop_exit":
                    close_reason = "notify_a_failed"
                if not exception_type:
                    exception_type = type(e).__name__
            with a_item["streams_lock"]:
                a_item["streams"].pop(sid, None)
                stats = a_item["stream_stats"].pop(sid, stats)
                if not stats["close_reason"]:
                    stats["close_reason"] = close_reason
                if exception_type and not stats["exception_type"]:
                    stats["exception_type"] = exception_type
            framed_c.close()
            _log_b_stream_closed(a_item, sid, stats)
            log(
                f"[B] 多流 stream_id={sid} 已关闭 c_to_a_bytes={c_to_a_bytes} "
                f"{_stats_locked()}"
            )

    def _handle_role_a(framed):
        a_id = next(next_a_id)
        if A_MULTI_STREAM:
            _handle_role_a_multi(framed, a_id)
        else:
            _handle_role_a_single(framed)

    def _handle_role_c(framed_c):
        if A_MULTI_STREAM:
            _handle_role_c_multi(framed_c)
        else:
            _handle_role_c_single(framed_c)

    def _handle_connection(conn, addr):
        try:
            role, ok, send_cipher, recv_cipher = verify_role_handshake(conn)
            if not ok:
                log(f"[!] 拒绝非法连接: {addr} role={role!r}")
                safe_close_sock(conn)
                return
            log(f"[+] {role} 认证成功: {addr}")
            framed = FramedConn(
                conn, name=f"B<->{role}",
                send_cipher=send_cipher, recv_cipher=recv_cipher,
            )
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
            _release_all_multi_a_locked(reason="服务退出")
        safe_close_sock(server)


if __name__ == "__main__":
    main()
