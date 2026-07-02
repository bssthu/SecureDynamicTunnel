# -*- coding: utf-8 -*-
"""
应用层帧协议 + 心跳/看门狗。

帧格式（大端，无对齐）：
    +--------+----------------+-----------------+
    | 1B 类型 | 4B payload 长度 |  payload 字节   |
    +--------+----------------+-----------------+

类型：
    0x01 DATA         业务字节流分段（多流模式下 payload 前 2B 为 stream_id）
    0x02 PING         心跳请求
    0x03 PONG         心跳应答
    0x04 CLOSE        优雅关闭通知（payload 通常为空）
    0x05 PAIR         B→A 通知有新 C 接入（payload: 2B stream_id）
    0x06 PAIR_ACK     A→B 确认已建立本地连接（payload: 2B stream_id）
    0x07 STREAM_CLOSE 通知对端关闭某个 stream（payload: 2B stream_id）
"""

import socket
import struct
import threading
import time

from config import (
    ALLOW_RAW_C_COMPAT,
    FRAME_MAX_PAYLOAD,
    HEARTBEAT_ENABLED,
    HEARTBEAT_INTERVAL,
    HEARTBEAT_TIMEOUT,
    MULTI_STREAM_PENDING_LIMIT,
    RECV_CHUNK_SIZE,
    RECV_POLL,
)
from crypto import TAG_LEN
from log_utils import log

FRAME_DATA = 0x01
FRAME_PING = 0x02
FRAME_PONG = 0x03
FRAME_CLOSE = 0x04
FRAME_PAIR = 0x05
FRAME_PAIR_ACK = 0x06
FRAME_STREAM_CLOSE = 0x07
_VALID_FRAME_TYPES = {FRAME_DATA, FRAME_PING, FRAME_PONG, FRAME_CLOSE,
                      FRAME_PAIR, FRAME_PAIR_ACK, FRAME_STREAM_CLOSE}

STREAM_ID_STRUCT = struct.Struct("!H")
STREAM_ID_LEN = STREAM_ID_STRUCT.size

_HDR = struct.Struct("!BI")
HEADER_LEN = _HDR.size
MAX_PAYLOAD = FRAME_MAX_PAYLOAD


class FrameError(Exception):
    pass


def safe_close_sock(sock):
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    try:
        sock.close()
    except Exception:
        pass


class FramedConn:
    """对一个已建立的 TCP socket 做帧化封装。线程安全的发送 + 最近收包时间戳。

    若提供 send_cipher / recv_cipher（来自 crypto.FrameCipher），则每帧 payload
    会被 ChaCha20-Poly1305 AEAD 加密：
        wire  = type(1) || ciphertext_len(4) || ciphertext
        AAD   = type(1) || ciphertext_len(4)
        nonce = 由 cipher 内部 seq 单调派生（双方同步前进）
    任何篡改 / 重放 / 乱序都会让 tag 校验失败并触发 FrameError。
    cipher 为 None 时退化为原始明文帧（仅供测试 / 兼容旧路径）。
    """

    def __init__(self, sock, name="", send_cipher=None, recv_cipher=None):
        self.sock = sock
        self.name = name
        self._send_lock = threading.Lock()
        self._closed = False
        self.last_recv = time.time()
        self._rx_buf = bytearray()
        self._send_cipher = send_cipher
        self._recv_cipher = recv_cipher
        self._encrypted = send_cipher is not None and recv_cipher is not None

    @property
    def closed(self):
        return self._closed

    @property
    def encrypted(self):
        return self._encrypted

    def send(self, ftype, payload=b""):
        if self._closed:
            raise FrameError(f"{self.name} 已关闭")
        if len(payload) > MAX_PAYLOAD:
            raise FrameError("payload 超过最大长度")
        with self._send_lock:
            if self._encrypted:
                # The AEAD sequence advances during encrypt(), so encryption and
                # socket write must be serialized together.
                wire_len = len(payload) + TAG_LEN
                header = _HDR.pack(ftype, wire_len)
                body = self._send_cipher.encrypt(header, payload)
            else:
                header = _HDR.pack(ftype, len(payload))
                body = payload
            self.sock.sendall(header + body)

    def _fill_until(self, target_len):
        """读取直到 _rx_buf 至少有 target_len 字节。
        socket.timeout 时保留已读字节并向上抛，下次可继续。"""
        while len(self._rx_buf) < target_len:
            chunk = self.sock.recv(target_len - len(self._rx_buf))
            if not chunk:
                raise FrameError(f"{self.name} 对端关闭")
            self._rx_buf.extend(chunk)
            self.last_recv = time.time()  # 收到任何字节都算活动

    def recv_frame(self):
        """读取一帧；socket.timeout 会原样抛出供上层做看门狗检查。所有已读字节会被保留。"""
        self._fill_until(HEADER_LEN)
        ftype, length = _HDR.unpack_from(self._rx_buf, 0)
        if ftype not in _VALID_FRAME_TYPES:
            raise FrameError(f"非法帧类型: {ftype}")
        # 加密模式下 length 表示密文长度（明文 + TAG）
        max_wire = MAX_PAYLOAD + (TAG_LEN if self._encrypted else 0)
        if length > max_wire:
            raise FrameError(f"非法 payload 长度: {length}")
        total = HEADER_LEN + length
        if length:
            self._fill_until(total)
        body = bytes(self._rx_buf[HEADER_LEN:total])
        del self._rx_buf[:total]
        if self._encrypted:
            if length < TAG_LEN:
                raise FrameError("密文长度不足")
            aad = _HDR.pack(ftype, length)
            try:
                payload = self._recv_cipher.decrypt(aad, body)
            except Exception as e:  # InvalidTag 等
                raise FrameError(f"帧解密失败: {e}")
        else:
            payload = body
        return ftype, payload

    def take_buffered(self):
        data = bytes(self._rx_buf)
        self._rx_buf.clear()
        return data

    def close(self):
        if self._closed:
            return
        # 尽力发一个 CLOSE 帧（加密模式下会自动走 AEAD），让对端能立即感知。
        # 注意先发再设 closed，避免 send() 检测到关闭状态而拒发。
        try:
            with self._send_lock:
                if self._encrypted:
                    header = _HDR.pack(FRAME_CLOSE, TAG_LEN)
                    body = self._send_cipher.encrypt(header, b"")
                    self.sock.sendall(header + body)
                else:
                    header = _HDR.pack(FRAME_CLOSE, 0)
                    self.sock.sendall(header)
        except Exception:
            pass
        self._closed = True
        safe_close_sock(self.sock)


def _heartbeat_loop(conn, stop_event):
    """周期性向对端发送 PING；conn 关闭或被通知停止时退出。"""
    if not HEARTBEAT_ENABLED:
        return
    while not stop_event.wait(HEARTBEAT_INTERVAL):
        if conn.closed:
            return
        try:
            conn.send(FRAME_PING)
        except Exception:
            return


def waiting_keepalive(framed, promote_event, label=""):
    """
    在"已认证但尚未配对"阶段维持一条链路：
        - 周期发送 PING
        - 读取并处理 PING/PONG/CLOSE，更新 last_recv
        - HEARTBEAT_TIMEOUT 内未收到任何帧 → 判死
        - 收到 DATA 帧视为协议违例（等待期不应有业务数据）

    返回值：
        True  - 被 promote_event 通知接管（配对成功）
        False - 链路已死（已被本函数关闭）
    """
    framed.sock.settimeout(RECV_POLL)
    last_ping = time.time()
    while not promote_event.is_set():
        try:
            ftype, _ = framed.recv_frame()
            if ftype == FRAME_PING:
                try:
                    framed.send(FRAME_PONG)
                except Exception:
                    framed.close()
                    return False
            elif ftype == FRAME_PONG:
                pass
            elif ftype == FRAME_CLOSE:
                log(f"[{label}] 等待期收到 CLOSE")
                framed.close()
                return False
            else:
                log(f"[{label}] 等待期收到非法帧类型: {ftype}")
                framed.close()
                return False
        except socket.timeout:
            pass
        except FrameError as e:
            log(f"[{label}] 等待期帧错误: {e}")
            framed.close()
            return False
        except Exception as e:
            log(f"[{label}] 等待期 recv 异常: {e}")
            framed.close()
            return False

        if HEARTBEAT_ENABLED:
            now = time.time()
            if now - last_ping >= HEARTBEAT_INTERVAL:
                try:
                    framed.send(FRAME_PING)
                    last_ping = now
                except Exception:
                    framed.close()
                    return False
            if now - framed.last_recv > HEARTBEAT_TIMEOUT:
                log(f"[{label}] 等待期心跳超时")
                framed.close()
                return False

    # 被提升为正式配对：清掉 timeout，让上层重新设置
    try:
        framed.sock.settimeout(None)
    except Exception:
        pass
    return True


def run_endpoint(framed, raw_sock, role_label=""):
    """
    A / C 端的双向转发循环：
        framed (帧侧，对 B) <-> raw_sock (本地裸字节侧)

    自带：发送 PING 心跳、读 PONG/PING 处理、看门狗。
    阻塞直到任一侧关闭或心跳超时。返回时两侧 socket 均已关闭。
    """
    stop = threading.Event()
    counters = {"raw_to_frame": 0, "frame_to_raw": 0}

    def raw_to_frame():
        try:
            while not stop.is_set():
                data = raw_sock.recv(RECV_CHUNK_SIZE)
                if not data:
                    break
                framed.send(FRAME_DATA, data)
                counters["raw_to_frame"] += len(data)
        except Exception:
            pass
        finally:
            stop.set()

    def watchdog():
        while not stop.wait(RECV_POLL):
            if time.time() - framed.last_recv > HEARTBEAT_TIMEOUT:
                log(f"[{role_label}] 心跳超时，断开链路")
                stop.set()
                # 关掉 socket 让阻塞中的 recv 立即返回
                safe_close_sock(framed.sock)
                return

    framed.sock.settimeout(RECV_POLL)

    threading.Thread(target=raw_to_frame, daemon=True).start()
    if HEARTBEAT_ENABLED:
        threading.Thread(target=_heartbeat_loop, args=(framed, stop), daemon=True).start()
        threading.Thread(target=watchdog, daemon=True).start()

    try:
        while not stop.is_set():
            try:
                ftype, payload = framed.recv_frame()
            except socket.timeout:
                continue
            except FrameError as e:
                log(f"[{role_label}] 帧错误: {e}")
                break
            except Exception as e:
                if not stop.is_set():
                    log(f"[{role_label}] recv 异常: {e}")
                break

            if ftype == FRAME_DATA:
                try:
                    raw_sock.sendall(payload)
                    counters["frame_to_raw"] += len(payload)
                except Exception:
                    break
            elif ftype == FRAME_PING:
                try:
                    framed.send(FRAME_PONG)
                except Exception:
                    break
            elif ftype == FRAME_PONG:
                pass  # last_recv 已更新
            elif ftype == FRAME_CLOSE:
                log(f"[{role_label}] 收到对端 CLOSE")
                break
            else:
                log(f"[{role_label}] 未知帧类型: {ftype}")
                break
    finally:
        stop.set()
        log(
            f"[{role_label}] endpoint_closed "
            f"raw_to_frame_bytes={counters['raw_to_frame']} "
            f"frame_to_raw_bytes={counters['frame_to_raw']}"
        )
        framed.close()
        safe_close_sock(raw_sock)


def _recv_first_c_item(framed_c):
    """读取 C 的首个业务单元；默认拒绝握手后的裸字节流。"""
    while True:
        try:
            ftype, payload = framed_c.recv_frame()
        except socket.timeout:
            if HEARTBEAT_ENABLED and time.time() - framed_c.last_recv > HEARTBEAT_TIMEOUT:
                raise FrameError("C 侧首包等待超时")
            continue
        except FrameError as e:
            raw = framed_c.take_buffered()
            if raw and raw[0] not in _VALID_FRAME_TYPES:
                preview = raw[:16]
                if ALLOW_RAW_C_COMPAT:
                    log(f"[B] C 侧首包不是帧协议，切换为裸流兼容模式: {e}; 预览={preview!r}")
                    return "raw", raw
                raise FrameError(f"C 侧首包不是帧协议，已拒绝裸流: {e}; 预览={preview!r}")
            raise

        if ftype == FRAME_DATA:
            return "framed", payload
        if ftype == FRAME_PING:
            framed_c.send(FRAME_PONG)
            continue
        if ftype == FRAME_PONG:
            continue
        if ftype == FRAME_CLOSE:
            return "close", b""
        raise FrameError(f"C 侧首包未知帧: {ftype}")


def _run_raw_c_bridge(framed_a, framed_c, first_payload):
    """
    兼容旧版 C：C<->B 是裸字节流，A<->B 仍是帧协议。
    只对 A 侧做应用层心跳；对 C 侧依赖 TCP 关闭/异常。
    """
    stop = threading.Event()
    c_sock = framed_c.sock
    framed_a.sock.settimeout(RECV_POLL)
    c_sock.settimeout(RECV_POLL)

    def watchdog_a():
        while not stop.wait(RECV_POLL):
            if time.time() - framed_a.last_recv > HEARTBEAT_TIMEOUT:
                log("[B] A 侧心跳超时")
                stop.set()
                safe_close_sock(framed_a.sock)
                safe_close_sock(c_sock)
                return

    def a_to_c():
        try:
            while not stop.is_set():
                try:
                    ftype, payload = framed_a.recv_frame()
                except socket.timeout:
                    continue
                except FrameError as e:
                    if not stop.is_set():
                        log(f"[B] A->C 帧错误: {e}")
                    break
                except Exception as e:
                    if not stop.is_set():
                        log(f"[B] A->C 读取异常: {e}")
                    break

                if ftype == FRAME_DATA:
                    try:
                        c_sock.sendall(payload)
                    except Exception as e:
                        if not stop.is_set():
                            log(f"[B] A->C 转发失败: {e}")
                        break
                elif ftype == FRAME_PING:
                    try:
                        framed_a.send(FRAME_PONG)
                    except Exception:
                        break
                elif ftype == FRAME_PONG:
                    pass
                elif ftype == FRAME_CLOSE:
                    log("[B] A->C 收到 CLOSE")
                    break
        finally:
            stop.set()

    def c_to_a():
        pending = first_payload
        try:
            while not stop.is_set():
                if pending:
                    data = pending
                    pending = b""
                else:
                    try:
                        data = c_sock.recv(RECV_CHUNK_SIZE)
                    except socket.timeout:
                        continue
                    if not data:
                        break
                try:
                    framed_a.send(FRAME_DATA, data)
                except Exception as e:
                    if not stop.is_set():
                        log(f"[B] C->A 转发失败: {e}")
                    break
        except Exception as e:
            if not stop.is_set():
                log(f"[B] C->A 裸流读取异常: {e}")
        finally:
            stop.set()

    threads = [
        threading.Thread(target=a_to_c, daemon=True),
        threading.Thread(target=c_to_a, daemon=True),
    ]
    if HEARTBEAT_ENABLED:
        threads.append(threading.Thread(target=_heartbeat_loop, args=(framed_a, stop), daemon=True))
        threads.append(threading.Thread(target=watchdog_a, daemon=True))
    for t in threads:
        t.start()

    stop.wait()
    framed_a.close()
    safe_close_sock(c_sock)
    framed_c._closed = True


def run_bridge(framed_a, framed_c):
    """
    B 端的双向桥接：framed_a <-> framed_c。
    PING/PONG 在 B 上各自就地应答；DATA 帧透传；任一侧 CLOSE/超时则两侧一起关闭。
    默认拒绝握手后的裸流；ALLOW_RAW_C_COMPAT=True 时才兼容旧版 C 裸流。
    """
    stop = threading.Event()
    framed_a.sock.settimeout(RECV_POLL)
    framed_c.sock.settimeout(RECV_POLL)

    try:
        c_mode, first_payload = _recv_first_c_item(framed_c)
    except Exception as e:
        log(f"[B] C 侧首包读取失败: {e}")
        framed_a.close()
        framed_c.close()
        return

    if c_mode == "close":
        log("[B] C->A 收到 CLOSE")
        framed_a.close()
        framed_c.close()
        return

    if c_mode == "raw":
        _run_raw_c_bridge(framed_a, framed_c, first_payload)
        return

    try:
        framed_a.send(FRAME_DATA, first_payload)
    except Exception as e:
        log(f"[B] C->A 首包转发失败: {e}")
        framed_a.close()
        framed_c.close()
        return

    def watchdog():
        while not stop.wait(RECV_POLL):
            now = time.time()
            if now - framed_a.last_recv > HEARTBEAT_TIMEOUT:
                log("[B] A 侧心跳超时")
                stop.set()
                safe_close_sock(framed_a.sock)
                safe_close_sock(framed_c.sock)
                return
            if now - framed_c.last_recv > HEARTBEAT_TIMEOUT:
                log("[B] C 侧心跳超时")
                stop.set()
                safe_close_sock(framed_a.sock)
                safe_close_sock(framed_c.sock)
                return

    def pump(src, dst, label):
        try:
            while not stop.is_set():
                try:
                    ftype, payload = src.recv_frame()
                except socket.timeout:
                    continue
                except FrameError as e:
                    if not stop.is_set():
                        log(f"[B] {label} 帧错误: {e}")
                    break
                except Exception as e:
                    if not stop.is_set():
                        log(f"[B] {label} 读取异常: {e}")
                    break

                if ftype == FRAME_DATA:
                    try:
                        dst.send(FRAME_DATA, payload)
                    except Exception as e:
                        if not stop.is_set():
                            log(f"[B] {label} 转发失败: {e}")
                        break
                elif ftype == FRAME_PING:
                    try:
                        src.send(FRAME_PONG)
                    except Exception:
                        break
                elif ftype == FRAME_PONG:
                    pass
                elif ftype == FRAME_CLOSE:
                    log(f"[B] {label} 收到 CLOSE")
                    break
        finally:
            stop.set()

    threads = [
        threading.Thread(target=pump, args=(framed_a, framed_c, "A->C"), daemon=True),
        threading.Thread(target=pump, args=(framed_c, framed_a, "C->A"), daemon=True),
    ]
    if HEARTBEAT_ENABLED:
        threads.append(threading.Thread(target=_heartbeat_loop, args=(framed_a, stop), daemon=True))
        threads.append(threading.Thread(target=_heartbeat_loop, args=(framed_c, stop), daemon=True))
        threads.append(threading.Thread(target=watchdog, daemon=True))
    for t in threads:
        t.start()

    stop.wait()
    framed_a.close()
    framed_c.close()


# ---------------------------------------------------------------------------
# 多流（Multi-Stream）模式：一个 A 连接同时服务多个 C
# ---------------------------------------------------------------------------

def run_multi_stream_a_endpoint(framed, local_service_addr, connect_timeout, role_label="A"):
    """A-side multi-stream endpoint with bounded pending buffers and stream stats."""
    stop = threading.Event()
    streams = {}
    streams_lock = threading.Lock()
    endpoint_state = {"close_reason": "endpoint_stopped", "exception_type": ""}

    framed.sock.settimeout(RECV_POLL)

    def _new_stream_entry():
        return {
            "sock": None,
            "pending": [],
            "pending_bytes": 0,
            "closed": False,
            "started_at": time.monotonic(),
            "c_to_a_bytes": 0,
            "a_to_local_bytes": 0,
            "local_to_a_bytes": 0,
            "close_reason": "",
            "exception_type": "",
            "lock": threading.Lock(),
        }

    def _add_bytes(entry, key, size):
        with entry["lock"]:
            entry[key] += size

    def _mark_closed(entry, reason="", exception_type=""):
        with entry["lock"]:
            entry["closed"] = True
            if reason and not entry["close_reason"]:
                entry["close_reason"] = reason
            if exception_type and not entry["exception_type"]:
                entry["exception_type"] = exception_type
            return entry["sock"]

    def _log_stream_closed(sid, entry):
        with entry["lock"]:
            duration_ms = int((time.monotonic() - entry["started_at"]) * 1000)
            close_reason = entry["close_reason"] or "closed"
            exception_type = entry["exception_type"] or ""
            c_to_a_bytes = entry["c_to_a_bytes"]
            a_to_local_bytes = entry["a_to_local_bytes"]
            local_to_a_bytes = entry["local_to_a_bytes"]
            pending_bytes = entry["pending_bytes"]
        log(
            f"[{role_label}] stream_closed stream_id={sid} "
            f"close_reason={close_reason} exception_type={exception_type} "
            f"duration_ms={duration_ms} c_to_a_bytes={c_to_a_bytes} "
            f"a_to_local_bytes={a_to_local_bytes} "
            f"local_to_a_bytes={local_to_a_bytes} "
            f"pending_bytes={pending_bytes} "
            f"pending_limit_bytes={MULTI_STREAM_PENDING_LIMIT}"
        )

    def _close_stream(sid, reason="", exception_type="", notify_b=False):
        with streams_lock:
            entry = streams.pop(sid, None)
            if entry is None:
                return
            sock = _mark_closed(entry, reason=reason, exception_type=exception_type)
        if notify_b:
            try:
                framed.send(FRAME_STREAM_CLOSE, STREAM_ID_STRUCT.pack(sid))
            except Exception as e:
                with entry["lock"]:
                    if not entry["exception_type"]:
                        entry["exception_type"] = type(e).__name__
                    if not entry["close_reason"]:
                        entry["close_reason"] = "notify_b_failed"
        if sock is not None:
            safe_close_sock(sock)
        _log_stream_closed(sid, entry)

    def _close_all_streams(reason, exception_type=""):
        with streams_lock:
            items = list(streams.items())
            streams.clear()
            socks = [
                _mark_closed(entry, reason=reason, exception_type=exception_type)
                for _, entry in items
            ]
        for sock in socks:
            if sock is not None:
                safe_close_sock(sock)
        for sid, entry in items:
            _log_stream_closed(sid, entry)

    def _local_to_framed(sid, entry, local_sock):
        prefix = STREAM_ID_STRUCT.pack(sid)
        close_reason = "local_eof"
        exception_type = ""
        try:
            while not stop.is_set():
                try:
                    data = local_sock.recv(RECV_CHUNK_SIZE)
                except Exception as e:
                    close_reason = "local_recv_error"
                    exception_type = type(e).__name__
                    break
                if not data:
                    close_reason = "local_eof"
                    break
                try:
                    framed.send(FRAME_DATA, prefix + data)
                    _add_bytes(entry, "local_to_a_bytes", len(data))
                except Exception as e:
                    close_reason = "send_to_b_failed"
                    exception_type = type(e).__name__
                    break
        finally:
            if stop.is_set() and close_reason == "local_eof":
                close_reason = endpoint_state["close_reason"]
                exception_type = endpoint_state["exception_type"]
            _close_stream(
                sid,
                reason=close_reason,
                exception_type=exception_type,
                notify_b=True,
            )

    def _start_stream(sid, entry):
        local_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        local_sock.settimeout(connect_timeout)
        try:
            local_sock.connect(local_service_addr)
        except Exception as e:
            log(f"[{role_label}] stream {sid} local_connect_failed: {e}")
            safe_close_sock(local_sock)
            _close_stream(
                sid,
                reason="local_connect_failed",
                exception_type=type(e).__name__,
                notify_b=True,
            )
            return
        local_sock.settimeout(None)

        with streams_lock:
            active = streams.get(sid) is entry
            if active:
                with entry["lock"]:
                    buffered = entry["pending"]
                    entry["pending"] = []
                    entry["pending_bytes"] = 0
                    entry["sock"] = local_sock
            else:
                buffered = None
        if not active:
            safe_close_sock(local_sock)
            return

        try:
            for chunk in buffered:
                local_sock.sendall(chunk)
                _add_bytes(entry, "a_to_local_bytes", len(chunk))
        except Exception as e:
            log(f"[{role_label}] stream {sid} pending_replay_failed: {e}")
            _close_stream(
                sid,
                reason="pending_replay_failed",
                exception_type=type(e).__name__,
                notify_b=True,
            )
            return

        try:
            framed.send(FRAME_PAIR_ACK, STREAM_ID_STRUCT.pack(sid))
        except Exception as e:
            log(f"[{role_label}] stream {sid} pair_ack_failed: {e}")
            _close_stream(
                sid,
                reason="pair_ack_failed",
                exception_type=type(e).__name__,
                notify_b=False,
            )
            return
        log(f"[{role_label}] stream {sid} local_connected {local_service_addr}")
        threading.Thread(
            target=_local_to_framed,
            args=(sid, entry, local_sock),
            daemon=True,
        ).start()

    def watchdog():
        while not stop.wait(RECV_POLL):
            if time.time() - framed.last_recv > HEARTBEAT_TIMEOUT:
                endpoint_state["close_reason"] = "heartbeat_timeout"
                log(f"[{role_label}] heartbeat_timeout")
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
            except FrameError as e:
                endpoint_state["close_reason"] = "frame_error"
                endpoint_state["exception_type"] = type(e).__name__
                log(f"[{role_label}] frame_error {e}")
                break
            except Exception as e:
                if not stop.is_set():
                    endpoint_state["close_reason"] = "recv_error"
                    endpoint_state["exception_type"] = type(e).__name__
                    log(f"[{role_label}] recv_error {e}")
                break

            if ftype == FRAME_PAIR:
                if len(payload) < STREAM_ID_LEN:
                    endpoint_state["close_reason"] = "invalid_pair"
                    log(f"[{role_label}] invalid_pair")
                    break
                sid = STREAM_ID_STRUCT.unpack_from(payload)[0]
                log(f"[{role_label}] pair_received stream_id={sid}")
                with streams_lock:
                    entry = _new_stream_entry()
                    streams[sid] = entry
                threading.Thread(target=_start_stream, args=(sid, entry), daemon=True).start()

            elif ftype == FRAME_DATA:
                if len(payload) < STREAM_ID_LEN:
                    continue
                sid = STREAM_ID_STRUCT.unpack_from(payload)[0]
                data = payload[STREAM_ID_LEN:]
                if not data:
                    continue
                entry = None
                local_sock = None
                overflow = False
                pending_bytes = 0
                with streams_lock:
                    entry = streams.get(sid)
                    if entry is not None:
                        with entry["lock"]:
                            if not entry["closed"]:
                                entry["c_to_a_bytes"] += len(data)
                                local_sock = entry["sock"]
                                if local_sock is None:
                                    pending_bytes = entry["pending_bytes"] + len(data)
                                    if pending_bytes > MULTI_STREAM_PENDING_LIMIT:
                                        overflow = True
                                    else:
                                        entry["pending"].append(data)
                                        entry["pending_bytes"] = pending_bytes
                if entry is None:
                    continue
                if overflow:
                    log(
                        f"[{role_label}] pending_limit_exceeded stream_id={sid} "
                        f"pending_bytes={pending_bytes} "
                        f"pending_limit_bytes={MULTI_STREAM_PENDING_LIMIT}"
                    )
                    _close_stream(sid, reason="pending_limit_exceeded", notify_b=True)
                    continue
                if local_sock is not None:
                    try:
                        local_sock.sendall(data)
                        _add_bytes(entry, "a_to_local_bytes", len(data))
                    except Exception as e:
                        _close_stream(
                            sid,
                            reason="local_write_failed",
                            exception_type=type(e).__name__,
                            notify_b=True,
                        )

            elif ftype == FRAME_STREAM_CLOSE:
                if len(payload) < STREAM_ID_LEN:
                    continue
                sid = STREAM_ID_STRUCT.unpack_from(payload)[0]
                _close_stream(sid, reason="b_stream_close", notify_b=False)

            elif ftype == FRAME_PING:
                try:
                    framed.send(FRAME_PONG)
                except Exception:
                    endpoint_state["close_reason"] = "send_pong_failed"
                    break
            elif ftype == FRAME_PONG:
                pass
            elif ftype == FRAME_CLOSE:
                endpoint_state["close_reason"] = "b_close"
                log(f"[{role_label}] b_close")
                break
            else:
                endpoint_state["close_reason"] = "unknown_frame"
                log(f"[{role_label}] unknown_frame ftype={ftype}")
                break
    finally:
        stop.set()
        _close_all_streams(
            endpoint_state["close_reason"],
            endpoint_state["exception_type"],
        )
        framed.close()
