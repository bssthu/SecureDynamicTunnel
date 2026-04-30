# -*- coding: utf-8 -*-
"""
应用层帧协议 + 心跳/看门狗。

帧格式（大端，无对齐）：
    +--------+----------------+-----------------+
    | 1B 类型 | 4B payload 长度 |  payload 字节   |
    +--------+----------------+-----------------+

类型：
    0x01 DATA   业务字节流分段
    0x02 PING   心跳请求
    0x03 PONG   心跳应答
    0x04 CLOSE  优雅关闭通知（payload 通常为空）
"""

import socket
import struct
import threading
import time

FRAME_DATA = 0x01
FRAME_PING = 0x02
FRAME_PONG = 0x03
FRAME_CLOSE = 0x04

_HDR = struct.Struct("!BI")
HEADER_LEN = _HDR.size
MAX_PAYLOAD = 1 << 20  # 1 MiB，防止异常长度撑爆内存

# 心跳参数（每条链路独立维护）
HEARTBEAT_INTERVAL = 15   # 秒：每隔多久发一次 PING
HEARTBEAT_TIMEOUT = 45    # 秒：多久没收到任何帧就视为对端死亡
RECV_POLL = 1.0           # 秒：recv 超时粒度，让看门狗可以周期检查


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
    """对一个已建立的 TCP socket 做帧化封装。线程安全的发送 + 最近收包时间戳。"""

    def __init__(self, sock, name=""):
        self.sock = sock
        self.name = name
        self._send_lock = threading.Lock()
        self._closed = False
        self.last_recv = time.time()

    @property
    def closed(self):
        return self._closed

    def send(self, ftype, payload=b""):
        if self._closed:
            raise FrameError(f"{self.name} 已关闭")
        if len(payload) > MAX_PAYLOAD:
            raise FrameError("payload 超过最大长度")
        header = _HDR.pack(ftype, len(payload))
        with self._send_lock:
            self.sock.sendall(header + payload)

    def _recv_exact(self, n):
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise FrameError(f"{self.name} 对端关闭")
            buf.extend(chunk)
        return bytes(buf)

    def recv_frame(self):
        """读取一帧；socket.timeout 会原样抛出供上层做看门狗检查。"""
        header = self._recv_exact(HEADER_LEN)
        ftype, length = _HDR.unpack(header)
        if length > MAX_PAYLOAD:
            raise FrameError(f"非法 payload 长度: {length}")
        payload = self._recv_exact(length) if length else b""
        self.last_recv = time.time()
        return ftype, payload

    def close(self):
        if self._closed:
            return
        self._closed = True
        # 尽力发一个 CLOSE 帧，让对端能立即感知
        try:
            header = _HDR.pack(FRAME_CLOSE, 0)
            with self._send_lock:
                self.sock.sendall(header)
        except Exception:
            pass
        safe_close_sock(self.sock)


def _heartbeat_loop(conn, stop_event):
    """周期性向对端发送 PING；conn 关闭或被通知停止时退出。"""
    while not stop_event.wait(HEARTBEAT_INTERVAL):
        if conn.closed:
            return
        try:
            conn.send(FRAME_PING)
        except Exception:
            return


def run_endpoint(framed, raw_sock, role_label=""):
    """
    A / C 端的双向转发循环：
        framed (帧侧，对 B) <-> raw_sock (本地裸字节侧)

    自带：发送 PING 心跳、读 PONG/PING 处理、看门狗。
    阻塞直到任一侧关闭或心跳超时。返回时两侧 socket 均已关闭。
    """
    stop = threading.Event()

    def raw_to_frame():
        try:
            while not stop.is_set():
                data = raw_sock.recv(8192)
                if not data:
                    break
                framed.send(FRAME_DATA, data)
        except Exception:
            pass
        finally:
            stop.set()

    def watchdog():
        while not stop.wait(RECV_POLL):
            if time.time() - framed.last_recv > HEARTBEAT_TIMEOUT:
                print(f"[{role_label}] 心跳超时，断开链路")
                stop.set()
                # 关掉 socket 让阻塞中的 recv 立即返回
                safe_close_sock(framed.sock)
                return

    framed.sock.settimeout(RECV_POLL)

    threading.Thread(target=raw_to_frame, daemon=True).start()
    threading.Thread(target=_heartbeat_loop, args=(framed, stop), daemon=True).start()
    threading.Thread(target=watchdog, daemon=True).start()

    try:
        while not stop.is_set():
            try:
                ftype, payload = framed.recv_frame()
            except socket.timeout:
                continue
            except FrameError as e:
                print(f"[{role_label}] 帧错误: {e}")
                break
            except Exception as e:
                print(f"[{role_label}] recv 异常: {e}")
                break

            if ftype == FRAME_DATA:
                try:
                    raw_sock.sendall(payload)
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
                print(f"[{role_label}] 收到对端 CLOSE")
                break
            else:
                print(f"[{role_label}] 未知帧类型: {ftype}")
                break
    finally:
        stop.set()
        framed.close()
        safe_close_sock(raw_sock)


def run_bridge(framed_a, framed_c):
    """
    B 端的双向桥接：framed_a <-> framed_c。
    PING/PONG 在 B 上各自就地应答；DATA 帧透传；任一侧 CLOSE/超时则两侧一起关闭。
    """
    stop = threading.Event()
    framed_a.sock.settimeout(RECV_POLL)
    framed_c.sock.settimeout(RECV_POLL)

    def watchdog():
        while not stop.wait(RECV_POLL):
            now = time.time()
            if now - framed_a.last_recv > HEARTBEAT_TIMEOUT:
                print("[B] A 侧心跳超时")
                stop.set()
                safe_close_sock(framed_a.sock)
                safe_close_sock(framed_c.sock)
                return
            if now - framed_c.last_recv > HEARTBEAT_TIMEOUT:
                print("[B] C 侧心跳超时")
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
                    print(f"[B] {label} 帧错误: {e}")
                    break
                except Exception as e:
                    print(f"[B] {label} 读取异常: {e}")
                    break

                if ftype == FRAME_DATA:
                    try:
                        dst.send(FRAME_DATA, payload)
                    except Exception as e:
                        print(f"[B] {label} 转发失败: {e}")
                        break
                elif ftype == FRAME_PING:
                    try:
                        src.send(FRAME_PONG)
                    except Exception:
                        break
                elif ftype == FRAME_PONG:
                    pass
                elif ftype == FRAME_CLOSE:
                    print(f"[B] {label} 收到 CLOSE")
                    break
                else:
                    print(f"[B] {label} 未知帧: {ftype}")
                    break
        finally:
            stop.set()

    threads = [
        threading.Thread(target=pump, args=(framed_a, framed_c, "A->C"), daemon=True),
        threading.Thread(target=pump, args=(framed_c, framed_a, "C->A"), daemon=True),
        threading.Thread(target=_heartbeat_loop, args=(framed_a, stop), daemon=True),
        threading.Thread(target=_heartbeat_loop, args=(framed_c, stop), daemon=True),
        threading.Thread(target=watchdog, daemon=True),
    ]
    for t in threads:
        t.start()

    stop.wait()
    framed_a.close()
    framed_c.close()
