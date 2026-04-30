# -*- coding: utf-8 -*-

import socket
import threading
from secret_tool import verify_token
from framing import (
    FramedConn, run_bridge, safe_close_sock, waiting_keepalive,
    FRAME_CLOSE,
)

LISTEN_PORT = 9001


def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("对端在握手阶段关闭")
        buf.extend(chunk)
    return bytes(buf)


def _start_bridge(framed_a, framed_c):
    """在独立线程中跑 run_bridge，避免阻塞主 accept 循环。"""
    def _run():
        try:
            run_bridge(framed_a, framed_c)
        finally:
            print("[***] A-C 隧道已关闭")
    threading.Thread(target=_run, daemon=True).start()
    print("[***] A-C 隧道建立成功！")


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', LISTEN_PORT))
    server.listen(20)
    print(f"[*] 中转机器 B 已启动，监听端口 {LISTEN_PORT}...")

    # 仅 A 会进入挂机等待状态：(framed, promote_event, keeper_thread)
    waiting_a = {"framed": None, "event": None, "thread": None}
    waiting_lock = threading.Lock()

    def _release_waiting_a_locked(reason=""):
        """调用方必须持有 waiting_lock。仅清空记录、关闭旧链路；不 join。"""
        old = waiting_a["framed"]
        ev = waiting_a["event"]
        if old is not None:
            if reason:
                print(f"[!] 释放等待中的 A: {reason}")
            try:
                old.close()
            except Exception:
                pass
        if ev is not None:
            ev.set()
        waiting_a["framed"] = None
        waiting_a["event"] = None
        waiting_a["thread"] = None

    def _handle_role_a(framed):
        """ROLE_A 上线：替换旧的等待者，启动等待守护线程。"""
        promote_event = threading.Event()

        def _keeper():
            alive = waiting_keepalive(framed, promote_event, label="B<->A")
            if not alive:
                # 自然死亡：从 waiting 中清除（如果还指向自己）
                with waiting_lock:
                    if waiting_a["framed"] is framed:
                        waiting_a["framed"] = None
                        waiting_a["event"] = None
                        waiting_a["thread"] = None

        with waiting_lock:
            _release_waiting_a_locked(reason="A 重连，关闭旧挂机连接")
            waiting_a["framed"] = framed
            waiting_a["event"] = promote_event
            t = threading.Thread(target=_keeper, daemon=True)
            waiting_a["thread"] = t
        t.start()
        print("[+] A 已挂机，等待 C 接入")

    def _handle_role_c(framed_c):
        """ROLE_C 上线：若 A 不在则立即拒绝；否则提升 A 并桥接。"""
        with waiting_lock:
            framed_a = waiting_a["framed"]
            event_a = waiting_a["event"]
            thread_a = waiting_a["thread"]
            # 抢占 A，避免被并发的另一个 C 抢走
            if framed_a is not None:
                waiting_a["framed"] = None
                waiting_a["event"] = None
                waiting_a["thread"] = None

        if framed_a is None:
            print("[!] C 接入但 A 未挂机，拒绝")
            try:
                framed_c.send(FRAME_CLOSE)
            except Exception:
                pass
            framed_c.close()
            return

        # 通知 A 的 keeper 退出（让出 socket 控制权），并等其结束
        event_a.set()
        if thread_a is not None:
            thread_a.join(timeout=5)

        if framed_a.closed:
            # 在我们抢占后、让出之前 A 恰好死了
            print("[!] A 在配对瞬间已断开，拒绝 C")
            try:
                framed_c.send(FRAME_CLOSE)
            except Exception:
                pass
            framed_c.close()
            return

        _start_bridge(framed_a, framed_c)

    try:
        while True:
            conn, addr = server.accept()
            try:
                role = _recv_exact(conn, 8).decode(errors="ignore").strip()
                token = _recv_exact(conn, 32)

                if role not in ("ROLE_A", "ROLE_C") or not verify_token(role, token):
                    print(f"[!] 拒绝非法连接: {addr} role={role!r}")
                    safe_close_sock(conn)
                    continue

                print(f"[+] {role} 认证成功: {addr}")
                framed = FramedConn(conn, name=f"B<->{role}")

                if role == "ROLE_A":
                    _handle_role_a(framed)
                else:
                    _handle_role_c(framed)

            except Exception as e:
                print(f"[!] 处理连接时出错: {e}")
                safe_close_sock(conn)
    except KeyboardInterrupt:
        print("\n[*] 收到退出信号，关闭服务...")
    finally:
        with waiting_lock:
            _release_waiting_a_locked(reason="服务退出")
        safe_close_sock(server)


if __name__ == "__main__":
    main()
