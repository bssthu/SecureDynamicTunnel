# -*- coding: utf-8 -*-

import socket
import threading
from secret_tool import verify_token
from framing import FramedConn, run_bridge, safe_close_sock

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

    # 用于存放等待配对的 FramedConn（已通过认证）
    waiting = {"ROLE_A": None, "ROLE_C": None}
    waiting_lock = threading.Lock()

    try:
        while True:
            conn, addr = server.accept()
            try:
                # 握手仍是裸字节：前 8 字节角色名 + 32 字节 HMAC
                role = _recv_exact(conn, 8).decode(errors="ignore").strip()
                token = _recv_exact(conn, 32)

                if role not in ("ROLE_A", "ROLE_C") or not verify_token(role, token):
                    print(f"[!] 拒绝非法连接: {addr} role={role!r}")
                    safe_close_sock(conn)
                    continue

                print(f"[+] {role} 认证成功: {addr}")
                framed = FramedConn(conn, name=f"B<->{role}")

                pair = None
                with waiting_lock:
                    # 同角色重连：把旧的等待连接关掉
                    old = waiting[role]
                    if old is not None:
                        print(f"[!] {role} 已存在等待连接，关闭旧连接")
                        old.close()
                    waiting[role] = framed

                    if waiting["ROLE_A"] and waiting["ROLE_C"]:
                        pair = (waiting["ROLE_A"], waiting["ROLE_C"])
                        waiting["ROLE_A"] = waiting["ROLE_C"] = None

                if pair is not None:
                    _start_bridge(pair[0], pair[1])

            except Exception as e:
                print(f"[!] 处理连接时出错: {e}")
                safe_close_sock(conn)
    except KeyboardInterrupt:
        print("\n[*] 收到退出信号，关闭服务...")
    finally:
        with waiting_lock:
            for f in waiting.values():
                if f is not None:
                    f.close()
        safe_close_sock(server)


if __name__ == "__main__":
    main()
