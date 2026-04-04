# -*- coding: utf-8 -*-

import socket
import threading
from secret_tool import generate_token

B_SERVER_IP = "B_MACHINE_PUBLIC_IP"
B_PORT = 9001
LOCAL_LISTEN_PORT = 8080 # 你在 C 机器访问 localhost:8080

def bridge_handler(c_user_conn):
    try:
        # 1. 接到本地请求后，立即去 B 开启隧道
        b_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        b_sock.connect((B_SERVER_IP, B_PORT))
        
        # 2. 认证
        b_sock.sendall("ROLE_C  ".encode())
        b_sock.sendall(generate_token("ROLE_C"))

        # 3. 数据转发
        def fwd(s, d):
            try:
                while True:
                    data = s.recv(8192)
                    if not data: break
                    d.sendall(data)
            except: pass
            finally: s.close(); d.close()

        threading.Thread(target=fwd, args=(c_user_conn, b_sock), daemon=True).start()
        fwd(b_sock, c_user_conn)
    except Exception as e:
        print(f"[!] 建立隧道失败: {e}")
        c_user_conn.close()

def main():
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.bind(('127.0.0.1', LOCAL_LISTEN_PORT))
    ls.listen(10)
    print(f"[*] 客户端代理启动。请访问 http://localhost:{LOCAL_LISTEN_PORT}")

    while True:
        c_user, _ = ls.accept()
        threading.Thread(target=bridge_handler, args=(c_user,), daemon=True).start()

if __name__ == "__main__":
    main()
