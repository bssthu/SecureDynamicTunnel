# -*- coding: utf-8 -*-

import socket
import threading
from secret_tool import verify_token

LISTEN_PORT = 9001

def bridge(s1, s2):
    try:
        while True:
            data = s1.recv(8192)
            if not data: break
            s2.sendall(data)
    except: pass
    finally:
        s1.close(); s2.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', LISTEN_PORT))
    server.listen(20)
    print(f"[*] 中转机器 B 已启动，监听端口 {LISTEN_PORT}...")

    # 用于存放等待配对的连接
    waiting_conns = {"ROLE_A": None, "ROLE_C": None}

    while True:
        conn, addr = server.accept()
        try:
            # 协议：前 8 字节角色名，后 32 字节 HMAC
            role = conn.recv(8).decode().strip()
            token = conn.recv(32)

            if not verify_token(role, token):
                print(f"[!] 拒绝非法连接: {addr}")
                conn.close()
                continue

            print(f"[+] {role} 认证成功: {addr}")
            waiting_conns[role] = conn

            # 只有当 A 和 C 同时在线时，打通隧道
            if waiting_conns["ROLE_A"] and waiting_conns["ROLE_C"]:
                a_side = waiting_conns["ROLE_A"]
                c_side = waiting_conns["ROLE_C"]
                
                threading.Thread(target=bridge, args=(a_side, c_side), daemon=True).start()
                threading.Thread(target=bridge, args=(c_side, a_side), daemon=True).start()
                
                # 重置等待列表
                waiting_conns["ROLE_A"] = waiting_conns["ROLE_C"] = None
                print("[***] A-C 隧道建立成功！")
                
        except Exception as e:
            print(f"[!] 处理连接时出错: {e}")
            conn.close()

if __name__ == "__main__":
    main()
