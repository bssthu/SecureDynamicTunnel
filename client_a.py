# -*- coding: utf-8 -*-

import socket
import time
import threading
from secret_tool import generate_token

# 配置
B_SERVER_IP = "B_MACHINE_PUBLIC_IP" # 填写 B 的公网 IP
B_PORT = 9001
LOCAL_SERVICE_ADDR = ("127.0.0.1", 80) # A 机器上服务的真实地址

def forward(src, dst):
    try:
        while True:
            data = src.recv(8192)
            if not data: break
            dst.sendall(data)
    except: pass
    finally:
        src.close(); dst.close()

def connect_loop():
    while True:
        try:
            # 1. 拨号到 B
            b_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            b_sock.connect((B_SERVER_IP, B_PORT))
            
            # 2. 发送认证信息
            b_sock.sendall("ROLE_A  ".encode()) # 补齐 8 字节
            b_sock.sendall(generate_token("ROLE_A"))
            print("[*] 已在 B 挂载服务，等待客户端 C...")

            # 3. 此时 B 会阻塞该连接，直到 C 出现。
            # 一旦收到数据，说明 C 接入了，立即连接 A 的本地服务。
            data_test = b_sock.recv(1, socket.MSG_PEEK) # 嗅探是否有数据流
            if not data_test: raise Exception("B 断开了连接")

            local_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            local_sock.connect(LOCAL_SERVICE_ADDR)

            # 4. 双向转发
            threading.Thread(target=forward, args=(b_sock, local_sock), daemon=True).start()
            forward(local_sock, b_sock)
            
        except Exception as e:
            print(f"[!] 连接中断 ({e})，5秒后重试...")
            time.sleep(5)

if __name__ == "__main__":
    connect_loop()
