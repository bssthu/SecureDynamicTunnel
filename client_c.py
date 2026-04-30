# -*- coding: utf-8 -*-

import socket
import threading
import time
from secret_tool import generate_token
from framing import FramedConn, run_endpoint, safe_close_sock

B_SERVER_IP = "B_MACHINE_PUBLIC_IP"
B_PORT = 9001

# 本地监听配置
BIND_IP = "127.0.0.1"        # 监听的本地 IP，如需外部访问可设为 "0.0.0.0"
LOCAL_LISTEN_PORT = 8080     # 在 C 机器访问 BIND_IP:LOCAL_LISTEN_PORT

# 断线重连配置
CONNECT_TIMEOUT = 5          # 单次连接 B 的超时(秒)
RECONNECT_MAX_RETRIES = 0    # 0 = 无限重连；>0 时连续失败超过该次数即放弃并断开本地连接
RECONNECT_INTERVAL = 2       # 每次重试间隔(秒)


def connect_to_b():
    """尝试连接并认证到 B。失败按配置重试，全部失败返回 None。"""
    last_err = None
    attempt = 0
    while True:
        attempt += 1
        b_sock = None
        try:
            b_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            b_sock.settimeout(CONNECT_TIMEOUT)
            b_sock.connect((B_SERVER_IP, B_PORT))

            # 握手认证（裸字节，与帧协议无关）
            b_sock.sendall("ROLE_C  ".encode())
            b_sock.sendall(generate_token("ROLE_C"))

            b_sock.settimeout(None)
            return b_sock
        except Exception as e:
            last_err = e
            safe_close_sock(b_sock)
            if RECONNECT_MAX_RETRIES:
                print(f"[!] 第 {attempt}/{RECONNECT_MAX_RETRIES} 次连接 B 失败: {e}")
                if attempt >= RECONNECT_MAX_RETRIES:
                    print(f"[x] 已达到最大重试次数，放弃连接 B (最后错误: {last_err})")
                    return None
            else:
                print(f"[!] 第 {attempt} 次连接 B 失败: {e}，{RECONNECT_INTERVAL}s 后重试")
            time.sleep(RECONNECT_INTERVAL)


def bridge_handler(c_user_conn):
    b_sock = connect_to_b()
    if b_sock is None:
        # 一直重连不上：正确断开本地连接
        safe_close_sock(c_user_conn)
        return

    framed = FramedConn(b_sock, name="C<->B")
    try:
        # 用户裸字节 <-> 帧化的 B 链路。心跳/看门狗由 run_endpoint 内部处理。
        run_endpoint(framed, c_user_conn, role_label="C")
    except Exception as e:
        print(f"[!] 隧道转发异常: {e}")
        framed.close()
        safe_close_sock(c_user_conn)


def main():
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((BIND_IP, LOCAL_LISTEN_PORT))
    ls.listen(10)
    print(f"[*] 客户端代理启动。请访问 http://{BIND_IP}:{LOCAL_LISTEN_PORT}")

    try:
        while True:
            c_user, _ = ls.accept()
            threading.Thread(target=bridge_handler, args=(c_user,), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[*] 收到退出信号，关闭监听...")
    finally:
        safe_close_sock(ls)


if __name__ == "__main__":
    main()
