# -*- coding: utf-8 -*-

from secret_tool import generate_token, verify_token

ROLE_A = "ROLE_A"
ROLE_C = "ROLE_C"
VALID_ROLES = {ROLE_A, ROLE_C}

ROLE_FIELD_LEN = 8
TOKEN_LEN = 32


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("对端在握手阶段关闭")
        buf.extend(chunk)
    return bytes(buf)


def send_role_handshake(sock, role):
    if role not in VALID_ROLES:
        raise ValueError(f"未知角色: {role!r}")
    sock.sendall(role.ljust(ROLE_FIELD_LEN).encode("ascii"))
    sock.sendall(generate_token(role))


def recv_role_handshake(sock):
    role = recv_exact(sock, ROLE_FIELD_LEN).decode(errors="ignore").strip()
    token = recv_exact(sock, TOKEN_LEN)
    return role, token


def verify_role_handshake(sock):
    role, token = recv_role_handshake(sock)
    return role, role in VALID_ROLES and verify_token(role, token)
