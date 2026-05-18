# -*- coding: utf-8 -*-

import socket

from crypto import (
    client_handshake as _client_handshake,
    server_handshake as _server_handshake,
)

ROLE_A = "ROLE_A"
ROLE_C = "ROLE_C"
VALID_ROLES = {ROLE_A, ROLE_C}

ROLE_FIELD_LEN = 8


def _role_field(role):
    if role not in VALID_ROLES:
        raise ValueError(f"未知角色: {role!r}")
    return role.ljust(ROLE_FIELD_LEN).encode("ascii")


def send_role_handshake(sock, role):
    """
    A/C 端握手。返回 (send_cipher, recv_cipher)。
    握手失败（网络/认证）抛 ConnectionError。
    """
    return _client_handshake(sock, _role_field(role))


def verify_role_handshake(sock):
    """
    B 端握手。返回 (role, ok, send_cipher, recv_cipher)。
    ok=False 时 cipher 为 None，调用方应关闭连接。
    所有握手失败统一为 (role_or_'', False, None, None)，便于上层做日志。
    """
    try:
        role, send_cipher, recv_cipher = _server_handshake(
            sock, ROLE_FIELD_LEN, VALID_ROLES,
        )
        return role, True, send_cipher, recv_cipher
    except ConnectionError as e:
        return _extract_role_from_error(e), False, None, None
    except (socket.timeout, OSError):
        return "", False, None, None


def _extract_role_from_error(err):
    msg = str(err)
    marker = "未知角色: "
    if marker in msg:
        try:
            return msg.split(marker, 1)[1].strip().strip("'\"")
        except Exception:
            return ""
    return ""
