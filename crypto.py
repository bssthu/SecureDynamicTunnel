# -*- coding: utf-8 -*-
"""
SDT v2 安全层：
- 启动期校验 SHARED_KEY 强度（最小长度 & 不允许示例默认值）。
- 三端握手：X25519 ECDH 派生临时会话密钥 + HMAC-SHA256(SHARED_KEY) 双向认证。
- 数据帧加密：ChaCha20-Poly1305 AEAD，nonce 由单调 seq 派生，天然防重放/防乱序。

威胁模型回应：
- 旁路抓包：业务流量全部 AEAD 加密，仅能看到帧头(类型+长度)。
- 中间人：因 ECDH 公钥用 PSK 做 HMAC 绑定，攻击者无 SHARED_KEY 无法伪造握手，
  也无法替换公钥而不被察觉，故无法接管会话。
- 重放：握手两端各发 16B 随机 nonce 并参与密钥派生；数据帧 seq 决定 nonce，
  重放/重排会导致 AEAD tag 校验失败。
- 弱口令离线爆破：HMAC 用 PSK 仅在握手阶段使用一次，无法降低协议强度；
  但仍要求 PSK 长度 >= MIN_SHARED_KEY_LEN，且禁用示例默认值。
"""

import hmac
import hashlib
import os
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from config import SHARED_KEY

# ---------- 常量 ----------

MIN_SHARED_KEY_LEN = 16
_FORBIDDEN_DEFAULT_KEYS = {
    "Your_Super_Strong_Random_Secret_Key_2026",
    "",
    "CHANGE_ME",
    "change_me",
}

NONCE_LEN = 16        # 握手期一次性随机串
PUB_LEN = 32          # X25519 公钥长度
MAC_LEN = 32          # HMAC-SHA256 输出长度
KEY_LEN = 32          # ChaCha20-Poly1305 密钥长度
TAG_LEN = 16          # Poly1305 tag 长度
SEQ_NONCE_LEN = 12    # ChaCha20-Poly1305 nonce 长度

_CLIENT_MAC_LABEL = b"sdt-v2-client"
_SERVER_MAC_LABEL = b"sdt-v2-server"
_HKDF_SESSION_INFO = b"sdt-v2 session"
_HKDF_C2S_INFO = b"sdt-v2 c2s"
_HKDF_S2C_INFO = b"sdt-v2 s2c"

# 序号空间上限：2^63，远超任何真实会话寿命；越界主动拒绝以防 nonce 重用。
_MAX_SEQ = 1 << 63


class SharedKeyError(RuntimeError):
    """SHARED_KEY 不符合强度要求时抛出。"""


def validate_shared_key():
    """启动期调用：不通过则直接抛 SharedKeyError 让进程退出。"""
    if not isinstance(SHARED_KEY, str):
        raise SharedKeyError("SHARED_KEY 必须是字符串")
    if SHARED_KEY in _FORBIDDEN_DEFAULT_KEYS:
        raise SharedKeyError(
            "SHARED_KEY 仍为示例/占位默认值，请改为强随机字符串后再启动。"
            f" 当前最小长度要求 {MIN_SHARED_KEY_LEN} 字符。"
        )
    if len(SHARED_KEY) < MIN_SHARED_KEY_LEN:
        raise SharedKeyError(
            f"SHARED_KEY 长度必须 ≥ {MIN_SHARED_KEY_LEN} 字符 "
            f"(当前 {len(SHARED_KEY)})。请使用 ≥32 字符的高熵随机字符串。"
        )


# 模块导入时立即校验；测试用 conftest 会在导入前注入合规 key。
validate_shared_key()
_PSK = SHARED_KEY.encode("utf-8")


# ---------- 内部工具 ----------

def _mac(label, *parts):
    h = hmac.new(_PSK, digestmod=hashlib.sha256)
    h.update(label)
    for p in parts:
        h.update(p)
    return h.digest()


def _pub_bytes(priv_key):
    return priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _derive_session_keys(shared, client_nonce, server_nonce):
    """返回 (k_c2s, k_s2c)。"""
    salt = _PSK + client_nonce + server_nonce
    base = HKDF(
        algorithm=hashes.SHA256(), length=KEY_LEN,
        salt=salt, info=_HKDF_SESSION_INFO,
    ).derive(shared)
    k_c2s = HKDF(
        algorithm=hashes.SHA256(), length=KEY_LEN,
        salt=None, info=_HKDF_C2S_INFO,
    ).derive(base)
    k_s2c = HKDF(
        algorithm=hashes.SHA256(), length=KEY_LEN,
        salt=None, info=_HKDF_S2C_INFO,
    ).derive(base)
    return k_c2s, k_s2c


# ---------- 帧密码器 ----------

class FrameCipher:
    """单方向的 AEAD 流：seq 单调递增派生 nonce，重放/丢帧/乱序均会校验失败。"""

    def __init__(self, key):
        if len(key) != KEY_LEN:
            raise ValueError("密钥长度错误")
        self._aead = ChaCha20Poly1305(key)
        self._seq = 0

    def _next_nonce(self):
        if self._seq >= _MAX_SEQ:
            raise RuntimeError("序号空间耗尽，会话需重建")
        nonce = b"\x00\x00\x00\x00" + struct.pack("!Q", self._seq)
        self._seq += 1
        return nonce

    def encrypt(self, aad, plaintext):
        return self._aead.encrypt(self._next_nonce(), plaintext, aad)

    def decrypt(self, aad, ciphertext):
        return self._aead.decrypt(self._next_nonce(), ciphertext, aad)


# ---------- 握手 ----------

def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("对端在握手阶段关闭")
        buf.extend(chunk)
    return bytes(buf)


def client_handshake(sock, role_field):
    """
    A/C 端握手。role_field 必须是已经 ljust(ROLE_FIELD_LEN) 的 ASCII bytes。
    成功返回 (send_cipher, recv_cipher)；失败抛 ConnectionError。
    """
    priv = X25519PrivateKey.generate()
    pub = _pub_bytes(priv)
    client_nonce = os.urandom(NONCE_LEN)
    client_mac = _mac(_CLIENT_MAC_LABEL, role_field, pub, client_nonce)
    sock.sendall(role_field + pub + client_nonce + client_mac)

    server_pub_bytes = _recv_exact(sock, PUB_LEN)
    server_nonce = _recv_exact(sock, NONCE_LEN)
    server_mac = _recv_exact(sock, MAC_LEN)

    expected = _mac(
        _SERVER_MAC_LABEL,
        role_field, pub, client_nonce, server_pub_bytes, server_nonce,
    )
    if not hmac.compare_digest(expected, server_mac):
        raise ConnectionError("服务端握手认证失败 (MAC mismatch)")

    server_pub = X25519PublicKey.from_public_bytes(server_pub_bytes)
    shared = priv.exchange(server_pub)
    k_c2s, k_s2c = _derive_session_keys(shared, client_nonce, server_nonce)
    return FrameCipher(k_c2s), FrameCipher(k_s2c)


def server_handshake(sock, role_field_len, valid_roles):
    """
    B 端握手。返回 (role_str, send_cipher, recv_cipher)。
    任何认证/格式失败均抛 ConnectionError，由调用方关闭连接。
    """
    role_field = _recv_exact(sock, role_field_len)
    client_pub_bytes = _recv_exact(sock, PUB_LEN)
    client_nonce = _recv_exact(sock, NONCE_LEN)
    client_mac = _recv_exact(sock, MAC_LEN)

    role = role_field.decode("ascii", errors="ignore").strip()
    if role not in valid_roles:
        # 仍走完 MAC 校验流程的话需要 PSK 已知；这里直接拒绝即可，
        # 因为 role 字段是明文，攻击者无 PSK 也算不出对的 MAC。
        raise ConnectionError(f"未知角色: {role!r}")

    expected = _mac(_CLIENT_MAC_LABEL, role_field, client_pub_bytes, client_nonce)
    if not hmac.compare_digest(expected, client_mac):
        raise ConnectionError("客户端握手认证失败 (MAC mismatch)")

    priv = X25519PrivateKey.generate()
    pub = _pub_bytes(priv)
    server_nonce = os.urandom(NONCE_LEN)
    server_mac = _mac(
        _SERVER_MAC_LABEL,
        role_field, client_pub_bytes, client_nonce, pub, server_nonce,
    )
    sock.sendall(pub + server_nonce + server_mac)

    client_pub = X25519PublicKey.from_public_bytes(client_pub_bytes)
    shared = priv.exchange(client_pub)
    k_c2s, k_s2c = _derive_session_keys(shared, client_nonce, server_nonce)
    # 服务端：解密 client→server 用 k_c2s；加密 server→client 用 k_s2c
    return role, FrameCipher(k_s2c), FrameCipher(k_c2s)
