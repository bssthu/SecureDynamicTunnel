# -*- coding: utf-8 -*-
"""A↔C end-to-end security carried inside the B-facing frame protocol.

B relays these packets as opaque FRAME_DATA payloads. A and C authenticate each
other with A_C_E2E_KEY, perform an ephemeral X25519 exchange per business
stream, and protect application chunks with directional ChaCha20-Poly1305 keys.
"""

import hashlib
import hmac
import os
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from config import A_C_E2E_KEY
from crypto import FrameCipher, KEY_LEN, MAC_LEN, NONCE_LEN, PUB_LEN, TAG_LEN


MIN_E2E_KEY_LEN = 16
_FORBIDDEN_DEFAULT_KEYS = {
    "",
    "CHANGE_ME",
    "change_me",
    "Your_Super_Strong_Random_Secret_Key_2026",
}

_MAGIC = b"SE2E"
_VERSION = 1
_TYPE_CLIENT_HELLO = 1
_TYPE_SERVER_HELLO = 2
_TYPE_DATA = 3
_HEADER = struct.Struct("!4sBB")

_CLIENT_HELLO_LEN = _HEADER.size + PUB_LEN + NONCE_LEN + MAC_LEN
_SERVER_HELLO_LEN = _CLIENT_HELLO_LEN

_CLIENT_MAC_LABEL = b"sdt-v3-e2e-client"
_SERVER_MAC_LABEL = b"sdt-v3-e2e-server"
_SALT_LABEL = b"sdt-v3-e2e-salt"
_SESSION_INFO = b"sdt-v3 a-c e2e session"
_C2A_INFO = b"sdt-v3 a-c e2e c2a"
_A2C_INFO = b"sdt-v3 a-c e2e a2c"


class E2EError(Exception):
    """The end-to-end handshake or record layer is invalid."""


class E2EKeyError(RuntimeError):
    """A_C_E2E_KEY is missing or obviously unsafe."""


def validate_e2e_key(value=None):
    key = A_C_E2E_KEY if value is None else value
    if not isinstance(key, str):
        raise E2EKeyError("A_C_E2E_KEY 必须是字符串")
    if key in _FORBIDDEN_DEFAULT_KEYS:
        raise E2EKeyError(
            "A_C_E2E_KEY 仍为示例/占位值，请在 A、C 上配置独立的强随机密钥。"
        )
    if len(key) < MIN_E2E_KEY_LEN:
        raise E2EKeyError(
            f"A_C_E2E_KEY 长度必须 ≥ {MIN_E2E_KEY_LEN} 字符 "
            f"(当前 {len(key)})。请使用 ≥32 字符的高熵随机字符串。"
        )
    return key.encode("utf-8")


_DEFAULT_PSK = validate_e2e_key()


def _resolve_psk(psk):
    if psk is None:
        return _DEFAULT_PSK
    if isinstance(psk, str):
        return validate_e2e_key(psk)
    if not isinstance(psk, bytes) or len(psk) < MIN_E2E_KEY_LEN:
        raise E2EKeyError("端到端测试密钥必须是至少 16 字节的 bytes")
    return psk


def _header(packet_type):
    return _HEADER.pack(_MAGIC, _VERSION, packet_type)


def _parse_header(packet, expected_type, expected_len=None):
    if expected_len is not None and len(packet) != expected_len:
        raise E2EError(f"端到端包长度错误: {len(packet)}")
    if len(packet) < _HEADER.size:
        raise E2EError("端到端包头长度不足")
    magic, version, packet_type = _HEADER.unpack_from(packet)
    if magic != _MAGIC or version != _VERSION or packet_type != expected_type:
        raise E2EError("端到端包头无效或版本不兼容")


def _mac(psk, label, *parts):
    digest = hmac.new(psk, digestmod=hashlib.sha256)
    digest.update(label)
    for part in parts:
        digest.update(part)
    return digest.digest()


def _pub_bytes(private_key):
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _derive_keys(psk, shared, client_nonce, server_nonce):
    salt = _mac(psk, _SALT_LABEL, client_nonce, server_nonce)
    base = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        info=_SESSION_INFO,
    ).derive(shared)
    c2a = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=None,
        info=_C2A_INFO,
    ).derive(base)
    a2c = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=None,
        info=_A2C_INFO,
    ).derive(base)
    return c2a, a2c


class E2EChannel:
    """Directional AEAD record layer for one A↔C business stream."""

    def __init__(self, send_key, recv_key):
        self._send_cipher = FrameCipher(send_key)
        self._recv_cipher = FrameCipher(recv_key)

    def seal(self, plaintext):
        if not isinstance(plaintext, bytes):
            raise TypeError("端到端明文必须是 bytes")
        header = _header(_TYPE_DATA)
        return header + self._send_cipher.encrypt(header, plaintext)

    def open(self, packet):
        _parse_header(packet, _TYPE_DATA)
        ciphertext = packet[_HEADER.size:]
        if len(ciphertext) < TAG_LEN:
            raise E2EError("端到端密文长度不足")
        try:
            return self._recv_cipher.decrypt(packet[:_HEADER.size], ciphertext)
        except Exception as exc:
            raise E2EError("端到端数据解密或鉴权失败") from exc


class E2EClientHandshake:
    """C-side state for a per-stream authenticated ephemeral handshake."""

    def __init__(self, psk=None):
        self._psk = _resolve_psk(psk)
        self._private_key = X25519PrivateKey.generate()
        self._public_key = _pub_bytes(self._private_key)
        self._nonce = os.urandom(NONCE_LEN)
        core = _header(_TYPE_CLIENT_HELLO) + self._public_key + self._nonce
        self._packet = core + _mac(self._psk, _CLIENT_MAC_LABEL, core)
        self._finished = False

    @property
    def initial_packet(self):
        return self._packet

    def finish(self, server_packet):
        if self._finished:
            raise E2EError("端到端客户端握手已完成")
        _parse_header(server_packet, _TYPE_SERVER_HELLO, _SERVER_HELLO_LEN)
        server_core = server_packet[:-MAC_LEN]
        server_mac = server_packet[-MAC_LEN:]
        expected = _mac(
            self._psk,
            _SERVER_MAC_LABEL,
            self._packet,
            server_core,
        )
        if not hmac.compare_digest(expected, server_mac):
            raise E2EError("A 端端到端握手认证失败")

        offset = _HEADER.size
        server_pub_bytes = server_packet[offset:offset + PUB_LEN]
        server_nonce = server_packet[offset + PUB_LEN:offset + PUB_LEN + NONCE_LEN]
        try:
            server_pub = X25519PublicKey.from_public_bytes(server_pub_bytes)
            shared = self._private_key.exchange(server_pub)
        except Exception as exc:
            raise E2EError("A 端 X25519 公钥无效") from exc

        c2a, a2c = _derive_keys(self._psk, shared, self._nonce, server_nonce)
        self._finished = True
        self._private_key = None
        return E2EChannel(send_key=c2a, recv_key=a2c)


def accept_client_hello(client_packet, psk=None):
    """Verify C's hello and return (A response packet, A-side channel)."""
    resolved_psk = _resolve_psk(psk)
    _parse_header(client_packet, _TYPE_CLIENT_HELLO, _CLIENT_HELLO_LEN)
    client_core = client_packet[:-MAC_LEN]
    client_mac = client_packet[-MAC_LEN:]
    expected = _mac(resolved_psk, _CLIENT_MAC_LABEL, client_core)
    if not hmac.compare_digest(expected, client_mac):
        raise E2EError("C 端端到端握手认证失败")

    offset = _HEADER.size
    client_pub_bytes = client_packet[offset:offset + PUB_LEN]
    client_nonce = client_packet[offset + PUB_LEN:offset + PUB_LEN + NONCE_LEN]
    private_key = X25519PrivateKey.generate()
    public_key = _pub_bytes(private_key)
    server_nonce = os.urandom(NONCE_LEN)
    server_core = _header(_TYPE_SERVER_HELLO) + public_key + server_nonce
    server_packet = server_core + _mac(
        resolved_psk,
        _SERVER_MAC_LABEL,
        client_packet,
        server_core,
    )

    try:
        client_pub = X25519PublicKey.from_public_bytes(client_pub_bytes)
        shared = private_key.exchange(client_pub)
    except Exception as exc:
        raise E2EError("C 端 X25519 公钥无效") from exc

    c2a, a2c = _derive_keys(
        resolved_psk,
        shared,
        client_nonce,
        server_nonce,
    )
    return server_packet, E2EChannel(send_key=a2c, recv_key=c2a)
