# -*- coding: utf-8 -*-

import socket
import struct
import threading
import time

import pytest

import framing
import server_b
from framing import FRAME_CLOSE, FRAME_DATA
from tunnel_common import (
    ROLE_A,
    ROLE_C,
    ROLE_FIELD_LEN,
    send_role_handshake,
    verify_role_handshake,
)

_HDR = struct.Struct("!BI")


@pytest.fixture(scope="session", autouse=True)
def _quiet_background_logs():
    server_b.log = lambda *_args, **_kwargs: None
    framing.log = lambda *_args, **_kwargs: None


def _free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed")
        buf.extend(chunk)
    return bytes(buf)


def _recv_frame(sock):
    header = _recv_exact(sock, _HDR.size)
    ftype, length = _HDR.unpack(header)
    payload = _recv_exact(sock, length) if length else b""
    return ftype, payload


def _send_frame(sock, ftype, payload=b""):
    sock.sendall(_HDR.pack(ftype, len(payload)) + payload)


def _connect_role(port, role):
    sock = socket.create_connection(("127.0.0.1", port), timeout=2)
    send_role_handshake(sock, role)
    sock.settimeout(2)
    return sock


def _assert_not_closed(sock):
    sock.setblocking(False)
    try:
        try:
            data = sock.recv(1)
        except BlockingIOError:
            return
        assert data != b"", "socket was closed"
        assert data[0] != FRAME_CLOSE, "server sent CLOSE"
    finally:
        sock.setblocking(True)
        sock.settimeout(2)


@pytest.fixture()
def b_server(monkeypatch):
    port = _free_port()
    monkeypatch.setattr(server_b, "B_LISTEN_HOST", "127.0.0.1")
    monkeypatch.setattr(server_b, "B_LISTEN_PORT", port)
    monkeypatch.setattr(server_b, "C_WAIT_TIMEOUT", 0.25)

    thread = threading.Thread(target=server_b.main, daemon=True)
    thread.start()
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            probe = socket.create_connection(("127.0.0.1", port), timeout=0.1)
            probe.close()
            break
        except OSError:
            time.sleep(0.01)
    else:
        raise RuntimeError("server_b did not start")

    return port


def test_role_handshake_round_trip():
    left, right = socket.socketpair()
    try:
        send_role_handshake(left, ROLE_A)
        role, ok = verify_role_handshake(right)
        assert role == ROLE_A
        assert ok is True
    finally:
        left.close()
        right.close()


def test_invalid_role_handshake_is_rejected():
    left, right = socket.socketpair()
    try:
        left.sendall(b"ROLE_X".ljust(ROLE_FIELD_LEN, b" "))
        left.sendall(b"0" * 32)
        role, ok = verify_role_handshake(right)
        assert role == "ROLE_X"
        assert ok is False
    finally:
        left.close()
        right.close()


def test_c_gets_http_503_frame_when_no_a_is_available(b_server):
    c_sock = _connect_role(b_server, ROLE_C)
    try:
        ftype, payload = _recv_frame(c_sock)
        assert ftype == FRAME_DATA
        assert b"HTTP/1.1 503 Service Unavailable" in payload
        assert b"no available tunnel peer A" in payload
    finally:
        c_sock.close()


def test_b_keeps_multiple_waiting_a_connections(b_server):
    a_socks = [_connect_role(b_server, ROLE_A) for _ in range(4)]
    try:
        time.sleep(0.2)
        for sock in a_socks:
            _assert_not_closed(sock)
    finally:
        for sock in a_socks:
            sock.close()


def test_c_claims_waiting_a_and_forwards_first_data(b_server):
    a_sock = _connect_role(b_server, ROLE_A)
    try:
        time.sleep(0.1)
        c_sock = _connect_role(b_server, ROLE_C)
        try:
            _send_frame(c_sock, FRAME_DATA, b"hello")
            ftype, payload = _recv_frame(a_sock)
            assert ftype == FRAME_DATA
            assert payload == b"hello"
        finally:
            c_sock.close()
    finally:
        a_sock.close()


def test_waiting_a_queue_is_fifo_for_c_pairing(b_server):
    a1 = _connect_role(b_server, ROLE_A)
    a2 = _connect_role(b_server, ROLE_A)
    try:
        time.sleep(0.2)
        c_sock = _connect_role(b_server, ROLE_C)
        try:
            _send_frame(c_sock, FRAME_DATA, b"first")
            ftype, payload = _recv_frame(a1)
            assert ftype == FRAME_DATA
            assert payload == b"first"
            _assert_not_closed(a2)
        finally:
            c_sock.close()
    finally:
        a1.close()
        a2.close()
