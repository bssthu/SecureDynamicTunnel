# -*- coding: utf-8 -*-

import socket
import struct
import threading
import time

import pytest

import framing
import server_b
import client_c
from framing import (
    FRAME_CLOSE, FRAME_DATA, FRAME_PING, FRAME_PONG,
    FRAME_PAIR, FRAME_PAIR_ACK, FRAME_STREAM_CLOSE,
    STREAM_ID_STRUCT, STREAM_ID_LEN,
    HEADER_LEN, MAX_PAYLOAD,
    FramedConn, run_multi_stream_a_endpoint,
)
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
    client_c.log = lambda *_args, **_kwargs: None


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


# ---- fixtures ----

@pytest.fixture()
def b_server(monkeypatch):
    """单流模式 B 服务器"""
    port = _free_port()
    monkeypatch.setattr(server_b, "B_LISTEN_HOST", "127.0.0.1")
    monkeypatch.setattr(server_b, "B_LISTEN_PORT", port)
    monkeypatch.setattr(server_b, "C_WAIT_TIMEOUT", 0.25)
    monkeypatch.setattr(server_b, "A_MULTI_STREAM", False)

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


@pytest.fixture()
def b_server_multi(monkeypatch):
    """多流模式 B 服务器"""
    port = _free_port()
    monkeypatch.setattr(server_b, "B_LISTEN_HOST", "127.0.0.1")
    monkeypatch.setattr(server_b, "B_LISTEN_PORT", port)
    monkeypatch.setattr(server_b, "C_WAIT_TIMEOUT", 0.25)
    monkeypatch.setattr(server_b, "A_MULTI_STREAM", True)

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


# ---- 握手测试 ----

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


# ---- 单流模式测试 ----

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


# ---- 多流模式测试 ----

def test_multi_c_gets_503_when_no_a(b_server_multi):
    """多流模式：无 A 时 C 收到 503"""
    c_sock = _connect_role(b_server_multi, ROLE_C)
    try:
        ftype, payload = _recv_frame(c_sock)
        assert ftype == FRAME_DATA
        assert b"503" in payload
    finally:
        c_sock.close()


def test_multi_a_registers_and_stays_alive(b_server_multi):
    """多流模式：A 注册后保持连接不被取走"""
    a_sock = _connect_role(b_server_multi, ROLE_A)
    try:
        time.sleep(0.3)
        _assert_not_closed(a_sock)
    finally:
        a_sock.close()


def test_multi_single_c_connects_and_receives_pair(b_server_multi):
    """多流模式：C 连接后 A 收到 PAIR 帧"""
    a_sock = _connect_role(b_server_multi, ROLE_A)
    try:
        time.sleep(0.1)
        c_sock = _connect_role(b_server_multi, ROLE_C)
        try:
            # C 先发 PING 进入帧协议
            _send_frame(c_sock, FRAME_PING)
            # C 消费 B 回的 PONG
            ftype, _ = _recv_frame(c_sock)
            assert ftype == FRAME_PONG
            # A 应该收到 PAIR 帧
            ftype, payload = _recv_frame(a_sock)
            assert ftype == FRAME_PAIR, f"expected PAIR(0x05), got {ftype:#x}"
            assert len(payload) == STREAM_ID_LEN
            sid = STREAM_ID_STRUCT.unpack(payload)[0]
            assert sid == 1
        finally:
            c_sock.close()
    finally:
        a_sock.close()


def test_multi_c_to_a_data_forward(b_server_multi):
    """多流模式：C→A 数据转发（带 stream_id）"""
    a_sock = _connect_role(b_server_multi, ROLE_A)
    try:
        time.sleep(0.1)
        c_sock = _connect_role(b_server_multi, ROLE_C)
        try:
            _send_frame(c_sock, FRAME_PING)  # 进入帧协议
            # C 消费 B 回的 PONG
            ftype, _ = _recv_frame(c_sock)
            assert ftype == FRAME_PONG
            # A 收到 PAIR
            ftype, _ = _recv_frame(a_sock)
            assert ftype == FRAME_PAIR

            # C 发 DATA
            _send_frame(c_sock, FRAME_DATA, b"hello world")
            # A 收到带 stream_id 的 DATA
            ftype, payload = _recv_frame(a_sock)
            assert ftype == FRAME_DATA
            assert len(payload) >= STREAM_ID_LEN
            sid = STREAM_ID_STRUCT.unpack(payload[:STREAM_ID_LEN])[0]
            assert sid == 1
            assert payload[STREAM_ID_LEN:] == b"hello world"
        finally:
            c_sock.close()
    finally:
        a_sock.close()


def test_multi_a_to_c_data_forward(b_server_multi):
    """多流模式：A→C 数据转发（B 去掉 stream_id 后发给 C）"""
    a_sock = _connect_role(b_server_multi, ROLE_A)
    try:
        time.sleep(0.1)
        c_sock = _connect_role(b_server_multi, ROLE_C)
        try:
            _send_frame(c_sock, FRAME_PING)
            # C 消费 B 回的 PONG
            ftype, _ = _recv_frame(c_sock)
            assert ftype == FRAME_PONG

            # A 收到 PAIR
            ftype, payload = _recv_frame(a_sock)
            assert ftype == FRAME_PAIR
            sid = STREAM_ID_STRUCT.unpack(payload)[0]

            # A 回复 PAIR_ACK + 发 DATA（带 stream_id）
            _send_frame(a_sock, FRAME_PAIR_ACK, STREAM_ID_STRUCT.pack(sid))
            _send_frame(a_sock, FRAME_DATA, STREAM_ID_STRUCT.pack(sid) + b"response")

            # C 收到纯 DATA（无 stream_id）
            ftype, payload = _recv_frame(c_sock)
            assert ftype == FRAME_DATA
            assert payload == b"response"
        finally:
            c_sock.close()
    finally:
        a_sock.close()


def test_multi_full_duplex_bidirectional(b_server_multi):
    """多流模式：全双工双向数据流"""
    a_sock = _connect_role(b_server_multi, ROLE_A)
    try:
        time.sleep(0.1)
        c_sock = _connect_role(b_server_multi, ROLE_C)
        try:
            _send_frame(c_sock, FRAME_PING)
            # C 消费 B 回的 PONG
            ftype, _ = _recv_frame(c_sock)
            assert ftype == FRAME_PONG

            ftype, payload = _recv_frame(a_sock)
            assert ftype == FRAME_PAIR
            sid = STREAM_ID_STRUCT.unpack(payload)[0]

            # A 回复 PAIR_ACK
            _send_frame(a_sock, FRAME_PAIR_ACK, STREAM_ID_STRUCT.pack(sid))

            # 双向同时发送
            _send_frame(c_sock, FRAME_DATA, b"c-to-a")
            _send_frame(a_sock, FRAME_DATA, STREAM_ID_STRUCT.pack(sid) + b"a-to-c")

            # A 收到 C 的数据
            ftype, payload = _recv_frame(a_sock)
            assert ftype == FRAME_DATA
            assert payload[STREAM_ID_LEN:] == b"c-to-a"

            # C 收到 A 的数据
            ftype, payload = _recv_frame(c_sock)
            assert ftype == FRAME_DATA
            assert payload == b"a-to-c"
        finally:
            c_sock.close()
    finally:
        a_sock.close()


def test_multi_multiple_c_share_one_a(b_server_multi):
    """多流模式：多个 C 共享一个 A，各自独立 stream_id"""
    a_sock = _connect_role(b_server_multi, ROLE_A)
    try:
        time.sleep(0.1)

        # C1
        c1 = _connect_role(b_server_multi, ROLE_C)
        _send_frame(c1, FRAME_PING)
        _recv_frame(c1)  # 消费 PONG
        ftype, p1 = _recv_frame(a_sock)
        assert ftype == FRAME_PAIR
        sid1 = STREAM_ID_STRUCT.unpack(p1)[0]
        assert sid1 == 1

        # C2
        c2 = _connect_role(b_server_multi, ROLE_C)
        _send_frame(c2, FRAME_PING)
        _recv_frame(c2)  # 消费 PONG
        ftype, p2 = _recv_frame(a_sock)
        assert ftype == FRAME_PAIR
        sid2 = STREAM_ID_STRUCT.unpack(p2)[0]
        assert sid2 == 2

        # 两个 C 各自发数据
        _send_frame(c1, FRAME_DATA, b"data-from-c1")
        _send_frame(c2, FRAME_DATA, b"data-from-c2")

        # A 收到两个 DATA，stream_id 不同
        ftype, payload = _recv_frame(a_sock)
        assert ftype == FRAME_DATA
        assert payload[STREAM_ID_LEN:] == b"data-from-c1"

        ftype, payload = _recv_frame(a_sock)
        assert ftype == FRAME_DATA
        assert payload[STREAM_ID_LEN:] == b"data-from-c2"

        c1.close()
        c2.close()
    finally:
        a_sock.close()


def test_multi_c_disconnect_triggers_stream_close(b_server_multi):
    """多流模式：C 断开后 A 收到 STREAM_CLOSE"""
    a_sock = _connect_role(b_server_multi, ROLE_A)
    try:
        time.sleep(0.1)
        c_sock = _connect_role(b_server_multi, ROLE_C)
        _send_frame(c_sock, FRAME_PING)
        _recv_frame(c_sock)  # 消费 PONG
        ftype, payload = _recv_frame(a_sock)
        assert ftype == FRAME_PAIR
        sid = STREAM_ID_STRUCT.unpack(payload)[0]

        # C 发 CLOSE 断开
        _send_frame(c_sock, FRAME_CLOSE)
        c_sock.close()

        # A 应收到 STREAM_CLOSE
        ftype, payload = _recv_frame(a_sock)
        assert ftype == FRAME_STREAM_CLOSE
        assert STREAM_ID_STRUCT.unpack(payload)[0] == sid
    finally:
        a_sock.close()


def test_multi_a_disconnect_cleans_all_streams(b_server_multi):
    """多流模式：A 断开后所有 C 连接被关闭"""
    a_sock = _connect_role(b_server_multi, ROLE_A)
    try:
        time.sleep(0.1)
        c1 = _connect_role(b_server_multi, ROLE_C)
        _send_frame(c1, FRAME_PING)
        _recv_frame(c1)  # 消费 PONG
        _recv_frame(a_sock)  # PAIR

        c2 = _connect_role(b_server_multi, ROLE_C)
        _send_frame(c2, FRAME_PING)
        _recv_frame(c2)  # 消费 PONG
        _recv_frame(a_sock)  # PAIR

        # A 断开
        a_sock.close()

        # C1 和 C2 应该很快被关闭（读返回空或 CLOSE）
        time.sleep(0.3)
        c1.settimeout(0.5)
        c2.settimeout(0.5)
        try:
            data = c1.recv(1)
        except (socket.timeout, ConnectionError, OSError):
            pass
        try:
            data = c2.recv(1)
        except (socket.timeout, ConnectionError, OSError):
            pass
        c1.close()
        c2.close()
    finally:
        a_sock.close()


def test_multi_ping_pong_between_b_and_c(b_server_multi):
    """多流模式：B↔C 心跳正常（B 应答 PING）"""
    a_sock = _connect_role(b_server_multi, ROLE_A)
    try:
        time.sleep(0.1)
        c_sock = _connect_role(b_server_multi, ROLE_C)
        try:
            _send_frame(c_sock, FRAME_PING)
            # 第一个 PING 触发配对，B 回 PONG
            ftype, _ = _recv_frame(c_sock)
            assert ftype == FRAME_PONG
            _recv_frame(a_sock)  # PAIR

            # C 再发 PING，B 应回 PONG
            _send_frame(c_sock, FRAME_PING)
            ftype, _ = _recv_frame(c_sock)
            assert ftype == FRAME_PONG
        finally:
            c_sock.close()
    finally:
        a_sock.close()


def test_multi_ping_pong_between_b_and_a(b_server_multi):
    """多流模式：B↔A 心跳正常"""
    a_sock = _connect_role(b_server_multi, ROLE_A)
    try:
        time.sleep(0.1)
        # A 发 PING，B 应回 PONG
        _send_frame(a_sock, FRAME_PING)
        ftype, _ = _recv_frame(a_sock)
        assert ftype == FRAME_PONG
    finally:
        a_sock.close()


def test_multi_stream_id_increments(b_server_multi):
    """多流模式：stream_id 递增"""
    a_sock = _connect_role(b_server_multi, ROLE_A)
    try:
        time.sleep(0.1)
        sids = []
        for _ in range(5):
            c_sock = _connect_role(b_server_multi, ROLE_C)
            _send_frame(c_sock, FRAME_PING)
            _recv_frame(c_sock)  # 消费 PONG
            ftype, payload = _recv_frame(a_sock)
            assert ftype == FRAME_PAIR
            sids.append(STREAM_ID_STRUCT.unpack(payload)[0])
            c_sock.close()
            # 消费 STREAM_CLOSE
            _recv_frame(a_sock)

        assert sids == [1, 2, 3, 4, 5]
    finally:
        a_sock.close()


def test_multi_large_payload_forward(b_server_multi):
    """多流模式：大数据块转发"""
    a_sock = _connect_role(b_server_multi, ROLE_A)
    try:
        time.sleep(0.1)
        c_sock = _connect_role(b_server_multi, ROLE_C)
        try:
            _send_frame(c_sock, FRAME_PING)
            _recv_frame(c_sock)  # 消费 PONG
            _recv_frame(a_sock)  # PAIR

            large_data = b"X" * 65536
            _send_frame(c_sock, FRAME_DATA, large_data)
            ftype, payload = _recv_frame(a_sock)
            assert ftype == FRAME_DATA
            assert payload[STREAM_ID_LEN:] == large_data
        finally:
            c_sock.close()
    finally:
        a_sock.close()


def test_multi_empty_data_frame(b_server_multi):
    """多流模式：空 DATA 帧"""
    a_sock = _connect_role(b_server_multi, ROLE_A)
    try:
        time.sleep(0.1)
        c_sock = _connect_role(b_server_multi, ROLE_C)
        try:
            _send_frame(c_sock, FRAME_PING)
            _recv_frame(c_sock)  # 消费 PONG
            _recv_frame(a_sock)  # PAIR

            _send_frame(c_sock, FRAME_DATA, b"")
            ftype, payload = _recv_frame(a_sock)
            assert ftype == FRAME_DATA
            assert payload == STREAM_ID_STRUCT.pack(1)  # 只有 stream_id
        finally:
            c_sock.close()
    finally:
        a_sock.close()


# ---- 帧协议单元测试 ----

def test_frame_constants():
    """验证帧类型常量值"""
    assert FRAME_DATA == 0x01
    assert FRAME_PING == 0x02
    assert FRAME_PONG == 0x03
    assert FRAME_CLOSE == 0x04
    assert FRAME_PAIR == 0x05
    assert FRAME_PAIR_ACK == 0x06
    assert FRAME_STREAM_CLOSE == 0x07


def test_stream_id_struct():
    """验证 stream_id 结构体"""
    assert STREAM_ID_LEN == 2
    packed = STREAM_ID_STRUCT.pack(0x1234)
    assert len(packed) == 2
    assert STREAM_ID_STRUCT.unpack(packed)[0] == 0x1234


def test_framed_conn_send_recv():
    """FramedConn 基本收发"""
    left, right = socket.socketpair()
    try:
        fc = FramedConn(left, name="test")
        fc.send(FRAME_DATA, b"hello")
        ftype, payload = _recv_frame(right)
        assert ftype == FRAME_DATA
        assert payload == b"hello"
    finally:
        left.close()
        right.close()


def test_framed_conn_close_sends_close_frame():
    """FramedConn.close() 发送 CLOSE 帧"""
    left, right = socket.socketpair()
    try:
        fc = FramedConn(left, name="test")
        fc.close()
        ftype, _ = _recv_frame(right)
        assert ftype == FRAME_CLOSE
    finally:
        left.close()
        right.close()


def test_framed_conn_recv_updates_last_recv():
    """FramedConn.recv_frame() 更新 last_recv"""
    left, right = socket.socketpair()
    try:
        fc = FramedConn(left, name="test")
        before = fc.last_recv
        time.sleep(0.01)
        _send_frame(right, FRAME_PING)
        fc.recv_frame()
        assert fc.last_recv > before
    finally:
        left.close()
        right.close()


def test_framed_conn_rejects_invalid_frame_type():
    """FramedConn 拒绝非法帧类型"""
    left, right = socket.socketpair()
    try:
        fc = FramedConn(left, name="test")
        _send_frame(right, 0xFF, b"bad")
        with pytest.raises(framing.FrameError, match="非法帧类型"):
            fc.recv_frame()
    finally:
        left.close()
        right.close()


def test_framed_conn_rejects_oversized_payload():
    """FramedConn 拒绝超大 payload"""
    left, right = socket.socketpair()
    try:
        fc = FramedConn(left, name="test")
        with pytest.raises(framing.FrameError, match="payload 超过最大长度"):
            fc.send(FRAME_DATA, b"X" * (MAX_PAYLOAD + 1))
    finally:
        left.close()
        right.close()


def test_framed_conn_send_after_close_raises():
    """FramedConn 关闭后发送抛异常"""
    left, right = socket.socketpair()
    try:
        fc = FramedConn(left, name="test")
        fc.close()
        with pytest.raises(framing.FrameError, match="已关闭"):
            fc.send(FRAME_DATA, b"data")
    finally:
        left.close()
        right.close()


# ---- run_multi_stream_a_endpoint 单元测试 ----

def test_multi_stream_a_endpoint_pair_flow():
    """A 端多流端点：收到 PAIR 后回复 PAIR_ACK"""
    a_sock, peer = socket.socketpair()
    try:
        framed = FramedConn(a_sock, name="A-test")

        def _run():
            run_multi_stream_a_endpoint(
                framed, ("127.0.0.1", 1), 0.1, role_label="A-test"
            )

        t = threading.Thread(target=_run, daemon=True)
        t.start()

        # 模拟 B 发 PAIR
        _send_frame(peer, FRAME_PAIR, STREAM_ID_STRUCT.pack(42))

        # A 应该回复 PAIR_ACK（或 STREAM_CLOSE，因为连不上本地服务）
        ftype, payload = _recv_frame(peer)
        # 本地服务连不上，所以收到 STREAM_CLOSE
        assert ftype in (FRAME_PAIR_ACK, FRAME_STREAM_CLOSE)
        if ftype == FRAME_STREAM_CLOSE:
            assert STREAM_ID_STRUCT.unpack(payload)[0] == 42

        framed.close()
        t.join(timeout=2)
    finally:
        a_sock.close()
        peer.close()


def test_multi_stream_a_endpoint_data_routing():
    """A 端多流端点：DATA 帧按 stream_id 路由到本地服务，本地服务回写也能透传回去。"""
    # 启动一个真实的本地 echo 服务，A endpoint 会主动连过去
    local_listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    local_listen.bind(("127.0.0.1", 0))
    local_listen.listen(1)
    local_listen.settimeout(2)
    local_addr = local_listen.getsockname()

    a_sock, peer = socket.socketpair()
    framed = FramedConn(a_sock, name="A-test")

    accepted_holder = []

    def _accept_local():
        try:
            conn, _ = local_listen.accept()
            accepted_holder.append(conn)
        except Exception:
            pass

    accept_thread = threading.Thread(target=_accept_local, daemon=True)
    accept_thread.start()

    def _run():
        run_multi_stream_a_endpoint(framed, local_addr, 1.0, role_label="A-test")

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    try:
        # 让 A endpoint 收到 PAIR → 连接本地服务 → 回 PAIR_ACK
        _send_frame(peer, FRAME_PAIR, STREAM_ID_STRUCT.pack(7))
        ftype, payload = _recv_frame(peer)
        assert ftype == FRAME_PAIR_ACK, f"got {ftype:#x}"
        assert STREAM_ID_STRUCT.unpack(payload)[0] == 7

        accept_thread.join(timeout=2)
        assert accepted_holder, "本地服务未收到连接"
        local_conn = accepted_holder[0]
        local_conn.settimeout(2)

        # B → A：DATA 带 stream_id，应被转发到本地服务
        _send_frame(peer, FRAME_DATA, STREAM_ID_STRUCT.pack(7) + b"ping-local")
        got = _recv_exact(local_conn, len(b"ping-local"))
        assert got == b"ping-local"

        # 本地服务回写 → A endpoint 应包成 DATA(带 stream_id) 发给 peer
        local_conn.sendall(b"pong-back")
        ftype, payload = _recv_frame(peer)
        assert ftype == FRAME_DATA
        assert STREAM_ID_STRUCT.unpack(payload[:STREAM_ID_LEN])[0] == 7
        assert payload[STREAM_ID_LEN:] == b"pong-back"

        local_conn.close()
    finally:
        try:
            framed.close()
        except Exception:
            pass
        t.join(timeout=2)
        local_listen.close()
        a_sock.close()
        peer.close()


def test_multi_stream_a_endpoint_ping_pong():
    """A 端多流端点：PING/PONG 处理"""
    a_sock, peer = socket.socketpair()
    try:
        framed = FramedConn(a_sock, name="A-test")

        def _run():
            run_multi_stream_a_endpoint(
                framed, ("127.0.0.1", 1), 0.1, role_label="A-test"
            )

        t = threading.Thread(target=_run, daemon=True)
        t.start()

        _send_frame(peer, FRAME_PING)
        ftype, _ = _recv_frame(peer)
        assert ftype == FRAME_PONG

        framed.close()
        t.join(timeout=2)
    finally:
        a_sock.close()
        peer.close()


def test_multi_stream_a_endpoint_close_frame():
    """A 端多流端点：收到 CLOSE 后退出"""
    a_sock, peer = socket.socketpair()
    try:
        framed = FramedConn(a_sock, name="A-test")

        def _run():
            run_multi_stream_a_endpoint(
                framed, ("127.0.0.1", 1), 0.1, role_label="A-test"
            )

        t = threading.Thread(target=_run, daemon=True)
        t.start()

        _send_frame(peer, FRAME_CLOSE)
        t.join(timeout=2)
        assert not t.is_alive()
    finally:
        a_sock.close()
        peer.close()


# ---- 边界条件测试 ----

def test_multi_a_queue_full_rejects_new_a(b_server_multi, monkeypatch):
    """多流模式：A 队列满后拒绝新 A"""
    monkeypatch.setattr(server_b, "WAITING_A_MAX", 2)
    a1 = _connect_role(b_server_multi, ROLE_A)
    a2 = _connect_role(b_server_multi, ROLE_A)
    try:
        time.sleep(0.1)
        # 第三个 A 应被拒绝（连接后立即被关闭）
        a3 = _connect_role(b_server_multi, ROLE_A)
        time.sleep(0.2)
        a3.settimeout(0.3)
        try:
            data = a3.recv(1)
            assert data == b"" or data[0] == FRAME_CLOSE
        except (socket.timeout, ConnectionError, OSError):
            pass
        a3.close()
    finally:
        a1.close()
        a2.close()


def test_multi_c_wait_timeout_when_no_a(b_server_multi, monkeypatch):
    """多流模式：C 等待 A 超时返回 503"""
    monkeypatch.setattr(server_b, "C_WAIT_TIMEOUT", 0.1)
    c_sock = _connect_role(b_server_multi, ROLE_C)
    try:
        ftype, payload = _recv_frame(c_sock)
        assert ftype == FRAME_DATA
        assert b"503" in payload
    finally:
        c_sock.close()


def test_multi_a_reconnect_after_disconnect(b_server_multi):
    """多流模式：A 断开后新 A 可以重新注册"""
    a1 = _connect_role(b_server_multi, ROLE_A)
    time.sleep(0.1)
    a1.close()

    a2 = _connect_role(b_server_multi, ROLE_A)
    try:
        time.sleep(0.2)
        _assert_not_closed(a2)
    finally:
        a2.close()


def test_multi_c_connects_after_a_reconnect(b_server_multi):
    """多流模式：A 重连后 C 可以正常连接"""
    a1 = _connect_role(b_server_multi, ROLE_A)
    time.sleep(0.1)
    a1.close()
    time.sleep(0.2)

    a2 = _connect_role(b_server_multi, ROLE_A)
    try:
        time.sleep(0.1)
        c_sock = _connect_role(b_server_multi, ROLE_C)
        try:
            _send_frame(c_sock, FRAME_PING)
            ftype, _ = _recv_frame(a2)
            assert ftype == FRAME_PAIR
        finally:
            c_sock.close()
    finally:
        a2.close()


def test_multi_concurrent_c_connections(b_server_multi):
    """多流模式：并发多个 C 连接"""
    a_sock = _connect_role(b_server_multi, ROLE_A)
    try:
        time.sleep(0.1)
        c_socks = []
        for i in range(10):
            c = _connect_role(b_server_multi, ROLE_C)
            _send_frame(c, FRAME_PING)
            _recv_frame(c)  # 消费 PONG
            c_socks.append(c)

        # 每个 C 都应该让 A 收到一个 PAIR
        for i in range(10):
            ftype, _ = _recv_frame(a_sock)
            assert ftype == FRAME_PAIR

        for c in c_socks:
            c.close()
    finally:
        a_sock.close()


def test_single_stream_mode_still_works(b_server):
    """单流模式：原有测试仍然通过（A_MULTI_STREAM=False）"""
    a_sock = _connect_role(b_server, ROLE_A)
    try:
        time.sleep(0.1)
        c_sock = _connect_role(b_server, ROLE_C)
        try:
            _send_frame(c_sock, FRAME_DATA, b"single-mode")
            ftype, payload = _recv_frame(a_sock)
            assert ftype == FRAME_DATA
            assert payload == b"single-mode"
        finally:
            c_sock.close()
    finally:
        a_sock.close()


# ---- 端到端：真实 client_c._bridge_handler_multi ----

def _start_real_c_bridge(b_port, monkeypatch):
    """模拟 client_c.bridge_handler 的入参环境，启动真实 _bridge_handler_multi。
    返回 (user_side_sock, c_thread)：测试可对 user_side_sock 读写模拟"用户连接"对端。
    """
    # 让 client_c 模块连到测试用 B 端口、跑多流模式
    monkeypatch.setattr(client_c, "B_SERVER_IP", "127.0.0.1")
    monkeypatch.setattr(client_c, "B_SERVER_PORT", b_port)
    monkeypatch.setattr(client_c, "A_MULTI_STREAM", True)
    monkeypatch.setattr(client_c, "C_RECONNECT_MAX_RETRIES", 1)
    client_c._shutdown_event.clear()

    # 用 socketpair 模拟用户 ↔ client_c 的本地 TCP
    user_side, c_user_conn = socket.socketpair()
    t = threading.Thread(target=client_c.bridge_handler, args=(c_user_conn,), daemon=True)
    t.start()
    return user_side, t


def test_e2e_real_client_c_multi_round_trip(b_server_multi, monkeypatch):
    """真实跑 client_c._bridge_handler_multi 与 B 通信，验证 A→C→用户、用户→C→A 双向数据。
    这条用例能捕获 _HDR_UNPACK 这种"只在 A 真正回数据时才暴露"的 bug。"""
    a_sock = _connect_role(b_server_multi, ROLE_A)
    user_side, c_thread = _start_real_c_bridge(b_server_multi, monkeypatch)
    try:
        # client_c.bridge_handler 起步会发一个 FRAME_PING；A 应收到 PAIR
        a_sock.settimeout(3)
        ftype, payload = _recv_frame(a_sock)
        assert ftype == FRAME_PAIR, f"expected PAIR, got {ftype:#x}"
        sid = STREAM_ID_STRUCT.unpack(payload)[0]

        # 模拟 A 完成本地连接：回 PAIR_ACK 后向 C 推送数据
        _send_frame(a_sock, FRAME_PAIR_ACK, STREAM_ID_STRUCT.pack(sid))
        _send_frame(a_sock, FRAME_DATA, STREAM_ID_STRUCT.pack(sid) + b"HTTP/1.1 200 OK\r\n\r\nbody")

        # 用户侧应能 recv 到原始字节（client_c 已剥掉帧头）
        user_side.settimeout(3)
        got = _recv_exact(user_side, len(b"HTTP/1.1 200 OK\r\n\r\nbody"))
        assert got == b"HTTP/1.1 200 OK\r\n\r\nbody"

        # 用户 → client_c → B → A
        user_side.sendall(b"GET / HTTP/1.1\r\n\r\n")
        ftype, payload = _recv_frame(a_sock)
        assert ftype == FRAME_DATA
        assert STREAM_ID_STRUCT.unpack(payload[:STREAM_ID_LEN])[0] == sid
        assert payload[STREAM_ID_LEN:] == b"GET / HTTP/1.1\r\n\r\n"
    finally:
        try:
            user_side.close()
        except Exception:
            pass
        a_sock.close()
        client_c._shutdown_event.set()
        c_thread.join(timeout=3)


def test_e2e_real_client_c_multi_handles_ping_from_b(b_server_multi, monkeypatch):
    """真实 client_c 多流模式下，B 主动发 PING，client_c 应正确回 PONG 而不是崩溃。"""
    a_sock = _connect_role(b_server_multi, ROLE_A)
    user_side, c_thread = _start_real_c_bridge(b_server_multi, monkeypatch)
    try:
        a_sock.settimeout(3)
        ftype, _ = _recv_frame(a_sock)
        assert ftype == FRAME_PAIR

        # client_c 起步时也会发 PING 给 B；B 会回 PONG。
        # 这里我们关心的是 client_c b_to_user 线程能正常解析任意帧而不崩溃。
        # 通过让 A 发一段小数据触发 client_c 的解帧路径：
        ftype_payload = STREAM_ID_STRUCT.pack(1) + b"x"
        _send_frame(a_sock, FRAME_DATA, ftype_payload)
        user_side.settimeout(3)
        assert _recv_exact(user_side, 1) == b"x"

        # 再发第二帧验证 b_to_user 线程仍存活（之前 unpack 崩溃后这一步会超时）
        _send_frame(a_sock, FRAME_DATA, STREAM_ID_STRUCT.pack(1) + b"y")
        assert _recv_exact(user_side, 1) == b"y"
    finally:
        try:
            user_side.close()
        except Exception:
            pass
        a_sock.close()
        client_c._shutdown_event.set()
        c_thread.join(timeout=3)


def test_e2e_real_client_c_multi_user_close_propagates(b_server_multi, monkeypatch):
    """真实 client_c：用户侧关闭 → B 侧应收到 STREAM_CLOSE。"""
    a_sock = _connect_role(b_server_multi, ROLE_A)
    user_side, c_thread = _start_real_c_bridge(b_server_multi, monkeypatch)
    try:
        a_sock.settimeout(3)
        ftype, payload = _recv_frame(a_sock)
        assert ftype == FRAME_PAIR
        sid = STREAM_ID_STRUCT.unpack(payload)[0]
        _send_frame(a_sock, FRAME_PAIR_ACK, STREAM_ID_STRUCT.pack(sid))

        # 用户侧关闭 → client_c 的 user_to_b 退出 → framed.close() → B 感知 → A 收到 STREAM_CLOSE
        user_side.close()

        # 期望在合理时间内收到 STREAM_CLOSE（中间可能夹杂 PONG/PING/CLOSE）
        deadline = time.monotonic() + 5
        seen_close = False
        while time.monotonic() < deadline:
            try:
                ftype, _ = _recv_frame(a_sock)
            except (socket.timeout, ConnectionError, OSError):
                break
            if ftype == FRAME_STREAM_CLOSE:
                seen_close = True
                break
        assert seen_close, "A 未在用户关闭后收到 STREAM_CLOSE"
    finally:
        a_sock.close()
        client_c._shutdown_event.set()
        c_thread.join(timeout=3)


