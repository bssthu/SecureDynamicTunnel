# -*- coding: utf-8 -*-
"""
真实端到端集成测试：在子进程里跑 server_b + client_a + client_c，
通过 client_c 的本地 HTTP 端口发请求，由 client_a 转发到一个本地
echo 服务，校验数据原样返回。

这是为了捕获之前那种"单元测试通过但联合运行就崩"的 bug
（例如 client_c 的 _HDR_UNPACK 误用、A_MULTI_STREAM 模式下的握手/转发问题）。
"""
import os
import socket
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _wait_port(port, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.2)
            s.close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


class _EchoServer:
    """简易 echo 服务，作为 client_a 后端的"本地服务"。
    收到的所有字节原样回写。"""
    def __init__(self):
        self._ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._ls.bind(("127.0.0.1", 0))
        self._ls.listen(8)
        self.port = self._ls.getsockname()[1]
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def _run(self):
        self._ls.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self._ls.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            while True:
                data = conn.recv(8192)
                if not data:
                    return
                conn.sendall(data)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def close(self):
        self._stop.set()
        try:
            self._ls.close()
        except Exception:
            pass


def _spawn_with_overrides(module_name, overrides):
    """以子进程方式运行 module_name (server_b/client_a/client_c)。
    overrides: dict of config 模块属性覆盖。
    用 -c "import config; config.X=...; runpy.run_module(...)" 实现。"""
    over_src = "\n".join(f"config.{k} = {v!r}" for k, v in overrides.items())
    code = textwrap.dedent(f"""
        import sys, runpy, config
{textwrap.indent(over_src, '        ')}
        runpy.run_module({module_name!r}, run_name='__main__')
    """)
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.Popen(
        [sys.executable, "-c", code],
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
    )
    return proc


def _drain_output(proc, sink):
    def _r():
        try:
            for line in proc.stdout:
                try:
                    sink.append(line.decode("utf-8", errors="replace").rstrip())
                except Exception:
                    pass
        except Exception:
            pass
    t = threading.Thread(target=_r, daemon=True)
    t.start()
    return t


def _kill(proc):
    if proc.poll() is None:
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except Exception:
                pass


def _do_request(c_port, payload, expect_bytes=None, timeout=5.0):
    s = socket.create_connection(("127.0.0.1", c_port), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(payload)
        expected = expect_bytes if expect_bytes is not None else len(payload)
        buf = bytearray()
        while len(buf) < expected:
            chunk = s.recv(expected - len(buf))
            if not chunk:
                break
            buf.extend(chunk)
        return bytes(buf)
    finally:
        try:
            s.close()
        except Exception:
            pass


@pytest.mark.parametrize("multi_stream", [False, True], ids=["single-stream", "multi-stream"])
def test_full_stack_round_trip(multi_stream):
    """端到端：用户 -> client_c -> server_b -> client_a -> echo 服务，再原路返回。"""
    echo = _EchoServer()
    b_port = _free_port()
    c_port = _free_port()

    common = {
        "B_LISTEN_HOST": "127.0.0.1",
        "B_LISTEN_PORT": b_port,
        "B_SERVER_IP": "127.0.0.1",
        "B_SERVER_PORT": b_port,
        "C_BIND_IP": "127.0.0.1",
        "C_LOCAL_LISTEN_PORT": c_port,
        "LOCAL_SERVICE_ADDR": ("127.0.0.1", echo.port),
        "A_MULTI_STREAM": multi_stream,
        "C_WAIT_TIMEOUT": 5,
        "A_CONNECT_TIMEOUT": 3,
        "C_CONNECT_TIMEOUT": 3,
        "A_RECONNECT_INTERVAL": 0.2,
        "C_RECONNECT_INTERVAL": 0.2,
        "A_RECONNECT_MAX_RETRIES": 0,
        "C_RECONNECT_MAX_RETRIES": 0,
        "HEARTBEAT_ENABLED": True,
        "HEARTBEAT_INTERVAL": 30,
        "HEARTBEAT_TIMEOUT": 60,
        "A_WORKERS": 1 if multi_stream else 4,
    }

    b_log = []
    a_log = []
    c_log = []
    b_proc = a_proc = c_proc = None
    try:
        b_proc = _spawn_with_overrides("server_b", common)
        _drain_output(b_proc, b_log)
        assert _wait_port(b_port, 5), f"B 未启动: {b_log[-20:]}"

        a_proc = _spawn_with_overrides("client_a", common)
        _drain_output(a_proc, a_log)

        c_proc = _spawn_with_overrides("client_c", common)
        _drain_output(c_proc, c_log)
        assert _wait_port(c_port, 5), f"C 未启动: {c_log[-20:]}"

        # 给 A 时间挂机到 B
        time.sleep(1.0)

        # 单次 round trip
        got = _do_request(c_port, b"HELLO-WORLD-1234567890")
        assert got == b"HELLO-WORLD-1234567890", (
            f"got={got!r}\nB:\n{chr(10).join(b_log[-20:])}\n"
            f"A:\n{chr(10).join(a_log[-20:])}\nC:\n{chr(10).join(c_log[-20:])}"
        )

        # 较大 payload
        big = b"X" * 50000
        got = _do_request(c_port, big, timeout=10)
        assert got == big, "大 payload 不完整"

        # 多次连续请求（每次新 TCP，验证多 stream 复用 / 单流多次重建）
        for i in range(5):
            msg = f"REQ-{i:03d}".encode()
            got = _do_request(c_port, msg)
            assert got == msg, f"第 {i} 次 round trip 失败: got={got!r}"
    finally:
        for p in (c_proc, a_proc, b_proc):
            if p is not None:
                _kill(p)
        echo.close()


def test_full_stack_concurrent_clients_multi_stream():
    """多流模式：5 个并发 C 用户连接同时跑，全部成功。"""
    echo = _EchoServer()
    b_port = _free_port()
    c_port = _free_port()

    common = {
        "B_LISTEN_HOST": "127.0.0.1",
        "B_LISTEN_PORT": b_port,
        "B_SERVER_IP": "127.0.0.1",
        "B_SERVER_PORT": b_port,
        "C_BIND_IP": "127.0.0.1",
        "C_LOCAL_LISTEN_PORT": c_port,
        "C_LISTEN_BACKLOG": 32,
        "LOCAL_SERVICE_ADDR": ("127.0.0.1", echo.port),
        "A_MULTI_STREAM": True,
        "C_WAIT_TIMEOUT": 5,
        "A_CONNECT_TIMEOUT": 3,
        "C_CONNECT_TIMEOUT": 3,
        "A_RECONNECT_INTERVAL": 0.2,
        "C_RECONNECT_INTERVAL": 0.2,
        "A_RECONNECT_MAX_RETRIES": 0,
        "C_RECONNECT_MAX_RETRIES": 0,
        "HEARTBEAT_ENABLED": True,
        "HEARTBEAT_INTERVAL": 30,
        "HEARTBEAT_TIMEOUT": 60,
        "A_WORKERS": 1,
    }
    b_log = []; a_log = []; c_log = []
    b_proc = a_proc = c_proc = None
    try:
        b_proc = _spawn_with_overrides("server_b", common)
        _drain_output(b_proc, b_log)
        assert _wait_port(b_port, 5)
        a_proc = _spawn_with_overrides("client_a", common)
        _drain_output(a_proc, a_log)
        c_proc = _spawn_with_overrides("client_c", common)
        _drain_output(c_proc, c_log)
        assert _wait_port(c_port, 5)
        time.sleep(1.0)

        results = {}
        errors = []
        def _worker(i):
            try:
                msg = f"CONCURRENT-CLIENT-{i:03d}".encode() * 50
                got = _do_request(c_port, msg, timeout=10)
                results[i] = (got == msg, len(got))
            except Exception as e:
                errors.append((i, repr(e)))

        threads = [threading.Thread(target=_worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

        assert not errors, (
            f"errors={errors}\nB:\n{chr(10).join(b_log[-30:])}\n"
            f"A:\n{chr(10).join(a_log[-30:])}\nC:\n{chr(10).join(c_log[-30:])}"
        )
        assert all(ok for ok, _ in results.values()), (
            f"results={results}\nA:\n{chr(10).join(a_log[-30:])}\n"
            f"C:\n{chr(10).join(c_log[-30:])}"
        )
        assert len(results) == 5
    finally:
        for p in (c_proc, a_proc, b_proc):
            if p is not None:
                _kill(p)
        echo.close()




# ---- ģ���û����������ϵ��ò������� / ���˳������ / ����������� ----

class _SlowEcho:
    def __init__(self):
        self._ls = socket.socket()
        self._ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._ls.bind(('127.0.0.1', 0))
        self._ls.listen(8)
        self.port = self._ls.getsockname()[1]
        self._stop = threading.Event()
        self.accepted = 0
        threading.Thread(target=self._run, daemon=True).start()
    def _run(self):
        self._ls.settimeout(0.2)
        while not self._stop.is_set():
            try:
                c, _ = self._ls.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.accepted += 1
            threading.Thread(target=self._h, args=(c,), daemon=True).start()
    def _h(self, c):
        try:
            c.settimeout(5)
            data = c.recv(8192)
            if data:
                c.sendall(b'OK:' + data)
        finally:
            try: c.close()
            except: pass
    def close(self):
        self._stop.set()
        try: self._ls.close()
        except: pass


def _spawn_stack(echo_port, multi):
    b_port = _free_port()
    c_port = _free_port()
    common = {
        'B_LISTEN_HOST': '127.0.0.1', 'B_LISTEN_PORT': b_port,
        'B_SERVER_IP': '127.0.0.1', 'B_SERVER_PORT': b_port,
        'C_BIND_IP': '127.0.0.1', 'C_LOCAL_LISTEN_PORT': c_port,
        'C_LISTEN_BACKLOG': 32,
        'LOCAL_SERVICE_ADDR': ('127.0.0.1', echo_port),
        'A_MULTI_STREAM': multi, 'C_WAIT_TIMEOUT': 5,
        'A_CONNECT_TIMEOUT': 3, 'C_CONNECT_TIMEOUT': 3,
        'A_RECONNECT_INTERVAL': 0.2, 'C_RECONNECT_INTERVAL': 0.2,
        'A_RECONNECT_MAX_RETRIES': 0, 'C_RECONNECT_MAX_RETRIES': 0,
        'HEARTBEAT_ENABLED': True, 'HEARTBEAT_INTERVAL': 30, 'HEARTBEAT_TIMEOUT': 60,
        'A_WORKERS': 1 if multi else 4,
    }
    b_log = []; a_log = []; c_log = []
    b = _spawn_with_overrides('server_b', common); _drain_output(b, b_log)
    assert _wait_port(b_port, 5)
    a = _spawn_with_overrides('client_a', common); _drain_output(a, a_log)
    c = _spawn_with_overrides('client_c', common); _drain_output(c, c_log)
    assert _wait_port(c_port, 5)
    time.sleep(1.0)
    return c_port, (b, a, c), (b_log, a_log, c_log)


@pytest.mark.parametrize('multi', [False, True], ids=['single', 'multi'])
def test_local_service_closes_after_response(multi):
    echo = _SlowEcho()
    c_port, procs, logs = _spawn_stack(echo.port, multi)
    try:
        for i in range(3):
            payload = f'REQ-{i}'.encode()
            got = _do_request(c_port, payload, expect_bytes=len(b'OK:') + len(payload), timeout=10)
            assert got == b'OK:' + payload, (
                f'i={i} got={got!r} accepted={echo.accepted}\n'
                f'B:\n' + '\n'.join(logs[0][-40:]) + f'\nA:\n' + '\n'.join(logs[1][-40:]) +
                f'\nC:\n' + '\n'.join(logs[2][-40:])
            )
        assert echo.accepted >= 3
    finally:
        for p in procs: _kill(p)
        echo.close()


@pytest.mark.parametrize('multi', [False, True], ids=['single', 'multi'])
def test_user_connects_but_idle_then_sends(multi):
    echo = _SlowEcho()
    c_port, procs, logs = _spawn_stack(echo.port, multi)
    try:
        s = socket.create_connection(('127.0.0.1', c_port), timeout=5)
        s.settimeout(10)
        time.sleep(3)
        s.sendall(b'PING')
        buf = b''
        while len(buf) < 7:
            chunk = s.recv(7 - len(buf))
            if not chunk: break
            buf += chunk
        assert buf == b'OK:PING', (
            f'got={buf!r}\nB:\n' + '\n'.join(logs[0][-40:]) +
            f'\nA:\n' + '\n'.join(logs[1][-40:]) + f'\nC:\n' + '\n'.join(logs[2][-40:])
        )
        s.close()
    finally:
        for p in procs: _kill(p)
        echo.close()


def test_multi_stream_sequential_after_close():
    echo = _SlowEcho()
    c_port, procs, logs = _spawn_stack(echo.port, multi=True)
    try:
        for i in range(5):
            payload = f'R-{i}'.encode()
            got = _do_request(c_port, payload, expect_bytes=len(b'OK:') + len(payload), timeout=10)
            assert got == b'OK:' + payload, (
                f'round {i} got={got!r}\n'
                f'B:\n' + '\n'.join(logs[0][-50:]) +
                f'\nA:\n' + '\n'.join(logs[1][-50:]) +
                f'\nC:\n' + '\n'.join(logs[2][-50:])
            )
            time.sleep(0.3)
    finally:
        for p in procs: _kill(p)
        echo.close()
