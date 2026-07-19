# -*- coding: utf-8 -*-
"""
pytest 全局前置：把项目根加入 sys.path，并在任何业务模块 import 之前注入
合规的测试密钥，避免链路层和端到端密钥校验在导入时抛错。
"""
import importlib.util
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

try:
    import config  # noqa: E402
except ModuleNotFoundError:
    spec = importlib.util.spec_from_file_location("config", _ROOT / "config_example.py")
    config = importlib.util.module_from_spec(spec)
    sys.modules["config"] = config
    spec.loader.exec_module(config)

# 两个用途不同的测试 PSK，避免测试掩盖密钥拆分错误。
TEST_B_AUTH_KEY = "pytest_b_auth_key_0123456789ABCDEF_xyz"
TEST_A_C_E2E_KEY = "pytest_a_c_e2e_key_0123456789ABCDEF_xyz"
config.B_AUTH_KEY = TEST_B_AUTH_KEY
config.A_C_E2E_KEY = TEST_A_C_E2E_KEY
