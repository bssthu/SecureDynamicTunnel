# -*- coding: utf-8 -*-
"""
pytest 全局前置：把项目根加入 sys.path，并在任何业务模块 import 之前注入
一个合规的测试 SHARED_KEY，避免 crypto.validate_shared_key 抛错。
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import config  # noqa: E402

# 测试专用 PSK：长度 > 32 字符，且不属于 _FORBIDDEN_DEFAULT_KEYS。
TEST_SHARED_KEY = "pytest_only_strong_key_0123456789ABCDEF_xyz"
config.SHARED_KEY = TEST_SHARED_KEY
