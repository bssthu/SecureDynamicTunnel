# -*- coding: utf-8 -*-

import hmac
import hashlib
import time

# [重要] 请在三台机器上保持此 Key 一致
SHARED_KEY = "Your_Super_Strong_Random_Secret_Key_2026" 

def generate_token(role):
    """基于当前分钟生成动态 HMAC Token"""
    timestamp = str(int(time.time() / 60)).encode()
    message = role.encode() + b"@" + timestamp
    return hmac.new(SHARED_KEY.encode(), message, hashlib.sha256).digest()

def verify_token(role, received_token):
    """校验 Token，允许 1 分钟内的误差以防时钟偏移"""
    t_now = int(time.time() / 60)
    for t in [t_now, t_now - 1]:
        expected = hmac.new(SHARED_KEY.encode(), role.encode() + b"@" + str(t).encode(), hashlib.sha256).digest()
        if hmac.compare_digest(expected, received_token):
            return True
    return False
