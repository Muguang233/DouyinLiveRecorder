# -*- coding: utf-8 -*-
"""
TOTP (RFC 6238) 动态码工具, 兼容 Microsoft Authenticator / Google Authenticator.

纯标准库实现, 不依赖第三方库。
"""
import base64
import hashlib
import hmac
import os
import struct
import time
from urllib.parse import quote

DEFAULT_DIGITS = 6
DEFAULT_PERIOD = 30


def generate_secret(length: int = 20) -> str:
    """生成随机的 base32 密钥(无填充), 可直接用于 Microsoft Authenticator。"""
    raw = os.urandom(length)
    return base64.b32encode(raw).decode('ascii').rstrip('=')


def _decode_secret(secret: str) -> bytes:
    secret = secret.strip().replace(' ', '').upper()
    padding = '=' * ((8 - len(secret) % 8) % 8)
    return base64.b32decode(secret + padding)


def hotp(secret: str, counter: int, digits: int = DEFAULT_DIGITS) -> str:
    key = _decode_secret(secret)
    msg = struct.pack('>Q', counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = (
        ((digest[offset] & 0x7F) << 24)
        | ((digest[offset + 1] & 0xFF) << 16)
        | ((digest[offset + 2] & 0xFF) << 8)
        | (digest[offset + 3] & 0xFF)
    )
    return str(binary % (10 ** digits)).zfill(digits)


def totp(secret: str, timestamp: float | None = None,
         period: int = DEFAULT_PERIOD, digits: int = DEFAULT_DIGITS) -> str:
    if timestamp is None:
        timestamp = time.time()
    counter = int(timestamp) // period
    return hotp(secret, counter, digits)


def verify(secret: str, code: str, window: int = 1,
           period: int = DEFAULT_PERIOD, digits: int = DEFAULT_DIGITS) -> bool:
    """校验动态码, 允许前后各 window 个时间步的偏差。"""
    code = (code or '').strip()
    if not code.isdigit():
        return False
    counter = int(time.time()) // period
    for offset in range(-window, window + 1):
        if hmac.compare_digest(hotp(secret, counter + offset, digits), code):
            return True
    return False


def provisioning_uri(secret: str, account: str, issuer: str,
                     period: int = DEFAULT_PERIOD, digits: int = DEFAULT_DIGITS) -> str:
    """生成 otpauth:// 供应 URI, 可用手机扫码添加到 Authenticator。"""
    label = quote(f'{issuer}:{account}')
    params = (
        f'secret={secret}'
        f'&issuer={quote(issuer)}'
        f'&algorithm=SHA1'
        f'&digits={digits}'
        f'&period={period}'
    )
    return f'otpauth://totp/{label}?{params}'
