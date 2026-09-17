"""SM3 密码杂凑算法（GM/T 0004-2012）纯 Python 参考实现。

依据：GB/T 32905-2016 / GM/T 0004-2012《SM3 密码杂凑算法》。

本实现为 **教学对照实现**：正确性由标准测试向量与 ``gmssl`` 交叉验证保证，
GMScope 主链路使用成熟库实现。附带 HMAC-SM3（RFC 2104 结构，杂凑函数为 SM3）。
"""

from __future__ import annotations

__all__ = ["hmac_sm3", "sm3_hash", "sm3_hex"]

# 初始值 IV（GB/T 32905 第 4.1 节）
_IV = (
    0x7380166F,
    0x4914B2B9,
    0x172442D7,
    0xDA8A0600,
    0xA96F30BC,
    0x163138AA,
    0xE38DEE4D,
    0xB0FB0E4E,
)

_MASK32 = 0xFFFFFFFF


def _rotl(x: int, n: int) -> int:
    """32 位循环左移。"""
    n &= 31
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _p0(x: int) -> int:
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)


def _p1(x: int) -> int:
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)


def _ff(j: int, x: int, y: int, z: int) -> int:
    if j < 16:
        return x ^ y ^ z
    return (x & y) | (x & z) | (y & z)


def _gg(j: int, x: int, y: int, z: int) -> int:
    if j < 16:
        return x ^ y ^ z
    return (x & y) | ((~x & _MASK32) & z)


def _compress(v: tuple, block: bytes) -> tuple:
    """压缩函数 CF：对单分组（64 字节）做迭代压缩。"""
    w = [int.from_bytes(block[i * 4 : i * 4 + 4], "big") for i in range(16)]
    for j in range(16, 68):
        w.append(_p1(w[j - 16] ^ w[j - 9] ^ _rotl(w[j - 3], 15)) ^ _rotl(w[j - 13], 7) ^ w[j - 6])
    wp = [w[j] ^ w[j + 4] for j in range(64)]

    a, b, c, d, e, f, g, h = v
    for j in range(64):
        t = 0x79CC4519 if j < 16 else 0x7A879D8A
        ss1 = _rotl((_rotl(a, 12) + e + _rotl(t, j)) & _MASK32, 7)
        ss2 = ss1 ^ _rotl(a, 12)
        tt1 = (_ff(j, a, b, c) + d + ss2 + wp[j]) & _MASK32
        tt2 = (_gg(j, e, f, g) + h + ss1 + w[j]) & _MASK32
        d = c
        c = _rotl(b, 9)
        b = a
        a = tt1
        h = g
        g = _rotl(f, 19)
        f = e
        e = _p0(tt2)
    return tuple(x ^ y for x, y in zip(v, (a, b, c, d, e, f, g, h)))


def _pad(data: bytes) -> bytes:
    """消息填充：1 比特 + 若干 0 + 64 比特长度（大端，比特数）。"""
    bit_len = len(data) * 8
    return data + b"\x80" + b"\x00" * ((55 - len(data)) % 64) + bit_len.to_bytes(8, "big")


def sm3_hash(data: bytes | bytearray) -> bytes:
    """计算 SM3 杂凑值，返回 32 字节 bytes。"""
    msg = _pad(bytes(data))
    v = _IV
    for i in range(0, len(msg), 64):
        v = _compress(v, msg[i : i + 64])
    return b"".join(x.to_bytes(4, "big") for x in v)


def sm3_hex(data: bytes | bytearray) -> str:
    """计算 SM3 杂凑值，返回 64 位十六进制字符串（小写）。"""
    return sm3_hash(data).hex()


def hmac_sm3(key: bytes, msg: bytes) -> bytes:
    """HMAC-SM3（RFC 2104 结构）。返回 32 字节。"""
    block_size = 64
    if len(key) > block_size:
        key = sm3_hash(key)
    key = key.ljust(block_size, b"\x00")
    o_key_pad = bytes(b ^ 0x5C for b in key)
    i_key_pad = bytes(b ^ 0x36 for b in key)
    return sm3_hash(o_key_pad + sm3_hash(i_key_pad + msg))
