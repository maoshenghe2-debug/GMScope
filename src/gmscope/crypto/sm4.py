"""SM4 分组密码算法（GM/T 0002-2012）纯 Python 参考实现。

依据：GB/T 32907-2016 / GM/T 0002-2012《SM4 分组密码算法》。

支持模式：ECB / CBC / CTR（配合 PKCS#7 填充；CTR 为流式对称加解密）。
模式说明：ECB 仅为标准向量符合性验证所需（GM/T 0002 附录示例即采用 ECB）；
ECB 会泄露明文结构，**实际数据保护应使用 CBC/CTR**（后续版本补充 GCM）。
本实现为 **教学对照实现**：正确性由标准测试向量与 ``gmssl`` / ``cryptography``
交叉验证保证，GMScope 主链路使用成熟库实现。
"""

from __future__ import annotations

__all__ = ["SM4", "pkcs7_pad", "pkcs7_unpad"]

# 系统参数 FK（GB/T 32907 第 5.3 节）
_FK = (0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC)

# S 盒（GB/T 32907 第 5.2 节）
_SBOX = (
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48,
)

_MASK32 = 0xFFFFFFFF
_BLOCK = 16


def _rotl(x: int, n: int) -> int:
    n &= 31
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _ck(i: int) -> int:
    """固定参数 CK：ck_{i,j} = (4i + j) × 7 mod 256。"""
    b = [(28 * i + k * 7) % 256 for k in range(4)]
    return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]


def _tau(x: int) -> int:
    """非线性变换 τ：S 盒逐字节替换。"""
    return (
        (_SBOX[(x >> 24) & 0xFF] << 24)
        | (_SBOX[(x >> 16) & 0xFF] << 16)
        | (_SBOX[(x >> 8) & 0xFF] << 8)
        | _SBOX[x & 0xFF]
    )


def _l(b: int) -> int:
    return b ^ _rotl(b, 2) ^ _rotl(b, 10) ^ _rotl(b, 18) ^ _rotl(b, 24)


def _lp(b: int) -> int:
    return b ^ _rotl(b, 13) ^ _rotl(b, 23)


def _t(x: int) -> int:
    return _l(_tau(x))


def _tp(x: int) -> int:
    return _lp(_tau(x))


def _key_schedule(key: bytes) -> list:
    """密钥扩展：由 128 位密钥生成 32 个轮密钥。"""
    k = [int.from_bytes(key[i * 4 : i * 4 + 4], "big") ^ _FK[i] for i in range(4)]
    rk = []
    for i in range(32):
        k.append(k[i] ^ _tp(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ _ck(i)))
        rk.append(k[-1])
    return rk


def _crypt_block(rk: list, block: bytes) -> bytes:
    """通用分组变换（加密/解密共用，仅轮密钥顺序不同）。"""
    x = [int.from_bytes(block[i * 4 : i * 4 + 4], "big") for i in range(4)]
    for i in range(32):
        x.append(x[i] ^ _t(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i]))
    return b"".join(x[i].to_bytes(4, "big") for i in (35, 34, 33, 32))


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def pkcs7_pad(data: bytes, block_size: int = _BLOCK) -> bytes:
    """PKCS#7 填充。"""
    n = block_size - len(data) % block_size
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes, block_size: int = _BLOCK) -> bytes:
    """PKCS#7 去填充；填充非法时抛出 ValueError。"""
    if not data or len(data) % block_size:
        raise ValueError("无效的 PKCS#7 填充：数据长度不是分组长度的整数倍")
    n = data[-1]
    if not 1 <= n <= block_size or data[-n:] != bytes([n]) * n:
        raise ValueError("无效的 PKCS#7 填充：填充字节校验失败")
    return data[:-n]


class SM4:
    """SM4 分组密码（ECB / CBC / CTR）。"""

    block_size = _BLOCK
    key_size = 16

    def __init__(self, key: bytes):
        if len(key) != self.key_size:
            raise ValueError("SM4 密钥必须为 16 字节")
        self._rk = _key_schedule(key)
        self._rk_dec = self._rk[::-1]

    # ---- 单分组 ----
    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != _BLOCK:
            raise ValueError("SM4 分组必须为 16 字节")
        return _crypt_block(self._rk, block)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != _BLOCK:
            raise ValueError("SM4 分组必须为 16 字节")
        return _crypt_block(self._rk_dec, block)

    # ---- ECB ----
    def encrypt_ecb(self, data: bytes, pad: bool = True) -> bytes:
        if pad:
            data = pkcs7_pad(data)
        if len(data) % _BLOCK:
            raise ValueError("ECB 数据长度必须为 16 字节的整数倍")
        return b"".join(self.encrypt_block(data[i : i + _BLOCK]) for i in range(0, len(data), _BLOCK))

    def decrypt_ecb(self, data: bytes, unpad: bool = True) -> bytes:
        if not data or len(data) % _BLOCK:
            raise ValueError("ECB 数据长度必须为非零的 16 字节整数倍")
        out = b"".join(self.decrypt_block(data[i : i + _BLOCK]) for i in range(0, len(data), _BLOCK))
        return pkcs7_unpad(out) if unpad else out

    # ---- CBC ----
    def encrypt_cbc(self, data: bytes, iv: bytes, pad: bool = True) -> bytes:
        if len(iv) != _BLOCK:
            raise ValueError("CBC IV 必须为 16 字节")
        if pad:
            data = pkcs7_pad(data)
        if len(data) % _BLOCK:
            raise ValueError("CBC 数据长度必须为 16 字节的整数倍")
        out = bytearray()
        prev = iv
        for i in range(0, len(data), _BLOCK):
            prev = self.encrypt_block(_xor(data[i : i + _BLOCK], prev))
            out += prev
        return bytes(out)

    def decrypt_cbc(self, data: bytes, iv: bytes, unpad: bool = True) -> bytes:
        if len(iv) != _BLOCK:
            raise ValueError("CBC IV 必须为 16 字节")
        if not data or len(data) % _BLOCK:
            raise ValueError("CBC 数据长度必须为非零的 16 字节整数倍")
        out = bytearray()
        prev = iv
        for i in range(0, len(data), _BLOCK):
            chunk = data[i : i + _BLOCK]
            out += _xor(self.decrypt_block(chunk), prev)
            prev = chunk
        result = bytes(out)
        return pkcs7_unpad(result) if unpad else result

    # ---- CTR（流式，对称） ----
    def crypt_ctr(self, data: bytes, iv: bytes) -> bytes:
        if len(iv) != _BLOCK:
            raise ValueError("CTR 计数器初值必须为 16 字节")
        out = bytearray()
        counter = int.from_bytes(iv, "big")
        for i in range(0, len(data), _BLOCK):
            key_stream = self.encrypt_block(counter.to_bytes(_BLOCK, "big"))
            chunk = data[i : i + _BLOCK]
            out += _xor(chunk, key_stream[: len(chunk)])
            counter = (counter + 1) % (1 << 128)
        return bytes(out)
