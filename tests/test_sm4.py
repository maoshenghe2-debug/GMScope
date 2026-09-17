"""SM4 实现测试：标准向量（含慢速）+ 模式往返 + 填充校验。"""

from __future__ import annotations

import pytest

from gmscope.crypto.sm4 import SM4, pkcs7_pad, pkcs7_unpad
from gmscope.crypto.vectors import SM4_SLOW_VECTORS, SM4_VECTORS

_KEY = bytes(range(16))
_IV = bytes(range(16, 32))


@pytest.mark.parametrize("v", SM4_VECTORS, ids=[v["name"] for v in SM4_VECTORS])
def test_standard_vectors(v):
    """GM/T 0002 附录 A 示例 1：单分组加解密。"""
    key = bytes.fromhex(v["key"])
    assert SM4(key).encrypt_block(bytes.fromhex(v["plain"])).hex() == v["cipher"]
    assert SM4(key).decrypt_block(bytes.fromhex(v["cipher"])).hex() == v["plain"]


@pytest.mark.slow
@pytest.mark.parametrize("v", SM4_SLOW_VECTORS, ids=[v["name"] for v in SM4_SLOW_VECTORS])
def test_slow_iterated_vector(v):
    """GM/T 0002 附录 A 示例 2：百万次迭代（-m slow 运行）。"""
    sm4 = SM4(bytes.fromhex(v["key"]))
    cur = bytes.fromhex(v["plain"])
    for _ in range(1_000_000):
        cur = sm4.encrypt_block(cur)
    assert cur.hex() == v["cipher"]


@pytest.mark.parametrize("n", [0, 1, 15, 16, 17, 31, 32, 100])
def test_ecb_roundtrip(n):
    data = (bytes(range(64)) * 3)[:n]
    c = SM4(_KEY)
    ct = c.encrypt_ecb(data)
    assert len(ct) % 16 == 0
    assert c.decrypt_ecb(ct) == data


def test_cbc_roundtrip_and_iv_effect():
    data = b"GMScope CBC test payload \xe4\xb8\xad\xe6\x96\x87" * 3
    c = SM4(_KEY)
    ct1 = c.encrypt_cbc(data, _IV)
    ct2 = c.encrypt_cbc(data, bytes([1]) * 16)
    assert ct1 != ct2  # IV 不同 → 密文不同
    assert c.decrypt_cbc(ct1, _IV) == data
    assert c.decrypt_cbc(ct2, bytes([1]) * 16) == data


def test_ctr_roundtrip_and_stream_property():
    data = b"GMScope CTR test payload " * 5
    c = SM4(_KEY)
    ct = c.crypt_ctr(data, _IV)
    assert len(ct) == len(data)
    assert c.crypt_ctr(ct, _IV) == data  # CTR 对称
    assert c.crypt_ctr(data, bytes([9]) * 16) != ct


def test_ctr_keystream_prefix_consistency():
    """流密码性质：前缀密文与截断一致。"""
    c = SM4(_KEY)
    long_ct = c.crypt_ctr(b"A" * 64, _IV)
    short_ct = c.crypt_ctr(b"A" * 33, _IV)
    assert short_ct == long_ct[:33]


def test_pkcs7_pad_unpad():
    assert pkcs7_unpad(pkcs7_pad(b"abc")) == b"abc"
    assert len(pkcs7_pad(b"x" * 16)) == 32  # 整块也要补一整块
    with pytest.raises(ValueError):
        pkcs7_unpad(b"")
    with pytest.raises(ValueError):
        pkcs7_unpad(b"\x01" * 15)  # 长度非整倍数
    with pytest.raises(ValueError):
        pkcs7_unpad(b"a" * 15 + b"\x11")  # 填充字节非法


def test_wrong_key_different_result():
    ct = SM4(bytes(16)).encrypt_ecb(b"secret data")
    out = SM4(bytes([1]) * 16).decrypt_ecb(ct, unpad=False)
    assert out != b"secret data"
