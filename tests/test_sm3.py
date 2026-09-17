"""SM3 实现测试：标准向量 + 填充边界 + HMAC 结构。"""

from __future__ import annotations

import pytest

from gmscope.crypto.sm3 import hmac_sm3, sm3_hash, sm3_hex
from gmscope.crypto.vectors import SM3_VECTORS


@pytest.mark.parametrize("v", SM3_VECTORS, ids=[v["name"] for v in SM3_VECTORS])
def test_standard_vectors(v):
    """GM/T 0004 附录 A 标准向量。"""
    assert sm3_hex(v["input"]) == v["digest"]


def test_digest_length_and_determinism():
    h1 = sm3_hash(b"GMScope")
    assert len(h1) == 32
    assert h1 == sm3_hash(b"GMScope")
    assert sm3_hash(b"GMScope") != sm3_hash(b"GMScopE")


@pytest.mark.parametrize("n", [0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 1000])
def test_padding_boundaries_stable(n):
    """填充边界长度：输出长度稳定、结果确定。"""
    data = b"\xa5" * n
    d1 = sm3_hash(data)
    assert len(d1) == 32
    assert d1 == sm3_hash(data)


def test_hmac_sm3_structure():
    mac = hmac_sm3(b"key", b"message")
    assert len(mac) == 32
    assert mac == hmac_sm3(b"key", b"message")
    assert mac != hmac_sm3(b"key2", b"message")
    assert mac != hmac_sm3(b"key", b"message2")


def test_hmac_sm3_long_key_hashed_first():
    """长于分组的密钥应先做 SM3 再参与 HMAC。"""
    long_key = b"k" * 100
    assert hmac_sm3(long_key, b"m") == hmac_sm3(sm3_hash(long_key), b"m")
