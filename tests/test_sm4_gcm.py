"""SM4-GCM 测试：KAT（含 12/16 字节 IV 两条路径）/ 往返 / 篡改与绑定校验。"""

from __future__ import annotations

import pytest

from gmscope.crypto.sm4 import SM4, SM4GCMError
from gmscope.kat_data import KAT


class TestKAT:
    """冻结 KAT：向量由 cryptography（OpenSSL）计算，本库实现比对一致后收录。"""

    def test_kat_iv12(self):
        k = KAT["SM4_GCM"]
        sm4 = SM4(bytes.fromhex(k["key"]))
        ct, tag = sm4.encrypt_gcm(bytes.fromhex(k["plaintext"]), bytes.fromhex(k["iv"]), bytes.fromhex(k["aad"]))
        assert ct.hex() == k["ciphertext"]
        assert tag.hex() == k["tag"]
        assert sm4.decrypt_gcm(ct, tag, bytes.fromhex(k["iv"]), bytes.fromhex(k["aad"])).hex() == k["plaintext"]

    def test_kat_iv16_ghash_path(self):
        k = KAT["SM4_GCM"]
        sm4 = SM4(bytes.fromhex(k["key"]))
        ct, tag = sm4.encrypt_gcm(bytes.fromhex(k["plaintext"]), bytes.fromhex(k["iv16"]), bytes.fromhex(k["aad"]))
        assert ct.hex() == k["ciphertext_iv16"]
        assert tag.hex() == k["tag_iv16"]


class TestGCM:
    def test_roundtrip_various_sizes(self):
        sm4 = SM4(bytes(16))
        for n in (0, 1, 15, 16, 17, 33, 128):
            msg = bytes(range(n))
            ct, tag = sm4.encrypt_gcm(msg, bytes(12), b"")
            assert sm4.decrypt_gcm(ct, tag, bytes(12), b"") == msg

    def test_roundtrip_with_aad(self):
        sm4 = SM4(bytes(16))
        msg = "GMScope GCM 往返 · 中文载荷".encode()
        ct, tag = sm4.encrypt_gcm(msg, bytes(16), b"header-v1")
        assert sm4.decrypt_gcm(ct, tag, bytes(16), b"header-v1") == msg

    def test_tag_tamper_rejected(self):
        sm4 = SM4(bytes(16))
        ct, tag = sm4.encrypt_gcm(b"data", bytes(12))
        with pytest.raises(SM4GCMError):
            sm4.decrypt_gcm(ct, bytes(16), bytes(12))
        bad = bytearray(tag)
        bad[0] ^= 1
        with pytest.raises(SM4GCMError):
            sm4.decrypt_gcm(ct, bytes(bad), bytes(12))

    def test_aad_and_ciphertext_binding(self):
        sm4 = SM4(bytes(16))
        ct, tag = sm4.encrypt_gcm(b"data", bytes(12), b"aad-a")
        with pytest.raises(SM4GCMError):
            sm4.decrypt_gcm(ct, tag, bytes(12), b"aad-b")
        ct_bad = bytearray(ct)
        ct_bad[0] ^= 1
        with pytest.raises(SM4GCMError):
            sm4.decrypt_gcm(bytes(ct_bad), tag, bytes(12), b"aad-a")

    def test_wrong_tag_length_rejected(self):
        sm4 = SM4(bytes(16))
        with pytest.raises(SM4GCMError):
            sm4.decrypt_gcm(b"x", b"", bytes(12))
