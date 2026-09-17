"""SM2 封装测试：KAT（冻结向量）/ 往返 / 篡改 / DER 编解码 / OpenSSL 互操作。"""

from __future__ import annotations

import re
import shutil
import subprocess

import pytest

from gmscope.crypto.sm2 import SM2, SM2Error, decode_signature_der, encode_signature_der
from gmscope.kat_data import KAT

_OPENSSL = shutil.which("openssl")


class TestKAT:
    """冻结 KAT：密钥由 OpenSSL 生成，签名经 gmssl 与 OpenSSL 双重校验。"""

    def test_kat_deterministic_signature(self):
        k = KAT["SM2_SIGN"]
        rig = SM2(private_key=k["private_key"], public_key=k["public_key"])
        sig = rig.sign(bytes.fromhex(k["message_hex"]), k=k["k"])
        assert sig == k["signature"]

    def test_kat_verify(self):
        k = KAT["SM2_SIGN"]
        rig = SM2(public_key=k["public_key"])
        assert rig.verify(k["signature"], bytes.fromhex(k["message_hex"]))

    def test_kat_public_derive(self):
        k = KAT["SM2_SIGN"]
        assert SM2.derive_public(k["private_key"]) == k["public_key"]


class TestRoundtrip:
    def test_sign_verify(self):
        kp = SM2.generate()
        msg = "GMScope SM2 往返测试 · 中文消息".encode()
        sig = kp.sign(msg)
        assert kp.verify(sig, msg)
        assert not kp.verify(sig, msg + b"!")

    def test_custom_uid_changes_digest(self):
        kp = SM2.generate()
        msg = b"uid-scoped-message"
        sig = kp.sign(msg, uid=b"custom-uid-123")
        assert kp.verify(sig, msg, uid=b"custom-uid-123")
        assert not kp.verify(sig, msg)  # 默认 UID 下验签必须失败

    def test_verify_rejects_tampered_signature(self):
        kp = SM2.generate()
        msg = b"payload"
        sig = kp.sign(msg)
        bad = ("0" if sig[0] != "0" else "1") + sig[1:]
        assert not kp.verify(bad, msg)

    def test_encrypt_decrypt_roundtrip(self):
        kp = SM2.generate()
        for msg in (b"a", b"x" * 16, b"y" * 255, "国密加密往返测试".encode()):
            assert kp.decrypt(kp.encrypt(msg)) == msg

    def test_empty_message_encrypt_rejected(self):
        kp = SM2.generate()
        with pytest.raises(SM2Error):
            kp.encrypt(b"")

    def test_decrypt_detects_c2_and_c3_tamper(self):
        kp = SM2.generate()
        ct = bytearray(kp.encrypt(b"integrity-check"))
        c2_bad = bytearray(ct)
        c2_bad[-1] ^= 1
        with pytest.raises(SM2Error):
            kp.decrypt(bytes(c2_bad))
        c3_bad = bytearray(ct)
        c3_bad[64] ^= 1
        with pytest.raises(SM2Error):
            kp.decrypt(bytes(c3_bad))

    def test_wrong_key_cannot_decrypt(self):
        kp1, kp2 = SM2.generate(), SM2.generate()
        with pytest.raises(SM2Error):
            kp2.decrypt(kp1.encrypt(b"secret-for-kp1"))


class TestDER:
    def test_der_roundtrip(self):
        kp = SM2.generate()
        sig = kp.sign(b"der-roundtrip")
        der = encode_signature_der(int(sig[:64], 16), int(sig[64:], 16))
        assert decode_signature_der(der) == (int(sig[:64], 16), int(sig[64:], 16))

    def test_der_high_bit_padding(self):
        der = encode_signature_der(int("ff" * 32, 16), 1)
        assert decode_signature_der(der) == (int("ff" * 32, 16), 1)


@pytest.mark.skipif(_OPENSSL is None, reason="本机无 openssl")
class TestOpenSSLInterop:
    """与 OpenSSL 的双向互操作。注意：OpenSSL 的 SM2 默认用户标识为空串，
    必须显式传 distid=GM/T 默认 ID（1234567812345678）才能互通。"""

    @staticmethod
    def _run(cmd):
        return subprocess.run(cmd, capture_output=True, text=True, check=False)

    @staticmethod
    def _collect(label: str, text: str) -> bytes:
        m = re.search(rf"{label}:\s*\n((?:\s+[0-9a-fA-F:]+\n)+)", text)
        assert m, f"无法解析 openssl 输出中的 {label}"
        return bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", m.group(1)))

    def test_openssl_bidirectional(self, tmp_path):
        priv_pem, pub_pem = tmp_path / "sm2.pem", tmp_path / "pub.pem"
        gen = self._run(["openssl", "genpkey", "-algorithm", "SM2", "-out", str(priv_pem)])
        if gen.returncode != 0:
            gen = self._run(["openssl", "ecparam", "-genkey", "-name", "SM2", "-out", str(priv_pem)])
        assert gen.returncode == 0, gen.stderr
        assert self._run(["openssl", "pkey", "-in", str(priv_pem), "-pubout", "-out", str(pub_pem)]).returncode == 0
        txt = self._run(["openssl", "pkey", "-in", str(priv_pem), "-text", "-noout"]).stdout

        priv = self._collect("priv", txt).hex()
        pub = self._collect("pub", txt).hex()
        pub = pub.removeprefix("04")
        rig = SM2(private_key=priv, public_key=pub)
        msg = "GMScope × OpenSSL 互操作用例".encode()
        (tmp_path / "msg.bin").write_bytes(msg)

        # ① 本库签名 → openssl 验签
        sig = rig.sign(msg, k=424242)
        (tmp_path / "sig.der").write_bytes(encode_signature_der(int(sig[:64], 16), int(sig[64:], 16)))
        v = self._run(
            [
                "openssl", "pkeyutl", "-verify",
                "-in", str(tmp_path / "msg.bin"), "-sigfile", str(tmp_path / "sig.der"),
                "-pubin", "-inkey", str(pub_pem), "-rawin", "-digest", "sm3",
                "-pkeyopt", "distid:1234567812345678",
            ]
        )
        assert v.returncode == 0, v.stderr

        # ② openssl 签名 → 本库验签
        s = self._run(
            [
                "openssl", "pkeyutl", "-sign",
                "-in", str(tmp_path / "msg.bin"), "-inkey", str(priv_pem),
                "-rawin", "-digest", "sm3", "-pkeyopt", "distid:1234567812345678",
                "-out", str(tmp_path / "sig2.der"),
            ]
        )
        assert s.returncode == 0, s.stderr
        r2, s2 = decode_signature_der((tmp_path / "sig2.der").read_bytes())
        assert rig.verify(f"{r2:064x}{s2:064x}", msg)
