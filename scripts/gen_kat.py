#!/usr/bin/env python3
"""生成并冻结 KAT（已知答案测试）数据到 ``src/gmscope/kat_data.py``（随包分发）。

- **SM2**：密钥由 OpenSSL 生成；确定性签名（注入 k）由 OpenSSL ``pkeyutl``
  独立验证（验证通过才收录）；同时做「OpenSSL 签名 → 本库验签」的反向互操作校验。
- **SM4-GCM**：向量由 ``cryptography``（OpenSSL 后端）计算生成，本库实现比对一致后收录。

用法：
    python scripts/gen_kat.py [--no-openssl]

注意：脚本生成的是**冻结数据**，测试只读取 ``gmscope.kat_data``；
重新生成请在本机具备 OpenSSL 3.x 时执行，并提交新的数据文件。
"""

from __future__ import annotations

import hashlib
import json
import pprint
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from gmscope.crypto.sm2 import DEFAULT_UID, SM2, decode_signature_der, encode_signature_der
from gmscope.crypto.sm4 import SM4

_CURVE_N = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def _parse_pkey_text(text: str) -> tuple[bytes, bytes]:
    """解析 ``openssl pkey -text -noout`` 输出中的 priv/pub 十六进制块。"""

    def _collect(label: str) -> bytes:
        m = re.search(rf"{label}:\s*\n((?:\s+[0-9a-fA-F:]+\n)+)", text)
        if not m:
            raise RuntimeError(f"无法从 openssl 输出中解析 {label}")
        return bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", m.group(1)))

    return _collect("priv"), _collect("pub")


def gen_sm2_kat(tmp: Path, use_openssl: bool) -> dict:
    priv_hex = pub_hex = None
    openssl_used = False
    if use_openssl and shutil.which("openssl"):
        priv_pem, pub_pem = tmp / "sm2.pem", tmp / "sm2_pub.pem"
        r1 = _run(["openssl", "genpkey", "-algorithm", "SM2", "-out", str(priv_pem)])
        if r1.returncode != 0:
            r1 = _run(["openssl", "ecparam", "-genkey", "-name", "SM2", "-out", str(priv_pem)])
        if r1.returncode == 0:
            r2 = _run(["openssl", "pkey", "-in", str(priv_pem), "-pubout", "-out", str(pub_pem)])
            r3 = _run(["openssl", "pkey", "-in", str(priv_pem), "-text", "-noout"])
            if r2.returncode == 0 and r3.returncode == 0:
                priv_b, pub_b = _parse_pkey_text(r3.stdout)
                priv_hex = priv_b.hex()
                pub_hex = pub_b.hex()
                if len(pub_b) == 65 and pub_hex.startswith("04"):
                    pub_hex = pub_hex[2:]
                openssl_used = True
    if priv_hex is None:
        kp = SM2.generate()
        priv_hex, pub_hex = kp.private_key, kp.public_key

    sm2 = SM2(private_key=priv_hex, public_key=pub_hex)
    msg = "国密算法 GMScope · SM2 签名 KAT 用例 #1".encode()
    k = int.from_bytes(hashlib.sha256(b"gmscope-sm2-kat-1").digest(), "big") % (_CURVE_N - 1) + 1
    sig = sm2.sign(msg, k=k)

    # 1) gmssl 原生路径复核（verify_with_sm3 内部自行计算 ZA）
    from gmscope.crypto.sm2 import new_gmssl_ctx

    g = new_gmssl_ctx("", pub_hex)
    gmssl_ok = bool(g.verify_with_sm3(sig, msg))

    # 2) 自研 SM3 计算 ZA/e 与 gmssl _sm3_z 对照
    g_full = new_gmssl_ctx(priv_hex, pub_hex)
    za_ok = g_full._sm3_z(msg) == sm2.compute_e(msg).hex()

    # 3) OpenSSL 双向互操作
    openssl_verify_ok = openssl_sign_ok = False
    if openssl_used:
        (tmp / "msg.bin").write_bytes(msg)
        r, s = int(sig[:64], 16), int(sig[64:], 16)
        (tmp / "sig.der").write_bytes(encode_signature_der(r, s))
        # 注意：OpenSSL 的 SM2 默认用户标识为**空串**（不套用 GM/T 默认 ID），
        # 必须显式传入 distid，才能与国密默认 ID（1234567812345678）互通。
        v = _run(
            [
                "openssl", "pkeyutl", "-verify",
                "-in", str(tmp / "msg.bin"), "-sigfile", str(tmp / "sig.der"),
                "-pubin", "-inkey", str(tmp / "sm2_pub.pem"), "-rawin", "-digest", "sm3",
                "-pkeyopt", "distid:1234567812345678",
            ]
        )
        openssl_verify_ok = v.returncode == 0
        sg = _run(
            [
                "openssl", "pkeyutl", "-sign",
                "-in", str(tmp / "msg.bin"), "-inkey", str(tmp / "sm2.pem"),
                "-rawin", "-digest", "sm3", "-pkeyopt", "distid:1234567812345678",
                "-out", str(tmp / "sig2.der"),
            ]
        )
        if sg.returncode == 0:
            r2, s2 = decode_signature_der((tmp / "sig2.der").read_bytes())
            openssl_sign_ok = sm2.verify(f"{r2:064x}{s2:064x}", msg)

    return {
        "private_key": priv_hex,
        "public_key": pub_hex,
        "message_hex": msg.hex(),
        "k": k,
        "signature": sig,
        "uid_hex": DEFAULT_UID.hex(),
        "checks": {
            "gmssl_native_verify": gmssl_ok,
            "za_e_matches_gmssl": za_ok,
            "openssl_verify": openssl_verify_ok,
            "openssl_sign_then_gmscope_verify": openssl_sign_ok,
        },
        "generator": "openssl-3.x" if openssl_used else "gmscope-fallback(无 openssl)",
    }


def gen_sm4_gcm_kat() -> dict:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    iv = bytes.fromhex("000102030405060708090a0b")  # 12 字节（GCM 推荐）
    iv16 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")  # 16 字节（GHASH 路径）
    aad = b"GMScope-AAD"
    pt = "国密算法 GMScope · SM4-GCM 认证加密 KAT 用例 #1".encode()

    def _enc(iv_bytes: bytes) -> tuple[bytes, bytes]:
        enc = Cipher(algorithms.SM4(key), modes.GCM(iv_bytes)).encryptor()
        enc.authenticate_additional_data(aad)
        ct = enc.update(pt) + enc.finalize()
        return ct, enc.tag

    ct, tag = _enc(iv)
    ct16, tag16 = _enc(iv16)

    sm4 = SM4(key)
    assert sm4.encrypt_gcm(pt, iv, aad) == (ct, tag), "12 字节 IV 向量与 cryptography 不一致"
    assert sm4.encrypt_gcm(pt, iv16, aad) == (ct16, tag16), "16 字节 IV 向量与 cryptography 不一致"
    assert sm4.decrypt_gcm(ct, tag, iv, aad) == pt

    return {
        "key": key.hex(),
        "iv": iv.hex(),
        "iv16": iv16.hex(),
        "aad": aad.hex(),
        "plaintext": pt.hex(),
        "ciphertext": ct.hex(),
        "tag": tag.hex(),
        "ciphertext_iv16": ct16.hex(),
        "tag_iv16": tag16.hex(),
        "generator": "cryptography/OpenSSL",
    }


def main() -> int:
    use_openssl = "--no-openssl" not in sys.argv
    with tempfile.TemporaryDirectory(prefix="gmscope_kat_") as td:
        tmp = Path(td)
        sm2_kat = gen_sm2_kat(tmp, use_openssl)
        sm4_kat = gen_sm4_gcm_kat()

    kat = {"SM2_SIGN": sm2_kat, "SM4_GCM": sm4_kat}
    target = ROOT / "src" / "gmscope" / "kat_data.py"
    header = (
        '"""自动生成的 KAT（已知答案测试）数据 —— 由 ``scripts/gen_kat.py`` 生成，请勿手改。\n\n'
        "- SM2：密钥与签名经 OpenSSL 独立验证（checks 字段为生成时的校验结果）。\n"
        "- SM4-GCM：向量由 cryptography（OpenSSL）计算，本库实现比对一致后收录。\n"
        '"""\n\n'
    )
    body = pprint.pformat(kat, width=110, sort_dicts=False)
    target.write_text(header + "KAT = " + body + "\n", encoding="utf-8")
    print(f"已写入 {target}")
    print(json.dumps({key: value.get("generator", "") for key, value in kat.items()}, ensure_ascii=False))
    print("SM2 checks:", json.dumps(sm2_kat["checks"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
