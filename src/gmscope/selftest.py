"""标准向量自检引擎：SM3 / SM4（GM/T 0002 / GM/T 0004 附录示例）。"""

from __future__ import annotations

from dataclasses import dataclass

from .crypto.sm3 import sm3_hex
from .crypto.sm4 import SM4
from .crypto.vectors import SM3_VECTORS, SM4_SLOW_VECTORS, SM4_VECTORS


@dataclass
class CheckResult:
    """单条自检结果。"""

    name: str
    source: str
    passed: bool
    detail: str = ""


def run_sm3_vectors() -> list[CheckResult]:
    results: list[CheckResult] = []
    for v in SM3_VECTORS:
        got = sm3_hex(v["input"])
        ok = got == v["digest"]
        detail = "" if ok else f"期望 {v['digest'][:20]}… / 实际 {got[:20]}…"
        results.append(CheckResult(v["name"], v["source"], ok, detail))
    return results


def run_sm4_vectors() -> list[CheckResult]:
    results: list[CheckResult] = []
    for v in SM4_VECTORS:
        key = bytes.fromhex(v["key"])
        plain = bytes.fromhex(v["plain"])
        sm4 = SM4(key)
        enc = sm4.encrypt_block(plain).hex()
        dec = sm4.decrypt_block(bytes.fromhex(v["cipher"])).hex()
        ok = enc == v["cipher"] and dec == v["plain"]
        detail = "" if ok else f"加密 {enc[:20]}… / 解密 {dec[:20]}…"
        results.append(CheckResult(f"{v['name']}（加密+解密）", v["source"], ok, detail))
    return results


def run_sm4_slow_vectors() -> list[CheckResult]:
    """百万次迭代向量（约 1-2 分钟，默认不运行）。"""
    results: list[CheckResult] = []
    for v in SM4_SLOW_VECTORS:
        sm4 = SM4(bytes.fromhex(v["key"]))
        cur = bytes.fromhex(v["plain"])
        for _ in range(1_000_000):
            cur = sm4.encrypt_block(cur)
        got = cur.hex()
        ok = got == v["cipher"]
        detail = "" if ok else f"期望 {v['cipher']} / 实际 {got}"
        results.append(CheckResult(v["name"], v["source"], ok, detail))
    return results


def run_kat_vectors() -> list[CheckResult]:
    """自建 KAT（``src/gmscope/kat_data.py``：经 OpenSSL / cryptography 交叉验证的冻结向量）。"""
    results: list[CheckResult] = []
    try:
        from .crypto.sm2 import SM2
        from .kat_data import KAT
    except ImportError:
        results.append(
            CheckResult("SM2/SM4-GCM KAT（跳过：未安装 gmssl）", "自建 KAT", True, "pip install gmscope[crypto]")
        )
        return results

    sm2k = KAT["SM2_SIGN"]
    rig = SM2(private_key=sm2k["private_key"], public_key=sm2k["public_key"])
    msg = bytes.fromhex(sm2k["message_hex"])
    sig = rig.sign(msg, k=sm2k["k"])
    ok = sig == sm2k["signature"] and rig.verify(sig, msg)
    results.append(
        CheckResult("SM2 确定性签名（注入 k）+ 验签", "自建 KAT · OpenSSL 交叉验证", ok, "" if ok else f"实际 {sig[:24]}…")
    )

    gk = KAT["SM4_GCM"]
    sm4 = SM4(bytes.fromhex(gk["key"]))
    ct, tag = sm4.encrypt_gcm(bytes.fromhex(gk["plaintext"]), bytes.fromhex(gk["iv"]), bytes.fromhex(gk["aad"]))
    ok = ct.hex() == gk["ciphertext"] and tag.hex() == gk["tag"]
    results.append(CheckResult("SM4-GCM 认证加密", "自建 KAT · cryptography 交叉验证", ok, "" if ok else "向量不一致"))
    return results


def run_selftest(include_slow: bool = False) -> list[CheckResult]:
    """运行全部标准向量自检（标准向量 + 自建 KAT）。"""
    results = run_sm3_vectors() + run_sm4_vectors() + run_kat_vectors()
    if include_slow:
        results += run_sm4_slow_vectors()
    return results
