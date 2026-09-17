"""与成熟库（gmssl / cryptography）的交叉验证。

用途：为「教学对照实现」提供独立可信度证据 —— 以随机用例批量比对，
双方一致即认为实现正确（两个独立实现同时犯相同错误的概率可忽略）。

约定：
- gmssl 的 ``crypt_ecb`` 自带 PKCS#7 填充，对照时取其首个分组；
- cryptography 依赖 OpenSSL 3.x 提供 SM4/SM3（缺能力时自动跳过并说明）。
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from .crypto.sm3 import sm3_hash
from .crypto.sm4 import SM4

_SEED = 20260917
_LENGTHS = [0, 1, 7, 15, 16, 31, 55, 56, 63, 64, 65, 100, 255, 256, 511, 512, 1000, 4096]


@dataclass
class CrossResult:
    """一次交叉验证的结果。"""

    engine: str
    algorithm: str
    cases: int
    matched: int
    note: str = ""

    @property
    def ok(self) -> bool:
        return self.cases > 0 and self.matched == self.cases


# ---------------------------------------------------------------- 依赖加载


def _load_gmssl():
    try:
        from gmssl import sm3 as g_sm3
        from gmssl import sm4 as g_sm4

        return g_sm3, g_sm4
    except ImportError:
        return None, None


def _load_cryptography():
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        return Cipher, algorithms, modes, hashes
    except ImportError:
        return None, None, None, None


# ---------------------------------------------------------------- SM3


def crosscheck_sm3_gmssl(n: int = 64) -> CrossResult:
    g_sm3, _ = _load_gmssl()
    if g_sm3 is None:
        return CrossResult("gmssl", "SM3", 0, 0, "未安装 gmssl，跳过")
    rng = random.Random(_SEED)
    matched = 0
    for _ in range(n):
        data = rng.randbytes(rng.choice(_LENGTHS))
        if g_sm3.sm3_hash(list(data)) == sm3_hash(data).hex():
            matched += 1
    return CrossResult("gmssl", "SM3", n, matched)


def crosscheck_sm3_cryptography(n: int = 64) -> CrossResult:
    _, _, _, hashes = _load_cryptography()
    if hashes is None or not hasattr(hashes, "SM3"):
        return CrossResult("cryptography", "SM3", 0, 0, "当前环境不支持 SM3（需 OpenSSL 3.x）")
    rng = random.Random(_SEED + 1)
    matched = 0
    try:
        for _ in range(n):
            data = rng.randbytes(rng.choice(_LENGTHS))
            h = hashes.Hash(hashes.SM3())
            h.update(data)
            if h.finalize().hex() == sm3_hash(data).hex():
                matched += 1
    except Exception as exc:  # noqa: BLE001 —— OpenSSL 能力缺失等
        return CrossResult("cryptography", "SM3", 0, 0, f"运行失败：{exc}")
    return CrossResult("cryptography", "SM3", n, matched)


# ---------------------------------------------------------------- SM4


def crosscheck_sm4_gmssl(n: int = 64) -> CrossResult:
    _, g_sm4 = _load_gmssl()
    if g_sm4 is None:
        return CrossResult("gmssl", "SM4-ECB", 0, 0, "未安装 gmssl，跳过")
    rng = random.Random(_SEED + 2)
    matched = 0
    for _ in range(n):
        key = rng.randbytes(16)
        pt = rng.randbytes(16)
        c = g_sm4.CryptSM4()
        c.set_key(key, g_sm4.SM4_ENCRYPT)
        theirs = c.crypt_ecb(pt)[:16]  # 库自带 PKCS#7 填充，取首个分组
        if theirs == SM4(key).encrypt_block(pt):
            matched += 1
    return CrossResult("gmssl", "SM4-ECB", n, matched)


def crosscheck_sm4_cryptography(n: int = 64) -> CrossResult:
    Cipher, algorithms, modes, _ = _load_cryptography()
    if Cipher is None or not hasattr(algorithms, "SM4"):
        return CrossResult("cryptography", "SM4", 0, 0, "当前环境不支持 SM4（需 OpenSSL 3.x）")

    rng = random.Random(_SEED + 3)
    matched = checks = 0
    try:
        for _ in range(n):
            key = rng.randbytes(16)
            pt = rng.randbytes(16)
            iv = rng.randbytes(16)
            sm4 = SM4(key)

            enc = Cipher(algorithms.SM4(key), modes.ECB()).encryptor()
            if enc.update(pt) + enc.finalize() == sm4.encrypt_block(pt):
                matched += 1
            checks += 1

            cbc = Cipher(algorithms.SM4(key), modes.CBC(iv)).encryptor()
            if cbc.update(pt) + cbc.finalize() == sm4.encrypt_cbc(pt, iv, pad=False):
                matched += 1
            checks += 1

            msg = rng.randbytes(rng.choice([0, 1, 15, 16, 17, 33, 64, 100]))
            ctr = Cipher(algorithms.SM4(key), modes.CTR(iv)).encryptor()
            if ctr.update(msg) + ctr.finalize() == sm4.crypt_ctr(msg, iv):
                matched += 1
            checks += 1
    except Exception as exc:  # noqa: BLE001
        return CrossResult("cryptography", "SM4-ECB/CBC/CTR", 0, 0, f"运行失败：{exc}")
    return CrossResult("cryptography", "SM4-ECB/CBC/CTR", checks, matched)


# ---------------------------------------------------------------- SM2


def crosscheck_sm2_gmssl(n: int = 16) -> CrossResult:
    """SM2 五项对照（每用例 5 项检查）：

    1) 自研 SM3 计算的 e 与 gmssl ``_sm3_z`` 一致（ZA 构造互证）；
    2) 本库签名 → gmssl 原生验签；
    3) gmssl 原生签名 → 本库验签；
    4) 本库加密 → gmssl 解密；
    5) gmssl 加密 → 本库解密（含 C3 完整性校验）。
    """
    try:
        from gmssl import sm2 as g_sm2

        from .crypto.sm2 import SM2
    except ImportError:
        return CrossResult("gmssl", "SM2(签/验/加解密)", 0, 0, "未安装 gmssl，跳过")

    rng = random.Random(_SEED + 4)
    matched = checks = 0
    for _ in range(n):
        kp = SM2.generate()
        # 避免 1-2 字节短消息：gmssl 内核在短消息下 KDF 输出可能退化（约 1/256 @ 1 字节），
        # 用例集中 ≥16 字节；封装层已做重试，见 tests/test_sm2.py 回归用例。
        msg = rng.randbytes(rng.choice([16, 32, 64, 100, 255]))
        # 注意：gmssl 的 CryptSM2 默认 mode=0（C1C2C3），而本库统一 C1C3C2（mode=1）——
        # 两侧必须显式对齐，否则加解密步骤会静默错位 / C3 完整性校验失败。
        g_full = g_sm2.CryptSM2(private_key=kp.private_key, public_key=kp.public_key, mode=1)
        g_pub = g_sm2.CryptSM2(private_key="", public_key=kp.public_key, mode=1)

        if g_full._sm3_z(msg) == kp.compute_e(msg).hex():  # ① e 值互证
            matched += 1
        checks += 1

        if g_pub.verify_with_sm3(kp.sign(msg), msg):  # ② 本库签 → gmssl 验
            matched += 1
        checks += 1

        sig2 = g_full.sign_with_sm3(msg)
        if sig2 and kp.verify(sig2, msg):  # ③ gmssl 签 → 本库验
            matched += 1
        checks += 1

        if g_sm2.CryptSM2(private_key=kp.private_key, public_key="", mode=1).decrypt(kp.encrypt(msg)) == msg:  # ④
            matched += 1
        checks += 1

        gm_ct = None
        for _ in range(8):
            gm_ct = g_pub.encrypt(msg)
            if gm_ct is not None:  # gmssl 侧 KDF 退化时换随机数重试
                break
        if gm_ct is not None and kp.decrypt(gm_ct) == msg:  # ⑤ 含 C3 校验
            matched += 1
        checks += 1
    return CrossResult("gmssl", "SM2(签/验/加解密)", checks, matched)


# ---------------------------------------------------------------- SM4-GCM


def crosscheck_sm4_gcm_cryptography(n: int = 32) -> CrossResult:
    """SM4-GCM 对照：随机密钥 / IV(12、16 字节) / AAD 批量比对密文与标签。"""
    Cipher, algorithms, modes, _ = _load_cryptography()
    if Cipher is None or not hasattr(algorithms, "SM4"):
        return CrossResult("cryptography", "SM4-GCM", 0, 0, "当前环境不支持 SM4（需 OpenSSL 3.x）")

    from .crypto.sm4 import SM4

    rng = random.Random(_SEED + 5)
    matched = checks = 0
    try:
        for _ in range(n):
            key = rng.randbytes(16)
            iv = rng.randbytes(rng.choice([12, 16]))
            aad = rng.randbytes(rng.choice([0, 1, 13, 64]))
            msg = rng.randbytes(rng.choice([0, 1, 15, 16, 17, 33, 64, 100, 255]))
            sm4 = SM4(key)

            ct, tag = sm4.encrypt_gcm(msg, iv, aad)
            enc = Cipher(algorithms.SM4(key), modes.GCM(iv)).encryptor()
            enc.authenticate_additional_data(aad)
            ref_ct = enc.update(msg) + enc.finalize()
            if ct == ref_ct and tag == enc.tag:
                matched += 1
            checks += 1

            dec = Cipher(algorithms.SM4(key), modes.GCM(iv, tag)).decryptor()
            dec.authenticate_additional_data(aad)
            if dec.update(ref_ct) + dec.finalize() == msg:
                matched += 1
            checks += 1
    except Exception as exc:  # noqa: BLE001 —— 环境能力缺失等
        return CrossResult("cryptography", "SM4-GCM", 0, 0, f"运行失败：{exc}")
    return CrossResult("cryptography", "SM4-GCM", checks, matched)


# ---------------------------------------------------------------- 汇总


def run_crosscheck(n: int = 64) -> list[CrossResult]:
    """运行全部交叉验证项（SM2 纯 Python 较慢，用例数上限 16）。"""
    return [
        crosscheck_sm3_gmssl(n),
        crosscheck_sm3_cryptography(n),
        crosscheck_sm4_gmssl(n),
        crosscheck_sm4_cryptography(n),
        crosscheck_sm4_gcm_cryptography(n),
        crosscheck_sm2_gmssl(min(n, 16)),
    ]
