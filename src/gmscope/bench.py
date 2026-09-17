"""性能基准：SM3 / SM4（ECB/CBC/GCM）/ SM2（本库 vs 参考库）。

用途：为 README / 验收提供**可复现**的性能口径（脚本 + 固定数据集 + 本机环境）。
说明：本库为纯 Python 教学对照实现，数字不代表生产性能；
生产链路请使用 gmssl / cryptography 等成熟实现。
"""

from __future__ import annotations

import time
from dataclasses import dataclass

__all__ = ["BenchResult", "run_bench"]


@dataclass
class BenchResult:
    name: str
    impl: str
    value: float
    unit: str
    detail: str = ""


def _mbps(nbytes: int, seconds: float) -> float:
    return (nbytes / (1024 * 1024)) / seconds if seconds > 0 else 0.0


def _take(fn, *args) -> float:
    t0 = time.perf_counter()
    fn(*args)
    return time.perf_counter() - t0


def _dataset(n: int) -> bytes:
    pattern = bytes(range(256))
    return (pattern * (n // 256 + 1))[:n]


def _try(fn) -> bool:
    """执行可选基准项；依赖 / 环境能力缺失时跳过（不中断其余基准）。"""
    try:
        fn()
    except Exception:  # noqa: BLE001 —— 可选依赖或环境能力缺失，基准不中断
        return False
    return True


def run_bench(quick: bool = True, tiny: bool = False) -> list[BenchResult]:
    """运行性能基准。

    :param quick: True=快速（默认）；False=完整数据集（约 8 倍时长）
    :param tiny: True=最小数据集（测试专用，数秒内完成）
    """
    from .crypto.sm3 import sm3_hash
    from .crypto.sm4 import SM4

    if tiny:
        sm3_n, sm4_n, gcm_n, sm2_ops = 32 * 1024, 8 * 1024, 2 * 1024, 3
    elif quick:
        sm3_n, sm4_n, gcm_n, sm2_ops = 256 * 1024, 64 * 1024, 8 * 1024, 8
    else:
        sm3_n, sm4_n, gcm_n, sm2_ops = 4 * 1024 * 1024, 512 * 1024, 64 * 1024, 24

    key = bytes(16)
    iv12 = bytes(12)
    aad = b"gmscope-bench"
    results: list[BenchResult] = []

    # ---- SM3 ----
    data = _dataset(sm3_n)
    secs = _take(sm3_hash, data)
    results.append(BenchResult("SM3 杂凑", "本库(纯 Python)", _mbps(sm3_n, secs), "MB/s", f"{sm3_n // 1024} KiB"))

    def _gmssl_sm3() -> None:
        from gmssl import sm3 as g_sm3

        secs_g = _take(g_sm3.sm3_hash, list(data))
        results.append(BenchResult("SM3 杂凑", "gmssl", _mbps(sm3_n, secs_g), "MB/s", f"{sm3_n // 1024} KiB"))

    _try(_gmssl_sm3)

    # ---- SM4 ECB / CBC ----
    sm4 = SM4(key)
    data = _dataset(sm4_n)
    n = len(data) - len(data) % 16
    data = data[:n]
    secs = _take(sm4.encrypt_ecb, data, True)
    results.append(BenchResult("SM4-ECB 加密", "本库(纯 Python)", _mbps(n, secs), "MB/s", f"{n // 1024} KiB"))
    secs = _take(sm4.encrypt_cbc, data, bytes(16), True)
    results.append(BenchResult("SM4-CBC 加密", "本库(纯 Python)", _mbps(n, secs), "MB/s", f"{n // 1024} KiB"))

    def _gmssl_sm4() -> None:
        from gmssl import sm4 as g_sm4

        c = g_sm4.CryptSM4()
        c.set_key(key, g_sm4.SM4_ENCRYPT)
        secs_g = _take(c.crypt_ecb, data)
        results.append(BenchResult("SM4-ECB 加密", "gmssl", _mbps(n, secs_g), "MB/s", f"{n // 1024} KiB（库内填充）"))

    _try(_gmssl_sm4)

    # ---- SM4-GCM ----
    data = _dataset(gcm_n)
    secs = _take(sm4.encrypt_gcm, data, iv12, aad)
    results.append(
        BenchResult("SM4-GCM 加密", "本库(纯 Python)", _mbps(gcm_n, secs), "MB/s", f"{gcm_n // 1024} KiB（含 GHASH）")
    )

    def _ref_gcm() -> None:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        enc = Cipher(algorithms.SM4(key), modes.GCM(iv12)).encryptor()
        enc.authenticate_additional_data(aad)
        secs_g = _take(lambda: enc.update(data) + enc.finalize())
        results.append(BenchResult("SM4-GCM 加密", "cryptography", _mbps(gcm_n, secs_g), "MB/s", f"{gcm_n // 1024} KiB"))

    _try(_ref_gcm)

    # ---- SM2 ----
    def _sm2_section() -> None:
        from .crypto.sm2 import SM2

        kp = SM2.generate()
        msg = b"gmscope-bench-payload"
        sig = kp.sign(msg)
        ct = kp.encrypt(msg)
        secs_s = _take(lambda: [kp.sign(msg) for _ in range(sm2_ops)])
        results.append(BenchResult("SM2 签名", "本库封装(gmssl 内核)", sm2_ops / secs_s, "ops/s", f"{sm2_ops} 次"))
        secs_s = _take(lambda: [kp.verify(sig, msg) for _ in range(sm2_ops)])
        results.append(BenchResult("SM2 验签", "本库封装(gmssl 内核)", sm2_ops / secs_s, "ops/s", f"{sm2_ops} 次"))
        secs_s = _take(lambda: [kp.encrypt(msg) for _ in range(sm2_ops)])
        results.append(BenchResult("SM2 加密", "本库封装(gmssl 内核)", sm2_ops / secs_s, "ops/s", f"{sm2_ops} 次"))
        secs_s = _take(lambda: [kp.decrypt(ct) for _ in range(sm2_ops)])
        results.append(BenchResult("SM2 解密", "本库封装(gmssl 内核)", sm2_ops / secs_s, "ops/s", f"{sm2_ops} 次"))

    _try(_sm2_section)
    return results
