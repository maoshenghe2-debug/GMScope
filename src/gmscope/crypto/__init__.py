"""国密算法参考实现（纯 Python）。

设计说明
--------
本模块为 **教学对照实现**：用于演示算法细节、生成交叉验证证据。
GMScope 主链路（检测 / 报告）以成熟库（``gmssl`` / ``cryptography``）为准，
两者互为参照 —— 详见 ``gmscope crosscheck``。
"""

from .sm3 import hmac_sm3, sm3_hash, sm3_hex
from .sm4 import SM4, pkcs7_pad, pkcs7_unpad

__all__ = ["SM4", "hmac_sm3", "pkcs7_pad", "pkcs7_unpad", "sm3_hash", "sm3_hex"]
