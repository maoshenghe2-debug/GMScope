"""SM2 椭圆曲线公钥密码算法封装（GB/T 32918 / GM/T 0003）。

设计要点：
- **主链路复用 ``gmssl``**（纯 Python，MIT 许可）完成椭圆曲线群运算与加解密；
- **可控随机数 k**：``sign_digest(..., k=...)`` / ``sign(..., k=...)`` 支持注入 k，
  用于确定性 KAT（自建已知答案测试）与标准向量消费；
- **ZA/摘要独立计算**：ZA 与 e = SM3(ZA || M) 由本项目自研纯 Python SM3
  实现计算，可与 gmssl 的 ``_sm3_z`` 交叉互证；
- **解密补强**：gmssl 原版解密不校验 C3（完整性），本封装按 GB/T 32918.4
  独立重算 C3 并校验，不匹配即报错（防篡改 / 防密文混淆）；
- 提供 DER（ASN.1）签名编解码辅助，便于与 OpenSSL 等外部工具互操作。

约定：私钥 64 位十六进制；公钥 128 位十六进制（X||Y，可带 04 前缀）。
"""

from __future__ import annotations

import secrets

from gmssl import func as gm_func
from gmssl import sm2 as gm_sm2

from .sm3 import sm3_hash

__all__ = [
    "SM2",
    "SM2Error",
    "decode_signature_der",
    "encode_signature_der",
]

CURVE_N = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
DEFAULT_UID = b"1234567812345678"


class SM2Error(ValueError):
    """SM2 参数错误或运算失败（含完整性校验失败）。"""


def _clean_hex(value: str, length: int, name: str) -> str:
    v = str(value).strip().lower()
    v = v.removeprefix("0x")
    if v.startswith("04") and len(v) == length + 2:
        v = v[2:]
    if len(v) != length:
        raise SM2Error(f"{name}长度错误：应为 {length} 位十六进制，实际 {len(v)} 位")
    try:
        int(v, 16)
    except ValueError as exc:
        raise SM2Error(f"{name}含非十六进制字符") from exc
    return v


def encode_signature_der(r: int, s: int) -> bytes:
    """把 (r, s) 编码为 DER（SEQUENCE{INTEGER r, INTEGER s}），OpenSSL 兼容。"""

    def _int(v: int) -> bytes:
        if v < 0:
            raise SM2Error("DER 整数不能为负")
        body = v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big")
        if body[0] & 0x80:
            body = b"\x00" + body
        return b"\x02" + bytes([len(body)]) + body

    inner = _int(r) + _int(s)
    return b"\x30" + bytes([len(inner)]) + inner


def decode_signature_der(der: bytes) -> tuple[int, int]:
    """解析 DER（SEQUENCE{INTEGER, INTEGER}）签名，返回 (r, s)。"""
    data = bytes(der)
    if len(data) < 8 or data[0] != 0x30:
        raise SM2Error("非法 DER 签名：缺少 SEQUENCE")
    idx, end = 2, len(data)
    values: list[int] = []
    for _ in range(2):
        if idx >= end or data[idx] != 0x02:
            raise SM2Error("非法 DER 签名：缺少 INTEGER")
        ln = data[idx + 1]
        idx += 2 + ln
        if ln == 0 or idx > end:
            raise SM2Error("非法 DER 签名：长度越界")
        values.append(int.from_bytes(data[idx - ln : idx], "big"))
    return values[0], values[1]


def new_gmssl_ctx(private_key: str = "", public_key: str = "", mode: int = 1) -> gm_sm2.CryptSM2:
    """构造 gmssl ``CryptSM2`` 上下文，并规避其公钥前缀误剥缺陷。

    gmssl 在 ``__init__`` 中执行 ``public_key.lstrip("04")``——这是**字符集剥离**
    而非前缀判断：当 128 位十六进制公钥本身以 ``04`` 开头时（约 1/256 概率，
    如 d=11 的 SM2 公钥 ``04b3cb10…``），真实数据会被误剥为 126 字符，
    导致后续点运算进入 ``None`` 退化路径（TypeError）或验签结果错误。
    本函数先以空公钥构造、再回填规范化公钥，彻底规避该缺陷。
    """
    ctx = gm_sm2.CryptSM2(private_key=private_key, public_key="", mode=mode)
    if public_key:
        ctx.public_key = public_key
    return ctx


class SM2:
    """SM2 密钥与运算封装（签名 / 验签 / 加密 / 解密）。"""

    def __init__(self, private_key: str | None = None, public_key: str | None = None):
        if private_key is None and public_key is None:
            raise SM2Error("至少需要提供私钥或公钥之一")
        self.private_key: str | None = None
        self.public_key: str | None = None
        if private_key is not None:
            priv = _clean_hex(private_key, 64, "私钥")
            if not 1 <= int(priv, 16) < CURVE_N:
                raise SM2Error("私钥必须落在 [1, n-1] 区间")
            self.private_key = priv
        if public_key is not None:
            self.public_key = _clean_hex(public_key, 128, "公钥")
        if self.public_key is None and self.private_key is not None:
            self.public_key = self.derive_public(self.private_key)
        # 密文顺序 C1C3C2（GB/T 32918.4-2016 默认）；构造入口见 new_gmssl_ctx
        self._c = new_gmssl_ctx(self.private_key or "", self.public_key or "")

    # ------------------------------------------------------------ 密钥
    @classmethod
    def generate(cls) -> SM2:
        """生成新密钥对（``secrets`` 密码学安全随机源）。"""
        d = secrets.randbelow(CURVE_N - 1) + 1
        return cls(private_key=f"{d:064x}")

    @staticmethod
    def derive_public(private_key: str) -> str:
        """由私钥推导公钥（X||Y，128 位十六进制）。"""
        priv = _clean_hex(private_key, 64, "私钥")
        c = new_gmssl_ctx(private_key=priv)
        return c._kg(int(priv, 16), c.ecc_table["g"])

    # ------------------------------------------------------------ ZA / 摘要
    def compute_za(self, uid: bytes = DEFAULT_UID) -> bytes:
        """ZA = SM3(ENTL || ID || a || b || Gx || Gy || Px || Py)（自研 SM3）。"""
        if not self.public_key:
            raise SM2Error("计算 ZA 需要公钥")
        table = gm_sm2.default_ecc_table
        entl = (len(uid) * 8).to_bytes(2, "big")
        g = table["g"]
        body = (
            entl
            + bytes(uid)
            + bytes.fromhex(table["a"])
            + bytes.fromhex(table["b"])
            + bytes.fromhex(g[:64])
            + bytes.fromhex(g[64:])
            + bytes.fromhex(self.public_key[:64])
            + bytes.fromhex(self.public_key[64:])
        )
        return sm3_hash(body)

    def compute_e(self, message: bytes, uid: bytes = DEFAULT_UID) -> bytes:
        """e = SM3(ZA || M)，返回 32 字节摘要。"""
        return sm3_hash(self.compute_za(uid) + bytes(message))

    # ------------------------------------------------------------ 签名 / 验签
    def sign_digest(self, e: bytes, k: int | None = None) -> str:
        """对 32 字节摘要 e 签名；k 可注入以实现确定性。返回 r||s（128 位十六进制）。"""
        if self.private_key is None:
            raise SM2Error("缺少私钥，无法签名")
        digest = bytes(e)
        if len(digest) != 32:
            raise SM2Error("待签摘要必须为 32 字节")
        k_hex = f"{k:064x}" if k is not None else gm_func.random_hex(64)
        sig = self._c.sign(digest, k_hex)
        if sig is None:
            if k is not None:
                raise SM2Error("注入的 k 产生退化签名（r=0 或 s=0）")
            return self.sign_digest(digest)
        return sig

    def sign(self, message: bytes, uid: bytes = DEFAULT_UID, k: int | None = None) -> str:
        """对消息签名（内部生成 e = SM3(ZA||M)），返回 r||s。"""
        return self.sign_digest(self.compute_e(message, uid), k=k)

    def verify(self, signature, message: bytes, uid: bytes = DEFAULT_UID) -> bool:
        """验签（内部生成 e）。signature 支持 r||s 十六进制字符串或 bytes。"""
        return self.verify_digest(signature, self.compute_e(message, uid))

    def verify_digest(self, signature, e: bytes) -> bool:
        """对摘要级签名验签。"""
        if self.public_key is None:
            raise SM2Error("缺少公钥，无法验签")
        sig = signature.hex() if isinstance(signature, (bytes, bytearray)) else str(signature)
        sig = sig.strip().lower()
        if len(sig) != 128:
            raise SM2Error("签名应为 128 位十六进制（r||s）")
        return bool(self._c.verify(sig, bytes(e)))

    # ------------------------------------------------------------ 加密 / 解密
    def encrypt(self, data: bytes) -> bytes:
        """加密（C1C3C2 顺序），返回密文字节。不支持空明文（gmssl 内核限制）。"""
        if self.public_key is None:
            raise SM2Error("缺少公钥，无法加密")
        payload = bytes(data)
        if not payload:
            raise SM2Error("不支持加密空消息（gmssl 内核限制）")
        # gmssl 内核在 KDF 输出退化（全零）时返回 None——短消息下概率不可忽略
        # （约 1/256 @ 1 字节），此处自动更换随机数重试，避免偶发失败。
        for _ in range(8):
            out = self._c.encrypt(payload)
            if out is not None:
                return out
        raise SM2Error("加密失败：连续 8 次 KDF 输出退化，请检查运行环境随机性")

    def decrypt(self, data: bytes) -> bytes:
        """解密（C1C3C2），并独立校验 C3 完整性。不支持空明文密文。"""
        if self.private_key is None:
            raise SM2Error("缺少私钥，无法解密")
        blob = bytes(data)
        if len(blob) < 97:
            raise SM2Error("密文长度非法：至少 97 字节（C1=64 + C3=32 + C2≥1；本封装不支持空明文）")
        m = self._c.decrypt(blob)
        if m is None:
            raise SM2Error("解密失败（KDF 输出全零或密文非法）")
        xy = self._c._kg(int(self.private_key, 16), blob[:64].hex())
        c3_expect = sm3_hash(bytes.fromhex(xy[:64]) + m + bytes.fromhex(xy[64:]))
        if c3_expect != blob[64:96]:
            raise SM2Error("完整性校验失败：C3 不匹配（密文被篡改或密钥不匹配）")
        return m
