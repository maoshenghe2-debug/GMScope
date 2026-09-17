"""TLCP 握手消息体解析（ClientHello / ServerHello / Certificate）。"""

from __future__ import annotations

from ..crypto.sm3 import sm3_hex
from .constants import SM2_OID_DER, cipher_suite_name, version_name

_MAX_CERTIFICATES = 64


def _u16(body: bytes, offset: int) -> tuple[int, int]:
    return int.from_bytes(body[offset : offset + 2], "big"), offset + 2


def parse_client_hello(body: bytes) -> dict:
    """解析 ClientHello 体：版本 / 随机数 / 会话 ID / 套件列表 / 压缩方法 / 扩展长度。"""
    if len(body) < 35:
        return {"error": "ClientHello 过短"}
    info: dict = {}
    version = int.from_bytes(body[0:2], "big")
    info["version"] = f"0x{version:04x}"
    info["version_name"] = version_name(version)
    offset = 2
    info["random"] = body[offset : offset + 32].hex()
    offset += 32
    sid_len = body[offset]
    offset += 1
    info["session_id"] = body[offset : offset + sid_len].hex()
    offset += sid_len
    cs_len, offset = _u16(body, offset)
    suites: list[int] = []
    end = min(offset + cs_len, len(body))
    while offset + 2 <= end:
        suites.append(int.from_bytes(body[offset : offset + 2], "big"))
        offset += 2
    info["cipher_suites"] = [f"0x{s:04X}" for s in suites]
    info["cipher_suite_names"] = [cipher_suite_name(s) for s in suites]
    comp_len = body[offset] if offset < len(body) else 0
    offset += 1
    info["compression"] = list(body[offset : offset + comp_len])
    offset += comp_len
    info["extensions_len"] = max(0, len(body) - offset)
    return info


def parse_server_hello(body: bytes) -> dict:
    """解析 ServerHello 体：版本 / 随机数 / 会话 ID / 选定套件 / 压缩方法。"""
    if len(body) < 38:
        return {"error": "ServerHello 过短"}
    info: dict = {}
    version = int.from_bytes(body[0:2], "big")
    info["version"] = f"0x{version:04x}"
    info["version_name"] = version_name(version)
    offset = 2
    info["random"] = body[offset : offset + 32].hex()
    offset += 32
    sid_len = body[offset]
    offset += 1
    info["session_id"] = body[offset : offset + sid_len].hex()
    offset += sid_len
    suite = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    info["cipher_suite"] = f"0x{suite:04X}"
    info["cipher_suite_name"] = cipher_suite_name(suite)
    comp = body[offset] if offset < len(body) else None
    offset += 1
    info["compression"] = comp
    info["extensions_len"] = max(0, len(body) - offset)
    return info


def parse_certificate(body: bytes) -> dict:
    """解析 Certificate 体：证书列表（长度 / SM3 指纹 / SM2 OID 识别）。"""
    if len(body) < 3:
        return {"error": "Certificate 过短"}
    declared_total = int.from_bytes(body[0:3], "big")
    offset = 3
    certificates: list[dict] = []
    while offset + 3 <= len(body) and len(certificates) < _MAX_CERTIFICATES:
        cert_len = int.from_bytes(body[offset : offset + 3], "big")
        offset += 3
        blob = body[offset : offset + cert_len]
        offset += cert_len
        certificates.append(
            {
                "length": cert_len,
                "sm3": sm3_hex(blob),
                "has_sm2_oid": SM2_OID_DER in blob,
                "preview": blob[:12].hex(),
            }
        )
    return {"declared_total": declared_total, "certificates": certificates}
