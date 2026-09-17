"""TLCP / TLS 常量（GB/T 38636-2020；密码套件编号与 GmSSL 参考实现一致）。"""

from __future__ import annotations

# 协议版本（TLS_PROTOCOL 枚举，详见 GmSSL tls.h / IANA）
TLCP_VERSION = 0x0101

VERSION_NAMES = {
    0x0002: "SSL 2.0",
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
    0xFEFF: "DTLS 1.0",
    0xFEFD: "DTLS 1.2",
    0x0101: "TLCP (GB/T 38636)",
}


def version_name(version: int) -> str:
    return VERSION_NAMES.get(version, f"未知版本 0x{version:04x}")


# 记录层内容类型
CONTENT_TYPES = {
    20: "change_cipher_spec",
    21: "alert",
    22: "handshake",
    23: "application_data",
    24: "heartbeat",
}

# 握手消息类型
HANDSHAKE_TYPES = {
    0: "hello_request",
    1: "client_hello",
    2: "server_hello",
    11: "certificate",
    12: "server_key_exchange",
    13: "certificate_request",
    14: "server_hello_done",
    15: "certificate_verify",
    16: "client_key_exchange",
    20: "finished",
}

# TLCP 密码套件（编号与 GmSSL 参考实现 tls.h 一致）
TLCP_CIPHER_SUITES = {
    0xE011: "ECDHE_SM4_CBC_SM3",
    0xE013: "ECC_SM4_CBC_SM3",
    0xE051: "ECDHE_SM4_GCM_SM3",
    0xE053: "ECC_SM4_GCM_SM3",
    0xE015: "IBSDH_SM4_CBC_SM3",
    0xE055: "IBSDH_SM4_GCM_SM3",
    0xE017: "IBC_SM4_CBC_SM3",
    0xE057: "IBC_SM4_GCM_SM3",
    0xE019: "RSA_SM4_CBC_SM3",
    0xE059: "RSA_SM4_GCM_SM3",
}


def cipher_suite_name(suite: int) -> str:
    return TLCP_CIPHER_SUITES.get(suite, f"0x{suite:04X}")


# SM2 曲线 OID：1.2.156.10197.1.301（DER 编码，用于证书内容识别）
SM2_OID_DER = bytes.fromhex("06082A811CCF5501822D")
