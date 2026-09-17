"""全合成 TLCP 演示样本：原始记录流 + PCAP。

**重要**：样本中不包含任何真实密钥、证书或流量——证书为「证书样」字节串
（DER 片段头 + SM2 OID + 伪随机填充），仅用于演示解析路径（OID 识别 / SM3 指纹）。
"""

from __future__ import annotations

from ..crypto.sm3 import sm3_hash
from .constants import SM2_OID_DER, TLCP_VERSION
from .pcap import build_ethernet_ipv4_tcp, write_pcap


def _handshake(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type]) + len(body).to_bytes(3, "big") + body


def _record(content_type: int, payload: bytes, version: int = TLCP_VERSION) -> bytes:
    return bytes([content_type]) + version.to_bytes(2, "big") + len(payload).to_bytes(2, "big") + payload


def _fake_certificate(tag: bytes, length: int = 320) -> bytes:
    """生成「证书样」字节串（非有效证书）：DER 片段头 + SM2 OID + 伪随机填充。"""
    seed = sm3_hash(tag)
    filler_len = max(0, length - 8 - len(SM2_OID_DER))
    filler = (seed * (filler_len // len(seed) + 2))[:filler_len]
    return b"\x30\x82\x01\x36\x30\x0d" + SM2_OID_DER + filler


def build_client_hello_body() -> bytes:
    """ClientHello：TLCP 0x0101，提供四个国密套件（E011/E013/E051/E053）。"""
    return (
        TLCP_VERSION.to_bytes(2, "big")
        + bytes(range(32))  # 随机数（确定性，演示用）
        + b"\x00"  # 会话 ID 长度 0
        + (8).to_bytes(2, "big")
        + bytes.fromhex("e011e013e051e053")
        + b"\x01\x00"  # 压缩方法：null
        + b"\x00\x00"  # 扩展长度 0
    )


def build_server_hello_body() -> bytes:
    """ServerHello：选定 ECDHE_SM4_GCM_SM3（0xE051）。"""
    return (
        TLCP_VERSION.to_bytes(2, "big")
        + bytes(reversed(range(32)))
        + b"\x00"
        + bytes.fromhex("e051")
        + b"\x00"
        + b"\x00\x00"
    )


def build_certificate_body() -> bytes:
    """Certificate：双证书（索引 0 签名证书 + 索引 1 加密证书，均为演示字节）。"""
    certs = [_fake_certificate(b"gmscope-sign-cert", 320), _fake_certificate(b"gmscope-enc-cert", 288)]
    body = b"".join(len(c).to_bytes(3, "big") + c for c in certs)
    return len(body).to_bytes(3, "big") + body


def build_tlcp_demo_stream() -> bytes:
    """完整演示记录流：CH → SH → Cert → SKE → SHD → CCS → 加密记录。"""
    ch = _record(22, _handshake(1, build_client_hello_body()))
    sh = _record(22, _handshake(2, build_server_hello_body()))
    cert = _record(22, _handshake(11, build_certificate_body()))
    ske = _record(22, _handshake(12, bytes.fromhex("0300294104") + sm3_hash(b"gmscope-ske") * 2))
    shd = _record(22, _handshake(14, b""))
    ccs = _record(20, b"\x01")
    enc = _record(22, sm3_hash(b"gmscope-encrypted-finished"))
    return ch + sh + cert + ske + shd + ccs + enc


def build_tlcp_demo_pcap() -> bytes:
    """把演示记录流切分为 4 个 TCP 段并封装为 PCAP（记录边界被刻意跨越）。"""
    stream = build_tlcp_demo_stream()
    total = len(stream)
    cuts = [0, total // 4, total // 2, (3 * total) // 4, total]
    frames = []
    seq = 1
    for i in range(4):
        segment = stream[cuts[i] : cuts[i + 1]]
        frames.append(build_ethernet_ipv4_tcp("192.0.2.10", "192.0.2.20", 50000, 4433, seq, 1, segment))
        seq += len(segment)
    return write_pcap(frames)
