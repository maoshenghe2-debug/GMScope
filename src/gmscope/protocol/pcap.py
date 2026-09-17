"""极简 PCAP 读写与 TCP 载荷提取 / 以太网帧构造（离线分析用）。

说明：
- 支持 libpcap 四种魔数（大小端 × 微秒/纳秒），仅读取帧字节；
- ``extract_tcp_payloads`` 按捕获顺序拼接 TCP 载荷，**不做 TCP 重组**（演示与分析用途）；
- ``build_ethernet_ipv4_tcp`` 用于生成合成样本（正确填写 IPv4 / TCP 校验和，
  产物可用 Wireshark 打开）。
"""

from __future__ import annotations

import struct

_MAGICS_LE = (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
_MAGICS_BE = (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d")


def _checksum16(data: bytes) -> int:
    """RFC 1071 校验和（16 位一组，一补数求和）。"""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _ip_bytes(text: str) -> bytes:
    return bytes(int(part) for part in text.split("."))


def build_ethernet_ipv4_tcp(
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    payload: bytes,
    *,
    src_mac: bytes = bytes.fromhex("020000000001"),
    dst_mac: bytes = bytes.fromhex("020000000002"),
    ttl: int = 64,
) -> bytes:
    """构造一个以太网 + IPv4 + TCP 帧（含正确校验和）。"""
    eth = dst_mac + src_mac + b"\x08\x00"
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, 0x18, 64240, 0, 0) + payload
    pseudo = _ip_bytes(src_ip) + _ip_bytes(dst_ip) + b"\x00\x06" + len(tcp).to_bytes(2, "big")
    tcp_csum = _checksum16(pseudo + tcp)
    tcp = tcp[:16] + struct.pack("!H", tcp_csum) + tcp[18:]
    total_len = 20 + len(tcp)
    ip = (
        struct.pack("!BBHHHBBH", 0x45, 0, total_len, 0x1234, 0x4000, ttl, 6, 0)
        + _ip_bytes(src_ip)
        + _ip_bytes(dst_ip)
    )
    ip_csum = _checksum16(ip)
    ip = ip[:10] + struct.pack("!H", ip_csum) + ip[12:]
    return eth + ip + tcp


def write_pcap(frames: list[bytes]) -> bytes:
    """把帧列表写为经典 libpcap 文件字节（小端、微秒时间戳）。"""
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for index, frame in enumerate(frames, start=1):
        out += struct.pack("<IIII", 1700000000 + index, index * 1000, len(frame), len(frame))
        out += frame
    return bytes(out)


def read_pcap(data: bytes) -> list[bytes]:
    """从 PCAP 字节读取出帧列表（支持四种魔数）。"""
    if len(data) < 24:
        raise ValueError("PCAP 文件过短")
    magic = data[:4]
    if magic in _MAGICS_LE:
        endian = "<"
    elif magic in _MAGICS_BE:
        endian = ">"
    else:
        raise ValueError(f"不支持的 PCAP 魔数：{magic.hex()}")
    frames: list[bytes] = []
    offset = 24
    while offset + 16 <= len(data):
        _, _, incl_len, _ = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if offset + incl_len > len(data):
            break
        frames.append(bytes(data[offset : offset + incl_len]))
        offset += incl_len
    return frames


def extract_tcp_payloads(frames: list[bytes]) -> bytes:
    """按捕获顺序提取并拼接 TCP 载荷（跳过非 IPv4/TCP 帧与空载荷）。"""
    out = bytearray()
    for frame in frames:
        if len(frame) < 34:  # Ethernet(14) + 最小 IPv4(20)
            continue
        if int.from_bytes(frame[12:14], "big") != 0x0800:
            continue
        ip = frame[14:]
        if (ip[0] >> 4) != 4 or ip[9] != 6:  # IPv4 且 TCP
            continue
        ihl = (ip[0] & 0x0F) * 4
        total_len = int.from_bytes(ip[2:4], "big")
        tcp = ip[ihl:total_len] if total_len >= ihl else ip[ihl:]
        if len(tcp) < 20:
            continue
        doff = (tcp[12] >> 4) * 4
        payload = tcp[doff:]
        if payload:
            out += payload
    return bytes(out)
