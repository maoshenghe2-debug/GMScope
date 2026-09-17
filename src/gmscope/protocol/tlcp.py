"""TLCP 协议画像：记录层 + 握手 + 双证书识别的一体化分析（离线）。

约定：
- 只解析**首个 ChangeCipherSpec 之前**的明文握手记录（之后为加密记录，仅计数）；
- 不做 TCP 重组（调用方负责按流提供字节序列，PCAP 提取按捕获顺序拼接）；
- 输出均为 JSON 可序列化结构，供 CLI ``gmscope parse`` 与测试使用。
"""

from __future__ import annotations

from .constants import HANDSHAKE_TYPES, TLCP_CIPHER_SUITES, version_name
from .handshake import parse_certificate, parse_client_hello, parse_server_hello
from .records import parse_handshake_stream, parse_records


def analyze_tlcp(data: bytes, max_records: int = 512) -> dict:
    """对原始字节流做 TLCP/TLS 协议画像分析。"""
    records, warnings = parse_records(data, max_records=max_records)

    plain_handshake = bytearray()
    encrypted_records = 0
    ccs_seen = False
    for r in records:
        if r.content_type == 20:  # change_cipher_spec
            ccs_seen = True
            continue
        if r.content_type == 22:  # handshake
            if ccs_seen:
                encrypted_records += 1
            else:
                plain_handshake += r.payload

    messages, leftover = parse_handshake_stream(bytes(plain_handshake))
    if leftover:
        warnings.append(f"握手流残留 {len(leftover)} 字节未能解析为完整消息")

    offered_suites: list[int] = []
    negotiated: int | None = None
    cert_count = 0
    handshake_out: list[dict] = []
    for m in messages:
        if m.type == 1:
            info = parse_client_hello(m.body)
            for s in info.get("cipher_suites", []):
                offered_suites.append(int(s, 16))
            handshake_out.append({"type": "client_hello", **info})
        elif m.type == 2:
            info = parse_server_hello(m.body)
            if "cipher_suite" in info:
                negotiated = int(info["cipher_suite"], 16)
            handshake_out.append({"type": "server_hello", **info})
        elif m.type == 11:
            info = parse_certificate(m.body)
            cert_count = len(info.get("certificates", []))
            handshake_out.append({"type": "certificate", **info})
        else:
            handshake_out.append({"type": HANDSHAKE_TYPES.get(m.type, f"unknown({m.type})"), "length": m.length})

    versions = sorted({r.version for r in records})
    handshake_versions = [h.get("version") for h in handshake_out if h.get("version")]
    is_tlcp = 0x0101 in versions or "0x0101" in handshake_versions

    summary = {
        "record_count": len(records),
        "handshake_count": len(messages),
        "encrypted_record_count": encrypted_records,
        "versions_seen": [f"0x{v:04x}（{version_name(v)}）" for v in versions],
        "is_tlcp": is_tlcp,
        "negotiated_cipher_suite": f"0x{negotiated:04X}" if negotiated is not None else None,
        "negotiated_cipher_suite_name": None,
        "offered_cipher_suites": [f"0x{s:04X}" for s in dict.fromkeys(offered_suites)],
        "certificate_count": cert_count,
        "dual_certificate": cert_count >= 2,
    }
    if negotiated is not None:
        from .constants import cipher_suite_name

        summary["negotiated_cipher_suite_name"] = cipher_suite_name(negotiated)
        if negotiated not in TLCP_CIPHER_SUITES and is_tlcp:
            warnings.append(f"协商套件 0x{negotiated:04X} 不属于国密套件集合")
    if not is_tlcp:
        warnings.append("未发现 TLCP（0x0101）版本号：可能为国际 TLS 流量")
    if is_tlcp and cert_count == 1:
        warnings.append("证书数量为 1：TLCP 通常使用双证书（签名证书 + 加密证书）")
    if is_tlcp and cert_count == 0:
        warnings.append("未在握手流中发现证书消息")

    records_out = [
        {
            "index": r.index,
            "content_type": r.content_type_name,
            "version": f"0x{r.version:04x}",
            "length": r.length,
        }
        for r in records
    ]
    return {"records": records_out, "handshake": handshake_out, "summary": summary, "warnings": warnings}
