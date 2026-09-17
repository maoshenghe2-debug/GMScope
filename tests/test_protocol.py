"""TLCP 解析测试：合成样本 / PCAP 往返 / 截断与异常输入。"""

from __future__ import annotations

from gmscope.protocol.constants import TLCP_VERSION
from gmscope.protocol.fixtures import build_tlcp_demo_pcap, build_tlcp_demo_stream
from gmscope.protocol.pcap import extract_tcp_payloads, read_pcap, write_pcap
from gmscope.protocol.records import parse_records
from gmscope.protocol.tlcp import analyze_tlcp


def test_demo_stream_structure():
    stream = build_tlcp_demo_stream()
    records, warnings = parse_records(stream)
    assert not warnings
    assert [r.content_type for r in records] == [22, 22, 22, 22, 22, 20, 22]
    assert all(r.version == TLCP_VERSION for r in records)


def test_analyze_finds_tlcp_handshake():
    analysis = analyze_tlcp(build_tlcp_demo_stream())
    summary = analysis["summary"]
    assert summary["is_tlcp"] is True
    assert summary["negotiated_cipher_suite"] == "0xE051"
    assert summary["negotiated_cipher_suite_name"] == "ECDHE_SM4_GCM_SM3"
    assert "0xE011" in summary["offered_cipher_suites"]
    assert "0xE053" in summary["offered_cipher_suites"]
    assert summary["dual_certificate"] is True
    assert summary["certificate_count"] == 2
    assert summary["handshake_count"] == 5
    assert summary["encrypted_record_count"] == 1

    certs = next(h for h in analysis["handshake"] if h["type"] == "certificate")["certificates"]
    assert len(certs) == 2
    assert all(c["has_sm2_oid"] for c in certs)
    assert certs[0]["sm3"] != certs[1]["sm3"]
    assert not analysis["warnings"]


def test_pcap_roundtrip_and_extract():
    pcap = build_tlcp_demo_pcap()
    frames = read_pcap(pcap)
    assert len(frames) == 4
    stream = extract_tcp_payloads(frames)
    assert stream == build_tlcp_demo_stream()
    analysis = analyze_tlcp(stream)
    assert analysis["summary"]["negotiated_cipher_suite_name"] == "ECDHE_SM4_GCM_SM3"


def test_write_pcap_roundtrip_trivial():
    frame = bytes(range(60))
    assert read_pcap(write_pcap([frame])) == [frame]


def test_truncated_record_warns_without_crash():
    stream = build_tlcp_demo_stream()
    records, warnings = parse_records(stream[:40])  # 截断在首条记录中部
    assert warnings
    analysis = analyze_tlcp(stream[:40])
    assert analysis["summary"]["record_count"] == len(records)
    assert analysis["warnings"]


def test_non_tlcp_flagged():
    # 国际 TLS 1.2（0x0303）的最小 ClientHello
    body = b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x00\x2f" + b"\x01\x00" + b"\x00\x00"
    msg = bytes([1]) + len(body).to_bytes(3, "big") + body
    record = bytes([22, 0x03, 0x03]) + len(msg).to_bytes(2, "big") + msg
    analysis = analyze_tlcp(record)
    assert analysis["summary"]["is_tlcp"] is False
    assert any("TLCP" in w for w in analysis["warnings"])


def test_certificate_parse_edge_cases():
    # 空证书体 / 声明长度不一致时的健壮性
    analysis = analyze_tlcp(build_tlcp_demo_stream())
    cert_msg = next(m for m in analysis["handshake"] if m["type"] == "certificate")
    assert cert_msg["declared_total"] > 0
    for cert in cert_msg["certificates"]:
        assert cert["length"] > 0
        assert len(cert["sm3"]) == 64
