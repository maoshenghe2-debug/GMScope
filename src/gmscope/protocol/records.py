"""TLCP/TLS 记录层与握手消息拆分（离线字节流；RFC 5246 / GB/T 38636 结构）。"""

from __future__ import annotations

from dataclasses import dataclass

from .constants import CONTENT_TYPES

_RECORD_HEADER = 5
_HANDSHAKE_HEADER = 4


@dataclass
class TLSRecord:
    index: int
    content_type: int
    version: int
    length: int
    payload: bytes

    @property
    def content_type_name(self) -> str:
        return CONTENT_TYPES.get(self.content_type, f"unknown({self.content_type})")


@dataclass
class HandshakeMessage:
    type: int
    length: int
    body: bytes


def parse_records(data: bytes, max_records: int = 512) -> tuple[list[TLSRecord], list[str]]:
    """按记录层拆分字节流。返回 ``(记录列表, 警告列表)``；截断时给出警告并停止。"""
    records: list[TLSRecord] = []
    warnings: list[str] = []
    offset = 0
    total = len(data)
    while offset + _RECORD_HEADER <= total:
        if len(records) >= max_records:
            warnings.append(f"记录数超过上限 {max_records}，剩余数据未解析")
            break
        content_type = data[offset]
        version = int.from_bytes(data[offset + 1 : offset + 3], "big")
        length = int.from_bytes(data[offset + 3 : offset + 5], "big")
        body_start = offset + _RECORD_HEADER
        body_end = body_start + length
        if body_end > total:
            warnings.append(f"第 {len(records)} 条记录被截断：声明 {length} 字节，剩余 {total - body_start} 字节")
            break
        records.append(
            TLSRecord(
                index=len(records),
                content_type=content_type,
                version=version,
                length=length,
                payload=bytes(data[body_start:body_end]),
            )
        )
        offset = body_end
    if offset < total and not warnings:
        warnings.append(f"流尾部残留 {total - offset} 字节（不足一条记录头）")
    return records, warnings


def parse_handshake_stream(data: bytes) -> tuple[list[HandshakeMessage], bytes]:
    """解析（明文）握手消息流。返回 ``(消息列表, 未解析的剩余字节)``。"""
    messages: list[HandshakeMessage] = []
    offset = 0
    total = len(data)
    while offset + _HANDSHAKE_HEADER <= total:
        msg_type = data[offset]
        length = int.from_bytes(data[offset + 1 : offset + _HANDSHAKE_HEADER], "big")
        body_start = offset + _HANDSHAKE_HEADER
        body_end = body_start + length
        if body_end > total:
            break
        messages.append(
            HandshakeMessage(type=msg_type, length=length, body=bytes(data[body_start:body_end]))
        )
        offset = body_end
    return messages, bytes(data[offset:])
