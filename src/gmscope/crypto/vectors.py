"""标准测试向量集（来自公开标准的附录示例）。

来源标注：
- SM3：GM/T 0004-2012 / GB/T 32905-2016 附录 A 示例
- SM4：GM/T 0002-2012 / GB/T 32907-2016 附录 A 示例

说明：向量仅收录标准文档公开示例，用于自检（``gmscope selftest``）与回归测试。
"""

from __future__ import annotations

SM3_VECTORS = [
    {
        "name": 'SM3("abc")',
        "source": "GM/T 0004 附录 A 示例 1",
        "input": b"abc",
        "digest": "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
    },
    {
        "name": 'SM3("abcd" × 16)',
        "source": "GM/T 0004 附录 A 示例 2",
        "input": b"abcd" * 16,
        "digest": "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
    },
]

SM4_VECTORS = [
    {
        "name": "SM4-ECB 单分组",
        "source": "GM/T 0002 附录 A 示例 1",
        "key": "0123456789abcdeffedcba9876543210",
        "plain": "0123456789abcdeffedcba9876543210",
        "cipher": "681edf34d206965e86b3e94f536e4246",
    },
]

SM4_SLOW_VECTORS = [
    {
        "name": "SM4-ECB 密钥明文循环加密 ×1,000,000 次",
        "source": "GM/T 0002 附录 A 示例 2",
        "key": "0123456789abcdeffedcba9876543210",
        "plain": "0123456789abcdeffedcba9876543210",
        "cipher": "595298c7c6fd271f0402f804c33d3f66",
    },
]
