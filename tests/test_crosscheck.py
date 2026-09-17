"""交叉验证测试：与 gmssl / cryptography 对照（依赖不可用时自动跳过）。"""

from __future__ import annotations

import pytest

from gmscope.crosscheck import (
    crosscheck_sm3_cryptography,
    crosscheck_sm3_gmssl,
    crosscheck_sm4_cryptography,
    crosscheck_sm4_gmssl,
)


def _assert_all_matched(result):
    if result.cases == 0:
        pytest.skip(result.note or "依赖不可用")
    assert result.matched == result.cases, f"{result.engine} {result.algorithm}: {result.matched}/{result.cases} 通过"


def test_sm3_vs_gmssl():
    _assert_all_matched(crosscheck_sm3_gmssl(32))


def test_sm3_vs_cryptography():
    _assert_all_matched(crosscheck_sm3_cryptography(32))


def test_sm4_vs_gmssl():
    _assert_all_matched(crosscheck_sm4_gmssl(32))


def test_sm4_vs_cryptography():
    _assert_all_matched(crosscheck_sm4_cryptography(16))
