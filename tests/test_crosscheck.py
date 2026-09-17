"""交叉验证测试：与 gmssl / cryptography 对照（依赖不可用时自动跳过）。"""

from __future__ import annotations

import pytest

from gmscope.crosscheck import (
    crosscheck_sm2_gmssl,
    crosscheck_sm3_cryptography,
    crosscheck_sm3_gmssl,
    crosscheck_sm4_cryptography,
    crosscheck_sm4_gcm_cryptography,
    crosscheck_sm4_gmssl,
    run_crosscheck,
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


def test_sm4_gcm_vs_cryptography():
    _assert_all_matched(crosscheck_sm4_gcm_cryptography(16))


def test_sm2_vs_gmssl():
    """SM2 五项对照。回归背景：gmssl 侧必须显式 mode=1（C1C3C2），
    否则加解密步骤密文顺序错位（gmssl 默认 C1C2C3），C3 校验将失败。"""
    _assert_all_matched(crosscheck_sm2_gmssl(4))


def test_run_crosscheck_full_set_ok():
    """全量交叉验证入口冒烟（`gmscope crosscheck` / `gmscope demo` 同路径）。"""
    results = run_crosscheck(n=4)
    assert len(results) == 6
    for r in results:
        if r.cases == 0:
            continue
        assert r.ok, f"{r.engine} {r.algorithm}: {r.matched}/{r.cases} — {r.note}"
