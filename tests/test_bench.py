"""bench 冒烟测试：保证基准脚本可运行且产出正数（tiny 模式，数秒内完成）。"""

from __future__ import annotations

from gmscope.bench import BenchResult, run_bench


def test_bench_tiny_runs():
    results = run_bench(quick=True, tiny=True)
    assert results, "基准结果不应为空"
    assert all(isinstance(r, BenchResult) for r in results)
    assert all(r.value > 0 for r in results)
    assert any(r.name.startswith("SM3") for r in results)
    assert any(r.name.startswith("SM4-GCM") for r in results)
    assert any(r.name.startswith("SM2") for r in results)
