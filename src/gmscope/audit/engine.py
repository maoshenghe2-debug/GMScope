"""密评自查引擎：加载检查项库与系统描述，执行三态判定并汇总得分。

说明：
- 检查项 DSL 支持两种等价写法：``partial`` / ``na_when`` 既可写在 ``logic`` 内部，
  也可作为 ``logic`` 的同级键（引擎自动合并；内置检查项库使用同级写法）。
- 得分为**简化展示口径**（符合=1、部分符合=0.5、不符合=0、不适用不计），
  非官方量化评估规则；正式密评以测评机构依据 GB/T 39786 / GM/T 0115 的结论为准。
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import yaml

from .. import __version__
from .dsl import (
    VERDICT_FAIL,
    VERDICT_NA,
    VERDICT_PARTIAL,
    VERDICT_PASS,
    CheckLogic,
    evaluate,
)

_HERE = Path(__file__).resolve().parent
CHECKS_PATH = _HERE / "checks_data.yaml"
EXAMPLES = {
    "a": _HERE / "examples" / "system_a.yaml",
    "b": _HERE / "examples" / "system_b.yaml",
}

_ITEM_SCORE = {VERDICT_PASS: 1.0, VERDICT_PARTIAL: 0.5, VERDICT_FAIL: 0.0}
_VERDICTS = (VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL, VERDICT_NA)


def _load_yaml(path: Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise TypeError(f"YAML 内容应为对象：{path}")
    return data


def load_checks(path: Path | None = None) -> dict:
    """加载检查项库（默认内置 ``checks_data.yaml``）。"""
    return _load_yaml(path or CHECKS_PATH)


def load_example(key: str) -> dict:
    """加载内置示例系统描述（``a`` 基本合规 / ``b`` 多处违规）。"""
    if key not in EXAMPLES:
        raise ValueError(f"未知示例：{key}（可选 a / b）")
    return _load_yaml(EXAMPLES[key])


def _score(subset: list[dict]) -> float | None:
    applicable = [f for f in subset if f["verdict"] != VERDICT_NA]
    if not applicable:
        return None
    return round(sum(_ITEM_SCORE[f["verdict"]] for f in applicable) / len(applicable) * 100, 1)


def _counts(subset: list[dict]) -> dict:
    counts = {v: 0 for v in _VERDICTS}
    for f in subset:
        counts[f["verdict"]] += 1
    return counts


def _build_logic(item: dict) -> CheckLogic:
    """构造判定逻辑：合并 ``logic`` 内外两种 partial/na_when 写法。"""
    logic_dict = dict(item.get("logic", {}))
    for extra_key in ("partial", "na_when"):
        if extra_key in item and extra_key not in logic_dict:
            logic_dict[extra_key] = item[extra_key]
    return CheckLogic.from_dict(logic_dict)


def run_audit(system: dict, checks_doc: dict | None = None) -> dict:
    """执行全部检查项，返回 JSON 可序列化的差距分析报告。"""
    doc = checks_doc or load_checks()
    findings: list[dict] = []

    for item in doc.get("items", []):
        result = evaluate(_build_logic(item), system)
        findings.append(
            {
                "check_id": item["id"],
                "layer": item["layer"],
                "title": item["title"],
                "std_ref": item["std_ref"],
                "risk": item["risk"],
                "verdict": result.verdict,
                "actual": result.actual,
                "advice": item.get("advice", ""),
                "note": result.note,
            }
        )

    risk_counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        if f["verdict"] in (VERDICT_FAIL, VERDICT_PARTIAL):
            risk_counts[f["risk"]] = risk_counts.get(f["risk"], 0) + 1

    layers_out = []
    for meta in doc.get("layers", []):
        subset = [f for f in findings if f["layer"] == meta["key"]]
        layers_out.append(
            {
                "key": meta["key"],
                "name": meta["name"],
                "score": _score(subset),
                "counts": _counts(subset),
            }
        )

    return {
        "tool": "gmscope",
        "tool_version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": system.get("system", {}),
        "summary": {
            "overall_score": _score(findings),
            "counts": {**_counts(findings), "total": len(findings)},
            "risk_counts": risk_counts,
            "layers": layers_out,
        },
        "findings": findings,
        "meta": {
            "checks_version": doc.get("meta", {}).get("version", ""),
            "scoring": doc.get("meta", {}).get("scoring", ""),
            "basis": doc.get("meta", {}).get("basis", []),
        },
    }


def run_audit_file(path: Path) -> dict:
    """便捷入口：直接对系统描述 YAML 路径执行自查。"""
    return run_audit(_load_yaml(Path(path)))
