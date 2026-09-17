"""密评自查引擎测试：DSL 单元 / 示例系统断言 / 报告与 schema 校验。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from gmscope.audit.dsl import (
    VERDICT_FAIL,
    VERDICT_NA,
    VERDICT_PARTIAL,
    VERDICT_PASS,
    CheckLogic,
    eval_op,
    evaluate,
    resolve_path,
)
from gmscope.audit.engine import EXAMPLES, load_checks, load_example, run_audit

REPO = Path(__file__).resolve().parents[1]
SCHEMAS = REPO / "schemas"


def _findings(report: dict) -> dict:
    return {f["check_id"]: f for f in report["findings"]}


# ---------------------------------------------------------------- DSL 单元


def test_resolve_path():
    data = {"a": {"b": [10, 20]}, "c": None}
    assert resolve_path(data, "a.b.1") == 20
    assert resolve_path(data, "c") is None
    assert resolve_path(data, "a.x") is not object  # 缺失返回哨兵（非具体值）


@pytest.mark.parametrize(
    ("op", "actual", "expected", "want"),
    [
        ("truthy", True, None, True),
        ("falsy", False, None, True),
        ("eq", [], [], True),
        ("in", "SM4", ["SM4", "SM3"], True),
        ("not_in", "MD5", ["SM4", "SM3"], True),
        ("ge", 256, 256, True),
        ("le", 60, 30, False),
        ("between", 365, [1, 365], True),
        ("between", 0, [1, 365], False),
        ("contains_all", ["SM4", "SM3"], ["SM4", "SM3"], True),
        ("contains_any", ["TLCP", "TLS1.2"], ["TLCP"], True),
        ("contains_none", [], ["RC4"], True),
        ("regex", "SM2 数字证书", r"SM2", True),
        ("startswith", "IPSEC_SM", "IPSEC", True),
    ],
)
def test_eval_op(op, actual, expected, want):
    assert eval_op(op, actual, expected) is want


def test_evaluate_tristate_and_na():
    data = {"net": {"score": 70, "used": False}}
    logic = CheckLogic.from_dict(
        {
            "path": "net.score",
            "op": "ge",
            "value": 90,
            "partial": {"path": "net.score", "op": "ge", "value": 30},
        }
    )
    assert evaluate(logic, data).verdict == VERDICT_PARTIAL
    logic2 = CheckLogic.from_dict({"path": "net.score", "op": "ge", "value": 90})
    assert evaluate(logic2, data).verdict == VERDICT_FAIL
    logic3 = CheckLogic.from_dict(
        {"path": "net.score", "op": "ge", "value": 90, "na_when": {"path": "net.used", "op": "truthy"}}
    )
    assert evaluate(logic3, data).verdict == VERDICT_FAIL  # na_when 不成立
    assert evaluate(logic3, {"net": {"score": 1, "used": True}}).verdict == VERDICT_NA
    logic4 = CheckLogic.from_dict({"path": "nope.missing", "op": "truthy"})
    assert evaluate(logic4, data).verdict == VERDICT_NA


# ---------------------------------------------------------------- 检查项库


def test_checks_library_quality():
    doc = load_checks()
    items = doc["items"]
    assert len(items) >= 60, "检查项库应不少于 60 项"
    assert len({i["id"] for i in items}) == len(items), "检查项 ID 必须唯一"
    layer_keys = {layer["key"] for layer in doc["layers"]}
    for item in items:
        assert item["std_ref"], f"{item['id']} 缺少标准出处"
        assert item["risk"] in ("high", "medium", "low")
        assert item["layer"] in layer_keys
        assert item["logic"].get("path") and item["logic"].get("op")


# ---------------------------------------------------------------- 示例系统


def test_system_a_mostly_compliant():
    report = run_audit(load_example("a"))
    assert report["summary"]["overall_score"] >= 90
    findings = _findings(report)
    assert findings["PHY-01"]["verdict"] == VERDICT_PASS
    assert findings["NET-04"]["verdict"] == VERDICT_PASS
    assert findings["APP-11"]["verdict"] == VERDICT_PASS
    assert findings["KEY-02"]["verdict"] == VERDICT_PASS
    assert findings["MGT-07"]["verdict"] == VERDICT_PASS
    assert findings["NET-06"]["verdict"] == VERDICT_PARTIAL  # 证书剩余 60 天：部分符合
    assert findings["NET-10"]["verdict"] == VERDICT_NA  # 未使用无线：不适用


def test_system_b_flags_violations():
    report = run_audit(load_example("b"))
    assert report["summary"]["overall_score"] <= 55
    findings = _findings(report)
    for check_id in ("PHY-02", "NET-01", "NET-03", "NET-04", "APP-02", "APP-07", "KEY-01", "KEY-03", "MGT-06"):
        assert findings[check_id]["verdict"] == VERDICT_FAIL, f"{check_id} 应判定为不符合"
    assert findings["NET-06"]["verdict"] == VERDICT_PARTIAL  # 45 天：部分符合
    assert findings["NET-08"]["verdict"] == VERDICT_NA  # 未使用 VPN：不适用
    assert report["summary"]["risk_counts"]["high"] > 0


def test_report_schema_validates():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((SCHEMAS / "audit_report.schema.json").read_text(encoding="utf-8"))
    report = run_audit(load_example("a"))
    jsonschema.validate(report, schema)


def test_examples_match_system_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((SCHEMAS / "system.schema.json").read_text(encoding="utf-8"))
    for key in ("a", "b"):
        data = yaml.safe_load(EXAMPLES[key].read_text(encoding="utf-8"))
        jsonschema.validate(data, schema)
