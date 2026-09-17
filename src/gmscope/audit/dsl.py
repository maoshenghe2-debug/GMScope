"""检查项判定 DSL（path/op/value 三态判定）。

三态语义（评审定稿，见 docs/06 §15.5）：
- **符合**：主规则成立；
- **部分符合**：主规则不成立，但 ``partial`` 规则成立；
- **不符合**：主规则与 ``partial`` 规则均不成立；
- **不适用**：``path`` 不存在，或 ``na_when`` 成立（有条件适用项）。

约定：路径为点分键（``a.b.c``，列表可用数字下标）；``value`` 为 DSL 声明值。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

VERDICT_PASS = "符合"
VERDICT_PARTIAL = "部分符合"
VERDICT_FAIL = "不符合"
VERDICT_NA = "不适用"

_MISSING = object()


@dataclass
class Rule:
    path: str
    op: str
    value: Any = None


@dataclass
class CheckLogic:
    rule: Rule
    partial: Rule | None = None
    na_when: Rule | None = None

    @classmethod
    def from_dict(cls, data: dict) -> CheckLogic:
        return cls(
            rule=_rule(data) or Rule("", "truthy"),
            partial=_rule(data.get("partial")),
            na_when=_rule(data.get("na_when")),
        )


def _rule(data: dict | None) -> Rule | None:
    if not data:
        return None
    return Rule(str(data["path"]), str(data["op"]), data.get("value"))


def resolve_path(data: Any, path: str) -> Any:
    """点路径取值；不存在返回哨兵 ``_MISSING``（以区分「缺失」与「值为 None」）。"""
    current = data
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return _MISSING
    return current


def _num(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def eval_op(op: str, actual: Any, expected: Any) -> bool:
    """基础算子求值。actual=系统描述中的实体值；expected=DSL 声明值。"""
    if op == "truthy":
        return bool(actual)
    if op == "falsy":
        return not actual
    if op == "eq":
        return actual == expected
    if op == "ne":
        return actual != expected
    if op == "in":
        return actual in (expected or [])
    if op == "not_in":
        return actual not in (expected or [])
    if op in ("ge", "le", "gt", "lt"):
        a, e = _num(actual), _num(expected)
        if a is None or e is None:
            return False
        return {"ge": a >= e, "le": a <= e, "gt": a > e, "lt": a < e}[op]
    if op == "between":
        lo, hi = (_num(expected[0]), _num(expected[1])) if isinstance(expected, list) and len(expected) == 2 else (None, None)
        a = _num(actual)
        return a is not None and lo is not None and hi is not None and lo <= a <= hi
    if op == "contains_all":
        items = actual if isinstance(actual, (list, tuple, set)) else []
        return bool(expected) and all(v in items for v in expected)
    if op == "contains_any":
        items = actual if isinstance(actual, (list, tuple, set)) else []
        return any(v in items for v in (expected or []))
    if op == "contains_none":
        items = actual if isinstance(actual, (list, tuple, set)) else []
        return not any(v in items for v in (expected or []))
    if op == "regex":
        return isinstance(actual, str) and re.search(str(expected), actual) is not None
    if op == "not_regex":
        return not (isinstance(actual, str) and re.search(str(expected), actual) is not None)
    if op == "startswith":
        return isinstance(actual, str) and actual.startswith(str(expected))
    if op == "endswith":
        return isinstance(actual, str) and actual.endswith(str(expected))
    raise ValueError(f"未知算子：{op}")


@dataclass
class EvalResult:
    verdict: str
    actual: Any = None
    note: str = ""


def evaluate(logic: CheckLogic, data: dict) -> EvalResult:
    """对一份系统描述执行判定，返回三态结果与「现状值」。"""
    if logic.na_when is not None:
        na_actual = resolve_path(data, logic.na_when.path)
        if na_actual is not _MISSING:
            try:
                if eval_op(logic.na_when.op, na_actual, logic.na_when.value):
                    return EvalResult(VERDICT_NA, None, "不适用（na_when 条件成立）")
            except ValueError:
                pass

    actual = resolve_path(data, logic.rule.path)
    if actual is _MISSING:
        return EvalResult(VERDICT_NA, None, f"描述中缺少路径：{logic.rule.path}")
    if isinstance(actual, (dict, list)):
        shown = f"<{type(actual).__name__}>"
    else:
        shown = actual
    try:
        if eval_op(logic.rule.op, actual, logic.rule.value):
            return EvalResult(VERDICT_PASS, shown, "")
        if logic.partial is not None:
            partial_actual = resolve_path(data, logic.partial.path)
            if partial_actual is not _MISSING and eval_op(logic.partial.op, partial_actual, logic.partial.value):
                return EvalResult(VERDICT_PARTIAL, shown, "满足部分条件")
        return EvalResult(VERDICT_FAIL, shown, "")
    except ValueError as exc:
        return EvalResult(VERDICT_NA, shown, str(exc))
