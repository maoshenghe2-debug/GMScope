"""报告渲染：单文件 HTML（离线 / 打印友好）与 Markdown 差距分析报告。"""

from __future__ import annotations

import copy
import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

_TEMPLATES = Path(__file__).resolve().parent / "templates"

# 2πr（r = 40，viewBox 100×100）——用于环形图 stroke-dasharray
_RING_CIRCUMFERENCE = 251.327

_RISK_LABEL = {"high": "高", "medium": "中", "low": "低"}
_VERDICT_CLASS = {"符合": "ok", "部分符合": "warn", "不符合": "bad", "不适用": "na"}


def _build_view(report: dict) -> dict:
    """构造模板视图模型：环形图参数 / 徽章样式 / 按层面分组 / 内嵌原始 JSON。"""
    view = copy.deepcopy(report)

    for layer in view["summary"]["layers"]:
        score = layer.get("score")
        layer["ring_dash"] = round(_RING_CIRCUMFERENCE * (score or 0) / 100, 1)
        layer["score_text"] = "—" if score is None else f"{score:g}"

    for finding in view["findings"]:
        finding["risk_label"] = _RISK_LABEL.get(finding["risk"], finding["risk"])
        finding["verdict_class"] = _VERDICT_CLASS.get(finding["verdict"], "na")
        finding["default_open"] = finding["verdict"] in ("不符合", "部分符合")

    for item in view.get("source_scan", {}).get("findings", []):
        item["risk_label"] = _RISK_LABEL.get(item["risk"], item["risk"])

    view["layers_view"] = [
        {**layer, "findings": [f for f in view["findings"] if f["layer"] == layer["key"]]}
        for layer in view["summary"]["layers"]
    ]
    view["raw_json"] = json.dumps(
        {
            "target": view["target"],
            "summary": view["summary"],
            "findings": view["findings"],
            "meta": view["meta"],
        },
        ensure_ascii=False,
        indent=2,
    )
    return view


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATES)),
        autoescape=select_autoescape(enabled_extensions=("html", "xml")),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_html(report: dict) -> str:
    """渲染单文件 HTML 报告（无外部资源，离线可开，打印友好）。"""
    return _env().get_template("report.html.j2").render(r=_build_view(report))


def render_markdown(report: dict) -> str:
    """渲染 Markdown 差距分析报告。"""
    return _env().get_template("report.md.j2").render(r=_build_view(report))
