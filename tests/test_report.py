"""报告渲染测试：HTML 单文件离线 / Markdown / CLI 端到端（audit → report）。"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from gmscope.audit import load_example, run_audit
from gmscope.audit.report import render_html, render_markdown
from gmscope.cli import app


def test_html_is_offline_single_file():
    html = render_html(run_audit(load_example("a")))
    assert "<!DOCTYPE html>" in html
    assert "#1f4e79" in html  # 政务蓝灰主色
    assert 'src="http' not in html and 'href="http' not in html  # 无外部资源
    assert "示例系统 A" in html
    assert "附录 A" in html and "附录 B" in html
    assert "@media print" in html


def test_html_contains_findings_and_filters():
    html = render_html(run_audit(load_example("b")))
    assert "NET-01" in html and "不符合" in html
    assert 'data-filter="不符合"' in html
    assert 'data-verdict="不符合"' in html
    assert "风险：高" in html


def test_markdown_report():
    md = render_markdown(run_audit(load_example("a")))
    assert md.startswith("# ")
    assert "总体符合度" in md
    assert "PHY-01" in md
    assert "| 层面 | 得分 |" in md


def test_cli_audit_and_report_roundtrip(tmp_path):
    runner = CliRunner()
    json_out = tmp_path / "report.json"
    result = runner.invoke(app, ["audit", "--example", "a", "-f", "json", "-o", str(json_out)])
    assert result.exit_code == 0, result.output
    data = json.loads(json_out.read_text(encoding="utf-8"))
    assert data["summary"]["overall_score"] >= 90

    html_out = tmp_path / "report.html"
    result = runner.invoke(app, ["report", str(json_out), "-f", "html", "-o", str(html_out)])
    assert result.exit_code == 0, result.output
    assert "示例系统 A" in html_out.read_text(encoding="utf-8")

    md_out = tmp_path / "b.md"
    result = runner.invoke(app, ["audit", "--example", "b", "-f", "md", "-o", str(md_out)])
    assert result.exit_code == 0, result.output
    assert "不符合" in md_out.read_text(encoding="utf-8")


def test_cli_audit_requires_input():
    runner = CliRunner()
    result = runner.invoke(app, ["audit"])
    assert result.exit_code == 2
