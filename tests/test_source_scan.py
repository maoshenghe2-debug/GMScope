"""源码弱模式扫描测试：规则命中 / 目录过滤 / 规则完整性 / CLI 集成。"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from gmscope.audit.source_scan import RULES, scan_directory
from gmscope.cli import app


def test_scan_finds_planted_patterns(tmp_path):
    (tmp_path / "app.py").write_text(
        "import hashlib, math\n"
        "h = hashlib.md5(b'x')\n"
        "mode = 'ECB'\n"
        "proto = 'TLSv1.0'\n"
        "r = math.random()\n"
        "password = 'SuperSecret123'\n",
        encoding="utf-8",
    )
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text("crypto.createHash('md5')", encoding="utf-8")

    result = scan_directory(tmp_path)
    ids = {f["rule_id"] for f in result["findings"]}
    assert {"SRC-01", "SRC-04", "SRC-06", "SRC-07", "SRC-08"} <= ids
    files = {f["file"] for f in result["findings"]}
    assert files and all("node_modules" not in f for f in files)
    assert result["files_scanned"] >= 1
    assert result["truncated"] is False


def test_scan_not_a_directory(tmp_path):
    with pytest.raises(NotADirectoryError):
        scan_directory(tmp_path / "missing")


def test_rules_wellformed():
    assert len(RULES) >= 8
    assert len({r.id for r in RULES}) == len(RULES)
    for rule in RULES:
        assert rule.id and rule.title and rule.pattern
        assert rule.risk in ("high", "medium", "low")
        assert rule.advice


def test_cli_audit_with_scan(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "weak.py").write_text("import hashlib\nx = hashlib.md5(b'a')\n", encoding="utf-8")
    out = tmp_path / "r.html"
    runner = CliRunner()
    result = runner.invoke(app, ["audit", "--example", "a", "--scan", str(src), "-o", str(out)])
    assert result.exit_code == 0, result.output
    html = out.read_text(encoding="utf-8")
    assert "源码/配置弱模式扫描" in html
    assert "SRC-01" in html
