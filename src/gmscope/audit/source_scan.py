"""源码 / 配置目录弱密码模式扫描（规则法，密评自查的辅助输入源）。

- 用途：对可获得源码/配置的系统做弱算法与危险模式扫描，作为配置清单判定的
  **补充发现**（需人工复核后再纳入整改计划）；
- 规则：见 ``RULES``（id / 名称 / 正则 / 风险 / 建议），可按项目扩展；
- 限制：纯正则扫描存在误报可能；默认跳过二进制、超大文件与常见依赖目录。
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FINDINGS = 500
_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
    ".idea",
    ".vscode",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
}


@dataclass(frozen=True)
class ScanRule:
    id: str
    title: str
    pattern: str
    risk: str
    advice: str


RULES: tuple[ScanRule, ...] = (
    ScanRule("SRC-01", "弱散列算法 MD5", r"\b[Mm][Dd]5\s*\(", "high", "替换为 SM3（GB/T 32905）"),
    ScanRule("SRC-02", "弱散列算法 SHA-1", r"\bsha1\b|\bSHA-?1\b", "high", "替换为 SM3"),
    ScanRule("SRC-03", "弱对称算法 DES/3DES", r"\b(?:DESede|TDEA|3DES|DES)\b", "high", "替换为 SM4（GB/T 32907）"),
    ScanRule("SRC-04", "ECB 分组模式", r"\bECB\b", "medium", "改用 CBC/GCM 等安全模式"),
    ScanRule("SRC-05", "弱密钥长度 RSA（512/1024）", r"\bRSA[_\s-]?(?:512|1024)\b", "high", "替换为 SM2（256 位，安全强度等效 RSA-3072+）"),
    ScanRule(
        "SRC-06",
        "非密码学安全随机数",
        r"math\.random|Math\.random|new Random\(\)|java\.util\.Random",
        "high",
        "使用密码学安全随机源（国密场景：物理噪声源/密码模块）",
    ),
    ScanRule(
        "SRC-07",
        "疑似硬编码口令/密钥",
        r"(?i)(?:password|passwd|secret|api[_-]?key|access[_-]?key|private[_-]?key)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
        "high",
        "移除硬编码凭据，改用密钥管理系统",
    ),
    ScanRule("SRC-08", "低版本 TLS/SSL 协议", r"TLSv1\.0|TLSv1\.1|SSLv3|SSLv2|PROTOCOL_SSLv3", "medium", "启用 TLCP 并停用低版本协议"),
    ScanRule("SRC-09", "非国密 TLS 套件/算法常量", r"ECDHE_RSA|AES_128_GCM|AES_256_GCM|CHACHA20", "low", "评估替换为国密套件（SM4-GCM 等）"),
    ScanRule("SRC-10", "明文口令存放线索", r"明文(?:口令|密码)", "medium", "口令应加盐杂凑（SM3）后存储"),
)


@dataclass
class ScanFinding:
    rule_id: str
    title: str
    risk: str
    advice: str
    file: str
    line: int
    evidence: str


def _iter_files(root: Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def scan_directory(root: str | Path, max_findings: int = MAX_FINDINGS) -> dict:
    """扫描目录，返回 ``{root, files_scanned, rules, findings[], truncated}``。"""
    root = Path(root)
    if not root.is_dir():
        raise NotADirectoryError(f"不是目录：{root}")
    compiled = [(rule, re.compile(rule.pattern)) for rule in RULES]
    findings: list[ScanFinding] = []
    files_scanned = 0
    truncated = False

    for path in _iter_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "\x00" in text[:1024]:  # 二进制粗判
            continue
        files_scanned += 1
        for lineno, line in enumerate(text.splitlines(), start=1):
            for rule, rx in compiled:
                if rx.search(line):
                    findings.append(
                        ScanFinding(
                            rule_id=rule.id,
                            title=rule.title,
                            risk=rule.risk,
                            advice=rule.advice,
                            file=str(path.relative_to(root)),
                            line=lineno,
                            evidence=line.strip()[:160].replace("|", "¦"),
                        )
                    )
                    if len(findings) >= max_findings:
                        truncated = True
                        break
            if truncated:
                break
        if truncated:
            break

    return {
        "root": str(root),
        "files_scanned": files_scanned,
        "rules": len(RULES),
        "findings": [asdict(f) for f in findings],
        "truncated": truncated,
    }
