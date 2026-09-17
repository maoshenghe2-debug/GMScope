"""GMScope 命令行入口。"""

from __future__ import annotations

import json as jsonlib
import sys

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .crosscheck import run_crosscheck
from .selftest import run_selftest


def _configure_stdio() -> None:
    """重定向场景（CI / 管道）下强制 UTF-8 输出。

    Windows 运行器默认代码页（cp1252/cp936）无法编码中文与框图字符，
    会导致 Rich 输出抛 UnicodeEncodeError；交互式控制台不受影响
    （Rich 在真控制台上走 Windows API 渲染）。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream is not None and not stream.isatty():
                stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            # 老环境/特殊流不支持 reconfigure 时静默跳过（如 pythonw、已关闭的管道）
            continue


_configure_stdio()

app = typer.Typer(
    help="GMScope · 国密应用安全检测与协议分析平台（SM2/SM3/SM4 · TLCP · 密评）",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


def _show_version(value: bool) -> None:
    if value:
        console.print(f"gmscope {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: bool = typer.Option(False, "--version", "-V", callback=_show_version, is_eager=True, help="显示版本并退出"),
) -> None:
    """GMScope：国密应用（密评自查）检测工具链。"""


@app.command()
def selftest(
    slow: bool = typer.Option(False, "--slow", help="包含百万次迭代慢速向量（约 1-2 分钟）"),
    as_json: bool = typer.Option(False, "--json", help="以 JSON 输出（便于脚本 / CI 解析）"),
) -> None:
    """运行标准向量自检（GM/T 0002 / GM/T 0004）。"""
    results = run_selftest(include_slow=slow)
    passed = sum(1 for r in results if r.passed)

    if as_json:
        payload = {
            "tool": "gmscope",
            "version": __version__,
            "total": len(results),
            "passed": passed,
            "results": [
                {"name": r.name, "source": r.source, "passed": r.passed, "detail": r.detail} for r in results
            ],
        }
        console.print_json(jsonlib.dumps(payload, ensure_ascii=False))
    else:
        table = Table(title=f"GMScope 标准向量自检 · v{__version__}")
        table.add_column("向量", style="cyan", no_wrap=True)
        table.add_column("来源", style="dim")
        table.add_column("结果", justify="center")
        table.add_column("详情", style="red")
        for r in results:
            mark = "[green]✔ 通过[/green]" if r.passed else "[red]✘ 失败[/red]"
            table.add_row(r.name, r.source, mark, r.detail)
        console.print(table)
        status = "[green]全部通过[/green]" if passed == len(results) else "[red]存在失败[/red]"
        console.print(f"通过 {passed}/{len(results)} — {status}")

    if passed != len(results):
        raise typer.Exit(code=1)


@app.command()
def crosscheck(
    cases: int = typer.Option(64, "--cases", "-n", min=1, max=1000, help="每个算法/库的随机用例数"),
    as_json: bool = typer.Option(False, "--json", help="以 JSON 输出"),
) -> None:
    """与 gmssl / cryptography 交叉验证（随机用例批量比对）。"""
    results = run_crosscheck(n=cases)

    if as_json:
        payload = {
            "tool": "gmscope",
            "version": __version__,
            "results": [
                {"engine": r.engine, "algorithm": r.algorithm, "cases": r.cases, "matched": r.matched, "note": r.note}
                for r in results
            ],
        }
        console.print_json(jsonlib.dumps(payload, ensure_ascii=False))
    else:
        table = Table(title=f"GMScope 交叉验证（每项 {cases} 用例）· v{__version__}")
        table.add_column("对照库", style="cyan")
        table.add_column("算法/模式")
        table.add_column("用例", justify="right")
        table.add_column("一致", justify="right")
        table.add_column("结论", justify="center")
        table.add_column("备注", style="dim")
        for r in results:
            if r.cases == 0:
                verdict = "[yellow]跳过[/yellow]"
            else:
                verdict = "[green]一致[/green]" if r.ok else "[red]不一致[/red]"
            table.add_row(r.engine, r.algorithm, str(r.cases), str(r.matched), verdict, r.note)
        console.print(table)

    failed = [r for r in results if r.cases > 0 and not r.ok]
    if failed:
        console.print(f"[red]存在不一致：{len(failed)} 项[/red]")
        raise typer.Exit(code=1)


@app.command()
def bench(
    full: bool = typer.Option(False, "--full", help="完整数据集（时长约为默认的 8 倍）"),
    as_json: bool = typer.Option(False, "--json", help="以 JSON 输出"),
) -> None:
    """性能基准：SM3 / SM4（ECB/CBC/GCM）/ SM2，含参考库对照。"""
    from .bench import run_bench

    results = run_bench(quick=not full)
    if as_json:
        payload = {
            "tool": "gmscope",
            "version": __version__,
            "results": [
                {
                    "name": r.name,
                    "impl": r.impl,
                    "value": round(r.value, 3),
                    "unit": r.unit,
                    "detail": r.detail,
                }
                for r in results
            ],
        }
        console.print_json(jsonlib.dumps(payload, ensure_ascii=False))
    else:
        table = Table(title=f"GMScope 性能基准（本库为纯 Python 教学对照实现）· v{__version__}")
        table.add_column("算法", style="cyan")
        table.add_column("实现")
        table.add_column("数值", justify="right")
        table.add_column("明细", style="dim")
        for r in results:
            table.add_row(r.name, r.impl, f"{r.value:.2f} {r.unit}", r.detail)
        console.print(table)


@app.command()
def parse(
    path: str = typer.Argument(..., help="PCAP 文件或原始记录流（.bin）路径"),
    as_json: bool = typer.Option(False, "--json", help="以 JSON 输出完整协议画像"),
    limit: int = typer.Option(512, "--limit", min=1, max=4096, help="最多解析的记录条数"),
) -> None:
    """离线解析 TLCP/TLS 协议画像（记录层 + 握手 + 双证书识别）。"""
    from pathlib import Path

    from .protocol.pcap import extract_tcp_payloads, read_pcap
    from .protocol.tlcp import analyze_tlcp

    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        console.print(f"[red]无法读取 {path}：{exc}[/red]")
        raise typer.Exit(code=2) from exc

    if raw[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        frames = read_pcap(raw)
        stream = extract_tcp_payloads(frames)
        source = f"PCAP：{len(frames)} 帧 → TCP 载荷 {len(stream)} 字节（按捕获顺序拼接）"
    else:
        stream = raw
        source = f"原始记录流：{len(stream)} 字节"

    analysis = analyze_tlcp(stream, max_records=limit)

    if as_json:
        payload = {"tool": "gmscope", "version": __version__, "source": source, **analysis}
        console.print_json(jsonlib.dumps(payload, ensure_ascii=False))
    else:
        summary = analysis["summary"]
        console.rule("[bold]TLCP 协议画像[/bold]")
        console.print(f"来源：{source}")
        if summary["is_tlcp"]:
            console.print("[green]判定：TLCP 流量（0x0101）[/green]")
        else:
            console.print("[yellow]判定：非 TLCP（未发现 0x0101 版本号）[/yellow]")
        console.print(
            f"记录 {summary['record_count']} 条 · 握手消息 {summary['handshake_count']} 条 · "
            f"加密记录 {summary['encrypted_record_count']} 条"
        )
        if summary["negotiated_cipher_suite"]:
            console.print(f"协商套件：{summary['negotiated_cipher_suite']}（{summary['negotiated_cipher_suite_name']}）")
        if summary["offered_cipher_suites"]:
            console.print(f"客户端提供：{', '.join(summary['offered_cipher_suites'])}")
        dual = "是（签名证书 + 加密证书）" if summary["dual_certificate"] else "否"
        console.print(f"双证书：{dual} · 证书数量 {summary['certificate_count']}")

        table = Table(title="握手消息（明文部分）")
        table.add_column("类型", style="cyan", no_wrap=True)
        table.add_column("要点", overflow="fold")
        for h in analysis["handshake"]:
            htype = h["type"]
            if htype == "client_hello":
                detail = f"版本 {h.get('version_name')} · 套件 {len(h.get('cipher_suites', []))} 个"
            elif htype == "server_hello":
                detail = f"版本 {h.get('version_name')} · 选定 {h.get('cipher_suite')}（{h.get('cipher_suite_name')}）"
            elif htype == "certificate":
                certs = h.get("certificates", [])
                sm2 = "SM2 OID 已识别" if certs and all(c.get("has_sm2_oid") for c in certs) else "SM2 OID 未识别"
                detail = f"{len(certs)} 张证书 · {sm2}"
            else:
                detail = f"{h.get('length', '-')} 字节"
            table.add_row(htype, detail)
        console.print(table)

    for warning in analysis["warnings"]:
        console.print(f"[yellow]⚠ {warning}[/yellow]")


@app.command("tlcp-fixture")
def tlcp_fixture(
    out: str = typer.Argument("tlcp_demo.pcap", help="输出文件路径"),
    raw: bool = typer.Option(False, "--raw", help="输出原始记录流（非 PCAP）"),
) -> None:
    """生成全合成 TLCP 演示样本（离线；用于 parse 上手与演示）。"""
    from pathlib import Path

    from .protocol.fixtures import build_tlcp_demo_pcap, build_tlcp_demo_stream

    data = build_tlcp_demo_stream() if raw else build_tlcp_demo_pcap()
    Path(out).write_bytes(data)
    console.print(f"已生成 {out}（{len(data)} 字节）— 试用：gmscope parse {out}")


@app.command()
def audit(
    config: str | None = typer.Argument(None, help="系统描述 YAML 路径（或使用 --example 内置示例）"),
    example: str = typer.Option(None, "--example", help="使用内置示例：a（基本合规）/ b（多处违规）"),
    fmt: str = typer.Option("html", "-f", "--format", help="报告格式：html / md / json"),
    out: str = typer.Option(None, "-o", "--out", help="输出路径（默认 report.<fmt>）"),
    scan: str = typer.Option(None, "-d", "--scan", help="可选：附加源码/配置目录弱模式扫描（补充发现）"),
) -> None:
    """密评自查：执行检查项库（72 项）并生成差距分析报告。"""
    from pathlib import Path

    import yaml

    from .audit import load_example
    from .audit.engine import run_audit, run_audit_file
    from .audit.report import render_html, render_markdown

    if example:
        try:
            report_data = run_audit(load_example(example))
        except ValueError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=2) from exc
    elif config:
        try:
            report_data = run_audit_file(config)
        except (OSError, ValueError, yaml.YAMLError) as exc:
            console.print(f"[red]无法读取系统描述：{exc}[/red]")
            raise typer.Exit(code=2) from exc
    else:
        console.print("[red]请提供系统描述 YAML 路径，或使用 --example a|b[/red]")
        raise typer.Exit(code=2)

    if scan:
        from .audit.source_scan import scan_directory

        try:
            report_data["source_scan"] = scan_directory(scan)
        except OSError as exc:
            console.print(f"[red]目录扫描失败：{exc}[/red]")
            raise typer.Exit(code=2) from exc

    if fmt == "json":
        path = Path(out or "report.json")
        path.write_text(jsonlib.dumps(report_data, ensure_ascii=False, indent=2), encoding="utf-8")
    elif fmt == "md":
        path = Path(out or "report.md")
        path.write_text(render_markdown(report_data), encoding="utf-8")
    elif fmt == "html":
        path = Path(out or "report.html")
        path.write_text(render_html(report_data), encoding="utf-8")
    else:
        console.print(f"[red]未知格式：{fmt}（可选 html / md / json）[/red]")
        raise typer.Exit(code=2)

    summary = report_data["summary"]
    table = Table(title=f"密评自查 · {report_data['target'].get('name', '未命名系统')} · 简化口径得分 {summary['overall_score']}")
    table.add_column("层面", style="cyan")
    table.add_column("得分", justify="right")
    table.add_column("符合", justify="right")
    table.add_column("部分", justify="right")
    table.add_column("不符合", justify="right")
    table.add_column("不适用", justify="right")
    for layer in summary["layers"]:
        counts = layer["counts"]
        table.add_row(
            layer["name"],
            "—" if layer["score"] is None else f"{layer['score']:g}",
            str(counts["符合"]),
            str(counts["部分符合"]),
            str(counts["不符合"]),
            str(counts["不适用"]),
        )
    console.print(table)
    console.print(
        f"风险项：高 {summary['risk_counts']['high']} · 中 {summary['risk_counts']['medium']} · "
        f"低 {summary['risk_counts']['low']} → 报告已写入 [bold]{path}[/bold]"
    )
    if report_data.get("source_scan"):
        scan_info = report_data["source_scan"]
        console.print(f"源码扫描：{scan_info['files_scanned']} 个文件 · 命中 {len(scan_info['findings'])} 处（补充发现，需人工复核）")


@app.command()
def report(
    source: str = typer.Argument(..., help="audit --format json 产出的报告 JSON 路径"),
    fmt: str = typer.Option("html", "-f", "--format", help="渲染格式：html / md"),
    out: str = typer.Option(None, "-o", "--out", help="输出路径"),
) -> None:
    """由报告 JSON 重新渲染 HTML / Markdown（可归档、可再分发）。"""
    from pathlib import Path

    from .audit.report import render_html, render_markdown

    try:
        report_data = jsonlib.loads(Path(source).read_text(encoding="utf-8"))
    except (OSError, jsonlib.JSONDecodeError) as exc:
        console.print(f"[red]无法读取报告 JSON：{exc}[/red]")
        raise typer.Exit(code=2) from exc

    if fmt == "html":
        path = Path(out or "report.html")
        path.write_text(render_html(report_data), encoding="utf-8")
    elif fmt == "md":
        path = Path(out or "report.md")
        path.write_text(render_markdown(report_data), encoding="utf-8")
    else:
        console.print(f"[red]未知格式：{fmt}（可选 html / md）[/red]")
        raise typer.Exit(code=2)
    console.print(f"报告已写入 [bold]{path}[/bold]")


@app.command()
def demo() -> None:
    """离线一键演示：标准向量自检 + 交叉验证 + 协议画像 + 密评自查（无需网络）。"""
    console.rule("[bold]GMScope 离线演示[/bold]")
    results = run_selftest()
    passed = sum(1 for r in results if r.passed)
    console.print(f"① 标准向量自检：通过 {passed}/{len(results)}（GM/T 0002/0004 + 自建 KAT）")
    xr = run_crosscheck(n=16)
    for r in xr:
        state = "跳过" if r.cases == 0 else ("一致" if r.ok else "不一致")
        mark = "[green]" if r.ok else "[yellow]" if r.cases == 0 else "[red]"
        console.print(f"   ② 交叉验证 · {r.engine} {r.algorithm}：{mark}{state}[/]({r.matched}/{r.cases})")
    console.print("③ 试用 TLCP 协议画像：`gmscope tlcp-fixture demo.pcap` → `gmscope parse demo.pcap`（离线）")
    from .audit import load_example
    from .audit.engine import run_audit

    score_a = run_audit(load_example("a"))["summary"]["overall_score"]
    score_b = run_audit(load_example("b"))["summary"]["overall_score"]
    console.print(
        f"④ 密评自查（内置示例）：A {score_a} 分 · B {score_b} 分"
        "（`gmscope audit --example a -o report.html` 生成 HTML 报告）"
    )
    ok = passed == len(results) and all((not r.cases) or r.ok for r in xr)
    if not ok:
        raise typer.Exit(code=1)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
