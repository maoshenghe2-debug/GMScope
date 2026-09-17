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
        except Exception:  # noqa: BLE001 —— 老环境/特殊流不支持 reconfigure 时静默跳过
            pass


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
def demo() -> None:
    """离线一键演示：标准向量自检 + 交叉验证 + 下一步指引（无需网络）。"""
    console.rule("[bold]GMScope 离线演示[/bold]")
    results = run_selftest()
    passed = sum(1 for r in results if r.passed)
    console.print(f"① 标准向量自检：通过 {passed}/{len(results)}（GM/T 0002/0004）")
    xr = run_crosscheck(n=16)
    for r in xr:
        state = "跳过" if r.cases == 0 else ("一致" if r.ok else "不一致")
        mark = "[green]" if r.ok else "[yellow]" if r.cases == 0 else "[red]"
        console.print(f"   ② 交叉验证 · {r.engine} {r.algorithm}：{mark}{state}[/]({r.matched}/{r.cases})")
    console.print("③ 下一步（v0.2.0）：`gmscope parse <pcap>` 协议画像 · `gmscope audit` 密评自查")
    ok = passed == len(results) and all((not r.cases) or r.ok for r in xr)
    if not ok:
        raise typer.Exit(code=1)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
