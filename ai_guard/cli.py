"""Command-line interface for KynSec AI Guard."""

from __future__ import annotations

from collections.abc import Callable
from enum import Enum, IntEnum
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn
from rich.text import Text

from ai_guard import __version__
from ai_guard.core.engine import Engine, ScanError, ScanResult
from ai_guard.core.reporter import (
    render_rule_catalog,
    render_table,
    table_to_string,
    to_json,
    to_sarif,
)
from ai_guard.rules import Severity


class OutputFormat(str, Enum):
    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"


class ExitCode(IntEnum):
    OK = 0
    FINDINGS = 1
    ERROR = 2


app = typer.Typer(
    name="ai-guard",
    help=(
        "Audit local AI agent configurations, MCP servers, prompt files, and LLM "
        "deployment configuration for security risks."
    ),
    no_args_is_help=True,
    add_completion=False,
)
stdout = Console()
stderr = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"KynSec AI Guard {__version__}")
        raise typer.Exit(code=ExitCode.OK)


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the AI-Guard version and exit.",
    ),
) -> None:
    """KynSec AI Guard - security auditing for the local AI stack."""


@app.command()
def scan(
    path: Path = typer.Argument(
        ...,
        exists=True,
        readable=True,
        help="File or directory to scan.",
    ),
    min_severity: Severity = typer.Option(
        Severity.INFO,
        "--min-severity",
        "-s",
        case_sensitive=False,
        help="Only report findings at or above this severity.",
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.TABLE,
        "--format",
        "-f",
        case_sensitive=False,
        help="Report format: table, json, or sarif.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write the report to a file instead of stdout.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show evidence, remediation, and references for each finding.",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Disable the progress bar.",
    ),
) -> None:
    """Scan a file or directory for AI agent security issues.

    Exit codes: 0 = no findings, 1 = findings at or above --min-severity,
    2 = operational error.
    """

    engine = Engine()
    _run_scan(
        engine.scan,
        target=path,
        min_severity=min_severity,
        output_format=output_format,
        output=output,
        verbose=verbose,
        quiet=quiet,
    )


@app.command("audit-mcp")
def audit_mcp(
    config_path: Path = typer.Argument(
        ...,
        exists=True,
        readable=True,
        help="MCP configuration file or directory to audit.",
    ),
    min_severity: Severity = typer.Option(
        Severity.INFO,
        "--min-severity",
        "-s",
        case_sensitive=False,
        help="Only report findings at or above this severity.",
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.TABLE,
        "--format",
        "-f",
        case_sensitive=False,
        help="Report format: table, json, or sarif.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write the report to a file instead of stdout.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show evidence, remediation, and references for each finding.",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Disable the progress bar.",
    ),
) -> None:
    """Run the specialized MCP server security audit.

    This command focuses on MCP command execution, network exposure,
    auto-approval, container escape, supply-chain, secret, and path rules.
    """

    engine = Engine()
    _run_scan(
        engine.audit_mcp,
        target=config_path,
        min_severity=min_severity,
        output_format=output_format,
        output=output,
        verbose=verbose,
        quiet=quiet,
    )


@app.command("rules")
def rules() -> None:
    """List the built-in security rules."""

    render_rule_catalog(stdout)


def _run_scan(
    scan_callable: Callable[..., ScanResult],
    *,
    target: Path,
    min_severity: Severity,
    output_format: OutputFormat,
    output: Path | None,
    verbose: bool,
    quiet: bool,
) -> None:
    progress_enabled = not quiet and output_format is OutputFormat.TABLE
    result: ScanResult | None = None

    if quiet:
        try:
            result = scan_callable(target, min_severity=min_severity)
        except ScanError as exc:
            _fail(str(exc))
    elif progress_enabled:
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            console=stderr,
            transient=True,
        )
        with progress:
            task = progress.add_task("Scanning AI configuration", total=None)

            def _on_progress(done: int, total: int, current: str | None) -> None:
                progress.update(task, total=total, completed=done)

            try:
                result = scan_callable(
                    target,
                    min_severity=min_severity,
                    on_progress=_on_progress,
                )
            except ScanError as exc:
                progress.stop()
                _fail(str(exc))
    else:
        try:
            result = scan_callable(target, min_severity=min_severity)
        except ScanError as exc:
            _fail(str(exc))

    if result is None:  # pragma: no cover - defensive
        _fail("Scan produced no result.")

    _render_result(
        result,
        output_format=output_format,
        output=output,
        verbose=verbose,
    )

    if result.has_findings:
        raise typer.Exit(code=ExitCode.FINDINGS)
    raise typer.Exit(code=ExitCode.OK)


def _render_result(
    result: ScanResult,
    *,
    output_format: OutputFormat,
    output: Path | None,
    verbose: bool,
) -> None:
    if output_format is OutputFormat.TABLE:
        if output is None or str(output) == "-":
            render_table(result, stdout, verbose=verbose)
        else:
            _write_file(output, table_to_string(result, verbose=verbose))
            stderr.print(Text(f"Table report written to {output}", style="green"))
        return

    content = to_json(result) if output_format is OutputFormat.JSON else to_sarif(result)
    if output is None or str(output) == "-":
        typer.echo(content, nl=False)
    else:
        _write_file(output, content)
        stderr.print(
            Text(
                f"{output_format.value.upper()} report written to {output}",
                style="green",
            )
        )


def _write_file(path: Path, content: str) -> None:
    try:
        if path.parent and not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        _fail(f"Unable to write report to {path}: {exc}")


def _fail(message: str) -> None:
    stderr.print(Text(f"Error: {message}", style="bold red"))
    raise typer.Exit(code=ExitCode.ERROR)


if __name__ == "__main__":  # pragma: no cover
    app()
