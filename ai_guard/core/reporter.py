"""Terminal, JSON, and SARIF v2.1.0 report generation."""

from __future__ import annotations

import hashlib
import io
import json
from datetime import datetime
from urllib.parse import quote

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ai_guard import __version__
from ai_guard.core.engine import ScanResult
from ai_guard.rules import RuleInfo, Severity, all_rule_info
from ai_guard.rules.base import Finding

SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


def render_table(
    result: ScanResult,
    console: Console,
    *,
    verbose: bool = False,
) -> None:
    """Print a polished human-readable report."""

    console.print(_summary_panel(result))
    if result.errors:
        console.print(_errors_panel(result.errors))

    if not result.findings:
        console.print(
            Panel(
                Text(
                    f"No findings at or above {result.min_severity.value.upper()} "
                    f"in {result.files_scanned} scanned file(s).",
                    style="green",
                ),
                title="Clean scan",
                border_style="green",
            )
        )
    else:
        table = Table(
            title=f"Security findings ({len(result.findings)})",
            title_style="bold",
            header_style="bold cyan",
            show_lines=False,
            expand=True,
        )
        table.add_column("Severity", no_wrap=True, width=9)
        table.add_column("Rule", no_wrap=True, width=12)
        table.add_column("Location", no_wrap=True, overflow="ellipsis", max_width=30)
        table.add_column("Finding", overflow="fold", ratio=1)
        for finding in result.findings:
            table.add_row(
                Text(finding.severity.value.upper(), style=SEVERITY_STYLES[finding.severity]),
                Text(finding.rule_id),
                Text(_location(finding)),
                Text(finding.message),
            )
        console.print(table)

    if verbose and result.findings:
        console.print()
        console.print(Text("Finding details", style="bold"))
        for finding in result.findings:
            console.print(_detail_panel(finding))


def table_to_string(result: ScanResult, *, verbose: bool = False) -> str:
    """Render the terminal report to plain text for ``--output``."""

    buffer = io.StringIO()
    console = Console(
        file=buffer,
        force_terminal=False,
        color_system=None,
        width=120,
        no_color=True,
    )
    render_table(result, console, verbose=verbose)
    return buffer.getvalue()


def to_json(result: ScanResult) -> str:
    """Serialize a scan result to stable machine-readable JSON."""

    payload = {
        "schema_version": "1.0",
        "tool": {"name": "AI-Guard-CLI", "version": __version__},
        "target": result.target,
        "generated_at": result.generated_at.isoformat(),
        "summary": result.summary(),
        "findings": [finding.model_dump(mode="json") for finding in result.findings],
        "rules": [info.model_dump(mode="json") for info in result.rules],
        "parse_error_files": result.parse_error_files,
        "errors": result.errors,
    }
    return json.dumps(payload, indent=2) + "\n"


def to_sarif(result: ScanResult) -> str:
    """Serialize a scan result to SARIF v2.1.0 for GitHub code scanning."""

    rules: list[dict[str, object]] = []
    rule_indexes: dict[str, int] = {}
    for info in result.rules:
        if info.id in rule_indexes:
            continue
        rule_indexes[info.id] = len(rules)
        rules.append(_sarif_rule(info))

    sarif_results: list[dict[str, object]] = []
    for finding in result.findings:
        rule_index = rule_indexes.get(finding.rule_id)
        physical: dict[str, object] = {
            "artifactLocation": {"uri": _artifact_uri(finding.file)},
            "region": {"startLine": finding.line or 1, "startColumn": 1},
        }
        entry: dict[str, object] = {
            "ruleId": finding.rule_id,
            "level": SARIF_LEVEL[finding.severity],
            "message": {"text": finding.message},
            "locations": [{"physicalLocation": physical}],
            "partialFingerprints": {
                "primaryLocationLineHash": _fingerprint(finding),
            },
            "properties": {
                "severity": finding.severity.value,
                "tags": finding.tags,
                **finding.metadata,
            },
        }
        if rule_index is not None:
            entry["ruleIndex"] = rule_index
        sarif_results.append(entry)

    notifications = [
        {
            "level": "warning",
            "message": {"text": f"Configuration could not be parsed: {path}"},
            "descriptor": {"id": "AI-GUARD-000"},
        }
        for path in result.parse_error_files
    ]
    notifications.extend(
        {
            "level": "error",
            "message": {"text": message},
            "descriptor": {"id": "AI-GUARD-000"},
        }
        for message in result.errors
    )

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AI-Guard-CLI",
                        "organization": "KynSec",
                        "version": __version__,
                        "informationUri": "https://github.com/KynSec/AI-Guard-CLI",
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": not result.errors,
                        "startTimeUtc": result.generated_at.isoformat(),
                        "endTimeUtc": _finished_at(result).isoformat(),
                        "toolExecutionNotifications": notifications,
                    }
                ],
                "results": sarif_results,
                "properties": {
                    "summary": result.summary(),
                    "target": result.target,
                },
            }
        ],
    }
    return json.dumps(payload, indent=2) + "\n"


def render_rule_catalog(console: Console) -> None:
    """Print the built-in rule catalog."""

    table = Table(
        title="AI-Guard rule catalog",
        header_style="bold cyan",
        expand=True,
    )
    table.add_column("Rule", no_wrap=True, width=12)
    table.add_column("Severity", no_wrap=True, width=10)
    table.add_column("Title", style="bold")
    table.add_column("Category", no_wrap=True)
    for info in all_rule_info():
        category = info.tags[0] if info.tags else "general"
        table.add_row(
            Text(info.id),
            Text(info.severity.value.upper(), style=SEVERITY_STYLES[info.severity]),
            Text(info.title),
            Text(category),
        )
    console.print(table)


def _summary_panel(result: ScanResult) -> Panel:
    summary = result.summary()
    counts = summary["by_severity"]
    assert isinstance(counts, dict)

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold", no_wrap=True)
    grid.add_column()
    grid.add_row("Target", Text(result.target))
    grid.add_row(
        "Files",
        Text(
            f"{result.files_scanned} scanned"
            + (f", {result.files_skipped} skipped" if result.files_skipped else "")
        ),
    )
    grid.add_row("Findings", Text(str(len(result.findings))))
    if result.files_skipped or result.errors or result.parse_error_files:
        grid.add_row(
            "Warnings",
            Text(
                f"{len(result.parse_error_files)} parse error(s), "
                f"{len(result.errors)} rule error(s), "
                f"{result.files_skipped} skipped file(s)"
            ),
        )

    severity_line = Text()
    for severity in (
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ):
        count = int(counts.get(severity.value, 0))
        if count == 0:
            continue
        if severity_line:
            severity_line.append("  ")
        severity_line.append(
            f"{severity.value.upper()} {count}",
            style=SEVERITY_STYLES[severity],
        )
    if not severity_line:
        severity_line = Text("none", style="dim")
    grid.add_row("By severity", severity_line)

    suppressed = int(summary["findings_suppressed"])
    if suppressed:
        grid.add_row("Suppressed", Text(f"{suppressed} below {result.min_severity.value}"))
    grid.add_row("Duration", Text(f"{result.duration_ms:.0f} ms"))
    grid.add_row("Generated", Text(result.generated_at.isoformat()))

    return Panel(
        grid,
        title="[bold]AI-Guard scan summary[/]",
        border_style="cyan",
    )


def _errors_panel(errors: list[str]) -> Panel:
    text = Text()
    for index, error in enumerate(errors):
        if index:
            text.append("\n")
        text.append(error, style="red")
    return Panel(text, title="Rule execution warnings", border_style="red")


def _detail_panel(finding: Finding) -> Panel:
    body = Text()
    body.append("Rule: ", style="bold")
    body.append(f"{finding.rule_id} - {finding.title}\n")
    body.append("Location: ", style="bold")
    body.append(f"{_location(finding)}\n")
    body.append("Message: ", style="bold")
    body.append(f"{finding.message}\n")
    if finding.evidence:
        body.append("Evidence: ", style="bold")
        body.append(f"{finding.evidence}\n")
    if finding.remediation:
        body.append("Remediation: ", style="bold")
        body.append(f"{finding.remediation}\n")
    if finding.references:
        body.append("References: ", style="bold")
        body.append(", ".join(finding.references))
    title = Text(f"{finding.severity.value.upper()} {finding.rule_id}", style="bold")
    return Panel(body, title=title, border_style=_border_style(finding.severity))


def _border_style(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "cyan",
        Severity.INFO: "dim",
    }[severity]


def _location(finding: Finding) -> str:
    return finding.file + (f":{finding.line}" if finding.line else "")


def _sarif_rule(info: RuleInfo) -> dict[str, object]:
    help_text = info.description
    if info.remediation:
        help_text += f"\n\nRemediation: {info.remediation}"
    payload: dict[str, object] = {
        "id": info.id,
        "name": info.id,
        "shortDescription": {"text": info.title},
        "fullDescription": {"text": info.description},
        "help": {"text": help_text},
        "defaultConfiguration": {"level": SARIF_LEVEL[info.severity]},
        "properties": {
            "tags": list(info.tags),
            "security-severity": SECURITY_SEVERITY[info.severity],
        },
    }
    if info.references:
        payload["helpUri"] = info.references[0]
    return payload


def _artifact_uri(path: str) -> str:
    return quote(path.replace("\\", "/"), safe="/:._-~")


def _fingerprint(finding: Finding) -> str:
    material = "|".join(
        [
            finding.rule_id,
            finding.file,
            str(finding.line or 0),
            finding.message,
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _finished_at(result: ScanResult) -> datetime:
    from datetime import timedelta

    return result.generated_at + timedelta(milliseconds=result.duration_ms)
