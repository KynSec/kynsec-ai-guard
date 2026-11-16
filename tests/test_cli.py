"""CLI smoke tests for exit codes and machine-readable output formats."""

from __future__ import annotations

import json

from ai_guard.cli import app
from typer.testing import CliRunner

runner = CliRunner()


def _write(path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_version_command() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert "KynSec AI Guard" in result.output


def test_rules_command_lists_catalog() -> None:
    result = runner.invoke(app, ["rules"])

    assert result.exit_code == 0
    assert "MCP001" in result.output
    assert "SEC001" in result.output


def test_scan_json_output_and_finding_exit_code(tmp_path) -> None:
    config = tmp_path / "mcp.json"
    _write(config, {"mcpServers": {"shell": {"command": "bash", "args": ["-c", "id"]}}})

    result = runner.invoke(
        app,
        ["scan", str(config), "--format", "json", "--quiet"],
    )

    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["tool"]["name"] == "KynSec AI Guard"
    assert any(finding["rule_id"] == "MCP001" for finding in payload["findings"])


def test_scan_clean_table_exit_zero(tmp_path) -> None:
    config = tmp_path / "mcp.json"
    _write(config, {"mcpServers": {"safe": {"command": "node", "args": ["server.js"]}}})

    result = runner.invoke(app, ["scan", str(config), "--quiet"])

    assert result.exit_code == 0
    assert "Clean scan" in result.output


def test_scan_min_severity_suppresses_medium_findings(tmp_path) -> None:
    config = tmp_path / "config.json"
    _write(
        config,
        {
            "key": (
                "eyJhbGciOiJIUzI1NiJ9."
                "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
                "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
            )
        },
    )

    result = runner.invoke(
        app,
        ["scan", str(config), "--min-severity", "HIGH", "--format", "json", "--quiet"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["findings"] == []
    assert payload["summary"]["findings_suppressed"] >= 1


def test_scan_sarif_output(tmp_path) -> None:
    config = tmp_path / "config.json"
    _write(config, {"root": "/etc/passwd"})

    result = runner.invoke(
        app,
        ["scan", str(config), "--format", "sarif", "--quiet"],
    )

    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "KynSec AI Guard"
    assert payload["runs"][0]["results"]


def test_audit_mcp_json_output(tmp_path) -> None:
    config = tmp_path / "mcp.json"
    _write(config, {"mcpServers": {"shell": {"command": "bash", "args": ["-c", "id"]}}})

    result = runner.invoke(
        app,
        ["audit-mcp", str(config), "--format", "json", "--quiet"],
    )

    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert any(finding["rule_id"] == "MCP001" for finding in payload["findings"])


def test_scan_writes_output_file(tmp_path) -> None:
    config = tmp_path / "config.json"
    output = tmp_path / "report.json"
    _write(config, {"root": "/etc/passwd"})

    result = runner.invoke(
        app,
        ["scan", str(config), "--format", "json", "--output", str(output), "--quiet"],
    )

    assert result.exit_code == 1
    assert output.exists()
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["findings"]


def test_scan_empty_directory_exits_with_operational_error(tmp_path) -> None:
    (tmp_path / "script.py").write_text("print('ignored')", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path), "--quiet"])

    assert result.exit_code == 2


def test_invalid_format_exits_with_usage_error(tmp_path) -> None:
    config = tmp_path / "config.json"
    _write(config, {"key": "value"})

    result = runner.invoke(app, ["scan", str(config), "--format", "xml", "--quiet"])

    assert result.exit_code == 2


def test_missing_path_exits_with_usage_error() -> None:
    result = runner.invoke(app, ["scan", "/definitely/not/here", "--quiet"])

    assert result.exit_code == 2
