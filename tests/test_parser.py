"""Tests for the configuration parser and file discovery layer."""

from __future__ import annotations

import pytest
from ai_guard.core import parser
from ai_guard.core.parser import (
    ConfigFormat,
    DiscoveryError,
    ParseError,
    discover_files,
    is_supported_file,
    parse_file,
    parse_string,
)


def test_parse_valid_json() -> None:
    document = parse_string(
        '{"mcpServers": {"safe": {"command": "node"}}}',
        "claude_desktop_config.json",
    )

    assert document.error is None
    assert document.format is ConfigFormat.JSON
    assert document.is_structured
    assert document.data["mcpServers"]["safe"]["command"] == "node"


def test_parse_jsonc_comments_and_trailing_commas() -> None:
    raw = """
    {
      // Claude Desktop sometimes gets hand-edited.
      "mcpServers": {
        "safe": {
          "command": "node",
          "args": ["server.js"], /* trailing comma below */
        },
      },
    }
    """

    document = parse_string(raw, "claude_desktop_config.json")

    assert document.error is None
    assert document.data["mcpServers"]["safe"]["args"] == ["server.js"]


def test_malformed_json_is_reported_without_raising() -> None:
    raw = '{"mcpServers": {"broken": '
    document = parse_string(raw, "config.json")

    assert document.format is ConfigFormat.JSON
    assert document.data is None
    assert document.error is not None
    assert "Invalid JSON" in document.error
    assert document.raw == raw


def test_parse_file_records_malformed_json(tmp_path) -> None:
    path = tmp_path / "cline_mcp_settings.json"
    path.write_text('{"mcpServers": {', encoding="utf-8")

    document = parse_file(path)

    assert document.error is not None
    assert document.display_path.endswith("cline_mcp_settings.json")


def test_parse_yaml_and_yaml_error() -> None:
    valid = parse_string("mcpServers:\n  safe:\n    command: node\n", "config.yaml")
    assert valid.error is None
    assert valid.format is ConfigFormat.YAML
    assert valid.data["mcpServers"]["safe"]["command"] == "node"

    invalid = parse_string("mcpServers: [unclosed\n", "config.yaml")
    assert invalid.error is not None
    assert "Invalid YAML" in invalid.error


def test_parse_toml() -> None:
    document = parse_string(
        "[mcpServers.safe]\ncommand = 'node'\nargs = ['server.js']\n",
        "config.toml",
    )

    assert document.error is None
    assert document.format is ConfigFormat.TOML
    assert document.data["mcpServers"]["safe"]["command"] == "node"


def test_parse_dotenv() -> None:
    document = parse_string(
        '# comment\nexport OPENAI_API_KEY=sk-test\nQUOTED="value here"\n',
        ".env",
    )

    assert document.error is None
    assert document.format is ConfigFormat.DOTENV
    assert document.data["OPENAI_API_KEY"] == "sk-test"
    assert document.data["QUOTED"] == "value here"


@pytest.mark.parametrize(
    ("raw", "filename", "expected"),
    [
        ('{"a": 1}', "config", ConfigFormat.JSON),
        ("key: value\n", "config", ConfigFormat.YAML),
        ("[section]\nkey = 1\n", "config", ConfigFormat.TOML),
        ("# Title\n\nBody\n", "README.md", ConfigFormat.MARKDOWN),
        ("plain instructions", "system.prompt", ConfigFormat.TEXT),
        ("KEY=value\n", ".env", ConfigFormat.DOTENV),
    ],
)
def test_format_detection(raw: str, filename: str, expected: ConfigFormat) -> None:
    assert parse_string(raw, filename).format is expected


def test_iter_leaf_values_and_strings() -> None:
    document = parse_string(
        '{"a": {"b": 1, "c": ["x", {"d": "y"}]}, "e": true}',
        "config.json",
    )

    values = dict(document.iter_leaf_values())
    strings = dict(document.iter_strings())

    assert values[("a", "b")] == 1
    assert values[("a", "c", "[0]")] == "x"
    assert values[("a", "c", "[1]", "d")] == "y"
    assert values[("e",)] is True
    assert strings["a.c[0]"] == "x"
    assert strings["a.c[1].d"] == "y"


def test_find_line_and_line_text() -> None:
    document = parse_string(
        '{\n  "command": "bash",\n  "args": ["-c", "id"]\n}\n',
        "config.json",
    )

    assert document.find_line("bash") == 2
    assert document.find_line("BASH") == 2
    assert document.find_line("missing") is None
    assert document.line_text(2) == '"command": "bash",'
    assert document.line_text(99) is None


def test_discover_files_filters_unsupported_and_excluded_dirs(tmp_path) -> None:
    (tmp_path / "claude_desktop_config.json").write_text("{}", encoding="utf-8")
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text("{}", encoding="utf-8")
    (tmp_path / "notes.md").write_text("hello", encoding="utf-8")
    (tmp_path / "script.py").write_text("print('no')", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config.json").write_text("{}", encoding="utf-8")
    (tmp_path / "ai_guard_cli.egg-info").mkdir()
    (tmp_path / "ai_guard_cli.egg-info" / "SOURCES.txt").write_text("README.md", encoding="utf-8")

    discovered = {path.name for path in discover_files(tmp_path)}

    assert discovered == {"claude_desktop_config.json", "settings.json", "notes.md"}


def test_discover_files_returns_explicit_unsupported_file(tmp_path) -> None:
    script = tmp_path / "weird.py"
    script.write_text("print('scan me')", encoding="utf-8")

    assert discover_files(script) == [script]


def test_discover_files_missing_target_raises(tmp_path) -> None:
    with pytest.raises(DiscoveryError):
        discover_files(tmp_path / "does-not-exist")


def test_is_supported_file_recognizes_env_and_known_names(tmp_path) -> None:
    assert is_supported_file(tmp_path / ".env")
    assert is_supported_file(tmp_path / ".env.production")
    assert is_supported_file(tmp_path / "claude_desktop_config.json")
    assert is_supported_file(tmp_path / "CLAUDE.md")
    assert not is_supported_file(tmp_path / "binary.exe")


def test_parse_file_handles_invalid_utf8(tmp_path) -> None:
    path = tmp_path / "config.json"
    path.write_bytes(b"\xff\xfe\x00")

    document = parse_file(path)

    assert document.error is not None
    assert "UTF-8" in document.error


def test_parse_file_rejects_oversized_files(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(parser, "MAX_FILE_BYTES", 8)
    path = tmp_path / "config.json"
    path.write_text('{"too": "large"}', encoding="utf-8")

    document = parse_file(path)

    assert document.error is not None
    assert "too large" in document.error


def test_parse_file_missing_path(tmp_path) -> None:
    document = parse_file(tmp_path / "missing.json")

    assert document.error is not None
    assert "does not exist" in document.error


def test_parse_invalid_yaml_raises_parse_error_internally() -> None:
    with pytest.raises(ParseError):
        parser._parse_yaml("a: [broken")
