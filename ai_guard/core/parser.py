"""Robust, dependency-light parsers for AI agent configuration formats.

The parser layer deliberately never raises for a single unreadable or malformed
file when used through :func:`parse_file`.  It records the failure on the
returned :class:`ConfigDocument` so the engine can keep scanning, emit a
finding, and continue with the remaining files.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_FILES = 25_000
MAX_WALK_DEPTH = 64


class ParseError(ValueError):
    """Raised when a configuration file cannot be decoded."""


class DiscoveryError(OSError):
    """Raised when a scan target cannot be discovered or enumerated."""


class ConfigFormat(str, Enum):
    """Supported on-disk configuration formats."""

    JSON = "json"
    YAML = "yaml"
    TOML = "toml"
    MARKDOWN = "markdown"
    TEXT = "text"
    DOTENV = "dotenv"
    UNKNOWN = "unknown"

    @property
    def is_structured(self) -> bool:
        return self in {
            ConfigFormat.JSON,
            ConfigFormat.YAML,
            ConfigFormat.TOML,
            ConfigFormat.DOTENV,
        }


@dataclass(slots=True)
class ConfigDocument:
    """A parsed file together with its raw text and parse diagnostics."""

    path: Path
    format: ConfigFormat
    raw: str
    data: Any = None
    error: str | None = None
    display_path: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def filename(self) -> str:
        return self.path.name

    @property
    def is_structured(self) -> bool:
        return self.format.is_structured and self.data is not None

    def find_line(self, needle: str, start: int = 0) -> int | None:
        """Return the 1-based line containing ``needle``, if present."""

        if not needle:
            return None
        index = self.raw.find(needle, start)
        if index < 0:
            index = self.raw.lower().find(needle.lower(), start)
        if index < 0:
            return None
        return self.raw.count("\n", 0, index) + 1

    def line_text(self, line: int | None) -> str | None:
        """Return a stripped physical line, or ``None`` when out of range."""

        if line is None or line < 1:
            return None
        lines = self.raw.splitlines()
        if line > len(lines):
            return None
        return lines[line - 1].strip()

    def iter_leaf_values(self) -> Iterator[tuple[tuple[str, ...], Any]]:
        """Yield ``(key_path, scalar_value)`` pairs from structured data."""

        if not isinstance(self.data, (dict, list)):
            return
        seen: set[int] = set()

        def walk(
            node: Any, path: tuple[str, ...], depth: int
        ) -> Iterator[tuple[tuple[str, ...], Any]]:
            if depth > MAX_WALK_DEPTH:
                return
            if isinstance(node, dict):
                node_id = id(node)
                if node_id in seen:
                    return
                seen.add(node_id)
                for key, value in node.items():
                    child_path = (*path, str(key))
                    if isinstance(value, (dict, list)):
                        yield from walk(value, child_path, depth + 1)
                    else:
                        yield child_path, value
                seen.discard(node_id)
            elif isinstance(node, list):
                node_id = id(node)
                if node_id in seen:
                    return
                seen.add(node_id)
                for index, value in enumerate(node):
                    child_path = (*path, f"[{index}]")
                    if isinstance(value, (dict, list)):
                        yield from walk(value, child_path, depth + 1)
                    else:
                        yield child_path, value
                seen.discard(node_id)

        yield from walk(self.data, (), 0)

    def iter_strings(self) -> Iterator[tuple[str, str]]:
        """Yield ``(dotted_key_path, string_value)`` pairs."""

        for path, value in self.iter_leaf_values():
            if isinstance(value, str):
                yield _path_to_string(path), value

    def all_strings(self) -> list[str]:
        return [value for _, value in self.iter_strings()]


JSON_SUFFIXES = frozenset({".json", ".jsonc", ".json5"})
YAML_SUFFIXES = frozenset({".yaml", ".yml"})
TOML_SUFFIXES = frozenset({".toml"})
MARKDOWN_SUFFIXES = frozenset({".md", ".markdown", ".mdx"})
TEXT_SUFFIXES = frozenset({".txt", ".prompt", ".system", ".instructions"})
SUPPORTED_SUFFIXES = (
    JSON_SUFFIXES | YAML_SUFFIXES | TOML_SUFFIXES | MARKDOWN_SUFFIXES | TEXT_SUFFIXES
)

KNOWN_CONFIG_FILENAMES = frozenset(
    {
        "agents.md",
        "claude.md",
        "claude_desktop_config.json",
        "cline_mcp_settings.json",
        "config.json",
        "copilot-instructions.md",
        "cursorrules",
        "instructions.md",
        "mcp.json",
        "mcp_config.json",
        "opencode.json",
        "opencode.jsonc",
        "pyproject.toml",
        "settings.json",
        "system_prompt",
        "system-prompt.txt",
        "windsurfrules",
    }
)

EXCLUDED_DIR_SUFFIXES = (".dist-info", ".egg-info")

EXCLUDED_DIRS = frozenset(
    {
        ".cache",
        ".eggs",
        ".git",
        ".hg",
        ".mypy_cache",
        ".next",
        ".nuxt",
        ".pytest_cache",
        ".ruff_cache",
        ".svn",
        ".tox",
        ".venv",
        "__pycache__",
        "bower_components",
        "build",
        "dist",
        "env",
        "htmlcov",
        "node_modules",
        "site-packages",
        "target",
        "vendor",
        "venv",
        "virtualenv",
    }
)


def is_supported_file(path: Path) -> bool:
    """Return ``True`` when a path looks like an AI/LLM configuration file."""

    name = path.name.lower()
    suffix = path.suffix.lower()
    if name in KNOWN_CONFIG_FILENAMES:
        return True
    if name == ".env" or name.startswith(".env."):
        return True
    return suffix in SUPPORTED_SUFFIXES


def discover_files(target: str | os.PathLike[str]) -> list[Path]:
    """Discover scannable files beneath ``target``.

    Explicit file targets are always returned, even with an unfamiliar suffix,
    because the user intentionally asked to scan that file.
    """

    root = Path(target).expanduser()
    if not root.exists():
        raise DiscoveryError(f"Scan target does not exist: {root}")
    if root.is_file():
        return [root]
    if not root.is_dir():
        raise DiscoveryError(f"Scan target is neither a file nor a directory: {root}")

    files: list[Path] = []
    walk_errors: list[OSError] = []

    def _on_error(error: OSError) -> None:
        walk_errors.append(error)

    for current, dirs, names in os.walk(root, topdown=True, followlinks=False, onerror=_on_error):
        dirs[:] = sorted(
            directory
            for directory in dirs
            if directory.lower() not in EXCLUDED_DIRS
            and not directory.lower().endswith(EXCLUDED_DIR_SUFFIXES)
        )
        for name in sorted(names):
            candidate = Path(current) / name
            if is_supported_file(candidate):
                files.append(candidate)
                if len(files) > MAX_FILES:
                    raise DiscoveryError(
                        f"Refusing to scan more than {MAX_FILES} files; narrow the target path."
                    )

    if not files and walk_errors:
        raise DiscoveryError(f"Unable to enumerate {root}: {walk_errors[0]}")
    return files


def detect_format(path: Path, raw: str) -> ConfigFormat:
    """Infer a format from the file suffix, with a conservative content sniff."""

    name = path.name.lower()
    suffix = path.suffix.lower()

    if name == ".env" or name.startswith(".env."):
        return ConfigFormat.DOTENV
    if suffix in JSON_SUFFIXES:
        return ConfigFormat.JSON
    if suffix in YAML_SUFFIXES:
        return ConfigFormat.YAML
    if suffix in TOML_SUFFIXES:
        return ConfigFormat.TOML
    if suffix in MARKDOWN_SUFFIXES:
        return ConfigFormat.MARKDOWN
    if suffix in TEXT_SUFFIXES or name in {"system_prompt", "cursorrules", "windsurfrules"}:
        return ConfigFormat.TEXT

    stripped = raw.lstrip()
    if not stripped:
        return ConfigFormat.UNKNOWN
    if stripped.startswith("{"):
        return ConfigFormat.JSON
    first_line = stripped.splitlines()[0].strip()
    if re.fullmatch(r"\[[A-Za-z0-9_.\-]+\]", first_line):
        return ConfigFormat.TOML
    if stripped.startswith("["):
        return ConfigFormat.JSON
    if re.search(r"^[ \t]*(?:[\w.-]+|\"[^\"]+\"|'[^']+')\s*:\s", raw, re.MULTILINE):
        return ConfigFormat.YAML
    return ConfigFormat.TEXT


def parse_document(
    raw: str,
    path: Path,
    format_hint: ConfigFormat | None = None,
) -> ConfigDocument:
    """Parse text into a :class:`ConfigDocument`, capturing errors."""

    config_format = format_hint or detect_format(path, raw)
    data: Any = None
    error: str | None = None

    try:
        if config_format is ConfigFormat.JSON:
            data = _parse_json(raw)
        elif config_format is ConfigFormat.YAML:
            data = _parse_yaml(raw)
        elif config_format is ConfigFormat.TOML:
            data = _parse_toml(raw)
        elif config_format is ConfigFormat.DOTENV:
            data = _parse_dotenv(raw)
        else:
            data = None
    except ParseError as exc:
        error = str(exc)
    except Exception as exc:  # pragma: no cover - defensive guard for parser libraries
        error = f"Unexpected parser failure: {exc}"

    return ConfigDocument(
        path=path,
        format=config_format,
        raw=raw,
        data=data,
        error=error,
        display_path=display_path(path),
    )


def parse_file(path: str | os.PathLike[str]) -> ConfigDocument:
    """Read and parse a single file without raising on malformed content."""

    file_path = Path(path).expanduser()
    if not file_path.exists():
        return ConfigDocument(
            path=file_path,
            format=ConfigFormat.UNKNOWN,
            raw="",
            error=f"File does not exist: {file_path}",
            display_path=display_path(file_path),
        )
    if file_path.is_dir():
        return ConfigDocument(
            path=file_path,
            format=ConfigFormat.UNKNOWN,
            raw="",
            error=f"Expected a file but found a directory: {file_path}",
            display_path=display_path(file_path),
        )

    try:
        size = file_path.stat().st_size
        if size > MAX_FILE_BYTES:
            return ConfigDocument(
                path=file_path,
                format=detect_format(file_path, ""),
                raw="",
                error=(
                    f"File is too large to scan ({size} bytes; limit is {MAX_FILE_BYTES} bytes)."
                ),
                display_path=display_path(file_path),
            )
        raw = file_path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        return ConfigDocument(
            path=file_path,
            format=ConfigFormat.UNKNOWN,
            raw="",
            error=f"File is not valid UTF-8 text: {exc}",
            display_path=display_path(file_path),
        )
    except OSError as exc:
        return ConfigDocument(
            path=file_path,
            format=ConfigFormat.UNKNOWN,
            raw="",
            error=f"Unable to read file: {exc}",
            display_path=display_path(file_path),
        )

    return parse_document(raw, file_path)


def parse_string(
    raw: str,
    filename: str = "<memory>",
    format_hint: ConfigFormat | None = None,
) -> ConfigDocument:
    """Parse an in-memory string. Useful for tests and embedded configs."""

    path = Path(filename)
    return parse_document(raw, path, format_hint=format_hint)


def display_path(path: Path) -> str:
    """Prefer repository-relative paths for readable findings and SARIF."""

    try:
        resolved = path.resolve()
        return resolved.relative_to(Path.cwd().resolve()).as_posix()
    except (ValueError, OSError):
        return path.as_posix()


def line_number(text: str, index: int) -> int:
    """Convert a character offset into a 1-based line number."""

    return text.count("\n", 0, max(0, index)) + 1


def _path_to_string(path: tuple[str, ...]) -> str:
    rendered = ""
    for part in path:
        if part.startswith("["):
            rendered += part
        else:
            rendered = f"{rendered}.{part}" if rendered else part
    return rendered


def _parse_json(raw: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        cleaned = _strip_trailing_commas(_strip_json_comments(raw))
        if cleaned != raw:
            try:
                return json.loads(cleaned)
            except json.JSONDecodeError:
                pass
        raise ParseError(
            f"Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc


def _parse_yaml(raw: str) -> Any:
    try:
        return yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        problem = getattr(exc, "problem", None) or str(exc)
        mark = getattr(exc, "problem_mark", None)
        if mark is not None:
            raise ParseError(
                f"Invalid YAML at line {mark.line + 1}, column {mark.column + 1}: {problem}"
            ) from exc
        raise ParseError(f"Invalid YAML: {problem}") from exc


def _parse_toml(raw: str) -> Any:
    try:
        return tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        raise ParseError(f"Invalid TOML: {exc}") from exc


def _parse_dotenv(raw: str) -> dict[str, str] | None:
    data: dict[str, str] = {}
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped[7:].lstrip()
        if "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        if not key:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        data[key] = value
    return data or None


def _strip_json_comments(text: str) -> str:
    """Remove ``//`` and ``/* */`` comments while preserving string content."""

    output: list[str] = []
    index = 0
    in_string = False
    escaped = False
    while index < len(text):
        char = text[index]
        if in_string:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            output.append(char)
            index += 1
            continue
        if char == "/" and index + 1 < len(text):
            nxt = text[index + 1]
            if nxt == "/":
                index += 2
                while index < len(text) and text[index] not in "\r\n":
                    index += 1
                continue
            if nxt == "*":
                end = text.find("*/", index + 2)
                index = len(text) if end < 0 else end + 2
                continue
        output.append(char)
        index += 1
    return "".join(output)


def _strip_trailing_commas(text: str) -> str:
    output: list[str] = []
    index = 0
    in_string = False
    escaped = False
    while index < len(text):
        char = text[index]
        if in_string:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            output.append(char)
            index += 1
            continue
        if char == ",":
            lookahead = index + 1
            while lookahead < len(text) and text[lookahead] in " \t\r\n":
                lookahead += 1
            if lookahead < len(text) and text[lookahead] in "}]":
                index += 1
                continue
        output.append(char)
        index += 1
    return "".join(output)
