"""Security analysis for Model Context Protocol (MCP) server definitions."""

from __future__ import annotations

import ipaddress
import os
import re
import shlex
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from ai_guard.core.parser import ConfigDocument, line_number
from ai_guard.rules.base import (
    Finding,
    Rule,
    RuleInfo,
    Severity,
    clip,
    first_line,
    flatten_strings,
)

CATALOG: tuple[RuleInfo, ...] = (
    RuleInfo(
        id="MCP001",
        title="Shell or inline code execution in MCP server",
        severity=Severity.HIGH,
        description=("An MCP server launches a shell interpreter, privilege tool, or inline code."),
        remediation=(
            "Invoke a fixed, vetted executable with allow-listed arguments instead of "
            "a shell or inline code."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/78.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/"
            "OS_Command_Injection_Defense_Cheat_Sheet.html",
        ),
        tags=("mcp", "tool-execution", "command-injection"),
    ),
    RuleInfo(
        id="MCP002",
        title="Exposed or unauthenticated MCP endpoint",
        severity=Severity.HIGH,
        description=(
            "An MCP server exposes a remote endpoint without authentication or over plaintext."
        ),
        remediation=(
            "Require strong authentication, terminate TLS, and bind local servers to loopback only."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/306.html",
            "https://cwe.mitre.org/data/definitions/319.html",
        ),
        tags=("mcp", "network", "authentication"),
    ),
    RuleInfo(
        id="MCP003",
        title="MCP server auto-approves tools",
        severity=Severity.HIGH,
        description=(
            "An MCP server automatically approves tool calls, including dangerous capabilities."
        ),
        remediation=(
            "Disable blanket auto-approval and require explicit human confirmation "
            "for file, shell, and network tools."
        ),
        references=("https://cwe.mitre.org/data/definitions/862.html",),
        tags=("mcp", "authorization", "human-in-the-loop"),
    ),
    RuleInfo(
        id="MCP004",
        title="Privileged container or sandbox bypass",
        severity=Severity.CRITICAL,
        description=(
            "An MCP server uses container privileges, host mounts, or sandbox-disabling flags."
        ),
        remediation=(
            "Remove privileged flags and host mounts; run tools in a rootless, "
            "least-privilege sandbox."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/250.html",
            "https://docs.docker.com/engine/security/",
        ),
        tags=("mcp", "container", "host-escape"),
    ),
    RuleInfo(
        id="MCP005",
        title="Unpinned MCP package execution",
        severity=Severity.MEDIUM,
        description="An MCP server runs a package runner without pinning the package version.",
        remediation="Pin package versions and verify integrity/provenance before execution.",
        references=(
            "https://cwe.mitre.org/data/definitions/829.html",
            "https://slsa.dev/",
        ),
        tags=("mcp", "supply-chain", "dependency"),
    ),
)

MCP_MAP_KEYS = {
    "mcpservers",
    "mcp_servers",
    "mcpconfig",
    "mcp_config",
    "mcp",
    "servers",
}
MCP_HINT_FILENAMES = ("mcp", "claude", "cline", "opencode", "cursor", "windsurf", "agent")

SHELL_COMMANDS = {
    "bash",
    "bash.exe",
    "sh",
    "sh.exe",
    "zsh",
    "zsh.exe",
    "fish",
    "fish.exe",
    "dash",
    "dash.exe",
    "ksh",
    "ksh.exe",
    "csh",
    "tcsh",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
    "wsl",
    "wsl.exe",
}
COMMAND_WRAPPERS = {"command", "exec", "nohup", "setsid", "time"}
ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
INLINE_INTERPRETERS = {
    "python": {"-c"},
    "python3": {"-c"},
    "node": {"-e", "--eval"},
    "deno": {"eval"},
    "bun": {"-e", "--eval"},
    "ruby": {"-e"},
    "perl": {"-e"},
    "php": {"-r"},
    "lua": {"-e"},
}
PRIVILEGE_COMMANDS = {"sudo", "su", "doas", "pkexec", "runas"}
PACKAGE_RUNNERS = {"npx", "pnpx", "bunx", "uvx", "pipx"}
PACKAGE_FLAGS = {"-p", "--package", "--from", "--spec"}
AUTO_APPROVE_KEYS = {
    "autoapprove",
    "auto_approve",
    "alwaysallow",
    "always_allow",
    "allowall",
    "allow_all",
    "autoauth",
    "auto_auth",
    "yolo",
}
DANGEROUS_TOOL_MARKERS = (
    "shell",
    "bash",
    "terminal",
    "exec",
    "command",
    "write",
    "delete",
    "remove",
    "filesystem",
    "file",
    "sudo",
    "network",
    "http",
    "database",
    "sql",
    "*",
)
PRIVILEGED_FLAGS = {
    "--privileged",
    "--pid=host",
    "--net=host",
    "--ipc=host",
    "--userns=host",
    "--uts=host",
    "--security-opt=seccomp=unconfined",
    "--security-opt=apparmor=unconfined",
    "--cap-add=all",
    "--cap-add=sys_admin",
}
SANDBOX_BYPASS_PREFIXES = (
    "--dangerously",
    "--no-sandbox",
    "--disable-web-security",
    "--allow-all",
    "--allow-write",
    "--disable-sandbox",
)
AUTH_KEY_MARKERS = (
    "authorization",
    "api_key",
    "api-key",
    "apikey",
    "auth_token",
    "access_token",
    "bearer",
    "client_secret",
    "x-api-key",
    "token",
    "secret",
    "password",
)
AUTH_CONTAINER_KEYS = {"auth", "authentication", "oauth", "oauth2"}
FALLBACK_SHELL = re.compile(
    r"""
    [\"']?(?:command|commandLine)[\"']?\s*[:=]\s*
    [\"'](bash|sh|zsh|fish|dash|ksh|cmd(?:\.exe)?|powershell|pwsh|wsl(?:\.exe)?)\b
    """,
    re.IGNORECASE | re.VERBOSE,
)
FALLBACK_HTTP_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class MCPServer:
    name: str
    data: dict[str, Any]
    path: tuple[str, ...]


class MCPSecurityRule(Rule):
    """Audit MCP server definitions for dangerous capabilities and exposure."""

    key = "mcp"
    name = "MCP server security"
    catalog = CATALOG

    def scan(self, document: ConfigDocument) -> list[Finding]:
        if document.error:
            return self._fallback_scan(document)
        if document.data is None:
            return []

        findings: list[Finding] = []
        for server in _iter_servers(document.data):
            findings.extend(_check_server(self, document, server))
        return findings

    def _fallback_scan(self, document: ConfigDocument) -> list[Finding]:
        lowered_name = document.filename.lower()
        looks_mcp = any(hint in lowered_name for hint in MCP_HINT_FILENAMES) or (
            "mcpservers" in document.raw.lower()
        )
        if not looks_mcp:
            return []

        findings: list[Finding] = []
        for match in FALLBACK_SHELL.finditer(document.raw):
            line = line_number(document.raw, match.start())
            findings.append(
                self.make_finding(
                    "MCP001",
                    document,
                    (
                        "Malformed MCP configuration still declares a raw shell command "
                        f"({match.group(1)}); fix the JSON/YAML before use."
                    ),
                    severity=Severity.HIGH,
                    line=line,
                    evidence=document.line_text(line) or match.group(0),
                    metadata={"source": "malformed-config-fallback"},
                )
            )

        for match in FALLBACK_HTTP_URL.finditer(document.raw):
            url = match.group(0).rstrip(".,;)]}")
            if not _is_plaintext_remote_url(url):
                continue
            line = line_number(document.raw, match.start())
            findings.append(
                self.make_finding(
                    "MCP002",
                    document,
                    (
                        "Malformed MCP configuration references a remote plaintext "
                        f"HTTP endpoint ({_safe_url(url)})."
                    ),
                    severity=Severity.HIGH,
                    line=line,
                    evidence=_safe_url(url),
                    metadata={"url": _safe_url(url), "source": "malformed-config-fallback"},
                )
            )
        return findings


def _iter_servers(node: Any) -> Iterator[MCPServer]:
    seen: set[int] = set()

    def walk(value: Any, path: tuple[str, ...], depth: int) -> Iterator[MCPServer]:
        if depth > 32:
            return
        if isinstance(value, dict):
            node_id = id(value)
            if node_id in seen:
                return
            seen.add(node_id)
            for key, child in value.items():
                key_text = str(key)
                lowered = key_text.lower()
                if isinstance(child, dict):
                    if lowered in MCP_MAP_KEYS and lowered != "mcp":
                        found = list(_servers_from_map(child))
                        if found:
                            for name, server in found:
                                yield MCPServer(
                                    name,
                                    server,
                                    (*path, key_text, name),
                                )
                        else:
                            yield from walk(child, (*path, key_text), depth + 1)
                    elif lowered == "mcp":
                        if _looks_like_server(child):
                            name = str(child.get("name") or "mcp")
                            yield MCPServer(name, child, (*path, key_text))
                        else:
                            found = list(_servers_from_map(child))
                            if found:
                                for name, server in found:
                                    yield MCPServer(
                                        name,
                                        server,
                                        (*path, key_text, name),
                                    )
                            else:
                                yield from walk(child, (*path, key_text), depth + 1)
                    else:
                        yield from walk(child, (*path, key_text), depth + 1)
                elif isinstance(child, list):
                    if lowered in MCP_MAP_KEYS and lowered != "mcp":
                        for index, entry in enumerate(child):
                            if isinstance(entry, dict) and _looks_like_server(entry):
                                name = str(entry.get("name") or f"{key_text}[{index}]")
                                yield MCPServer(
                                    name,
                                    entry,
                                    (*path, key_text, name),
                                )
                            elif isinstance(entry, (dict, list)):
                                yield from walk(entry, (*path, key_text, f"[{index}]"), depth + 1)
                    else:
                        for index, entry in enumerate(child):
                            if isinstance(entry, (dict, list)):
                                yield from walk(entry, (*path, key_text, f"[{index}]"), depth + 1)
            seen.discard(node_id)
        elif isinstance(value, list):
            node_id = id(value)
            if node_id in seen:
                return
            seen.add(node_id)
            for index, entry in enumerate(value):
                if isinstance(entry, (dict, list)):
                    yield from walk(entry, (*path, f"[{index}]"), depth + 1)
            seen.discard(node_id)

    yield from walk(node, (), 0)


def _servers_from_map(mapping: dict[Any, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    for name, server in mapping.items():
        if isinstance(server, dict) and _looks_like_server(server):
            yield str(name), server


def _looks_like_server(value: dict[Any, Any]) -> bool:
    keys = {str(key).lower() for key in value}
    if keys & {
        "command",
        "commandline",
        "args",
        "url",
        "endpoint",
        "httpurl",
        "serverurl",
        "baseurl",
        "transport",
    }:
        return True
    return any(key.endswith("url") for key in keys)


def _check_server(
    rule: MCPSecurityRule, document: ConfigDocument, server: MCPServer
) -> list[Finding]:
    data = server.data
    findings: list[Finding] = []
    line = _server_line(document, server)

    command_value = data.get("command", data.get("commandLine"))
    executable, args = _split_command(command_value, data.get("args"))
    executable, args = _unwrap_command(executable, args)
    base = _basename(executable)
    lowered_args = [arg.lower() for arg in args]

    if base in SHELL_COMMANDS:
        findings.append(
            rule.make_finding(
                "MCP001",
                document,
                f"MCP server {server.name!r} launches a raw shell interpreter ({base}).",
                severity=Severity.HIGH,
                line=first_line(document, base, server.name) or line,
                evidence=f"{server.name}: command={base} args={len(args)}",
                metadata={
                    "server": server.name,
                    "command": base,
                    "transport": data.get("transport"),
                },
            )
        )
    elif base in INLINE_INTERPRETERS:
        inline_flags = INLINE_INTERPRETERS[base]
        if any(
            arg == flag or arg.startswith(f"{flag}=") or (flag == "-c" and arg.startswith("-c"))
            for arg in lowered_args
            for flag in inline_flags
        ):
            findings.append(
                rule.make_finding(
                    "MCP001",
                    document,
                    f"MCP server {server.name!r} executes inline code through {base}.",
                    severity=Severity.HIGH,
                    line=first_line(document, base, server.name) or line,
                    evidence=f"{server.name}: command={base} inline-eval",
                    metadata={"server": server.name, "command": base},
                )
            )

    privilege = next(
        (
            token
            for token in [base, *(_basename(arg) for arg in args)]
            if token in PRIVILEGE_COMMANDS
        ),
        None,
    )
    if privilege:
        findings.append(
            rule.make_finding(
                "MCP001",
                document,
                f"MCP server {server.name!r} invokes privilege-escalation command {privilege!r}.",
                severity=Severity.CRITICAL,
                line=first_line(document, privilege, server.name) or line,
                evidence=f"{server.name}: privilege={privilege}",
                metadata={"server": server.name, "command": privilege},
            )
        )

    docker_issue = _docker_escape(base, args)
    if docker_issue:
        findings.append(
            rule.make_finding(
                "MCP004",
                document,
                f"MCP server {server.name!r} uses a container escape primitive: {docker_issue}.",
                severity=Severity.CRITICAL,
                line=first_line(document, docker_issue, server.name) or line,
                evidence=f"{server.name}: {docker_issue}",
                metadata={"server": server.name, "flag": docker_issue},
            )
        )

    bypass = next(
        (arg for arg in args if arg.lower().startswith(SANDBOX_BYPASS_PREFIXES)),
        None,
    )
    if bypass:
        findings.append(
            rule.make_finding(
                "MCP004",
                document,
                f"MCP server {server.name!r} disables sandbox or permission controls ({bypass}).",
                severity=Severity.HIGH,
                line=first_line(document, bypass, server.name) or line,
                evidence=f"{server.name}: {bypass}",
                metadata={"server": server.name, "flag": bypass},
            )
        )

    auto_approve = _auto_approve_issue(data)
    if auto_approve is not None:
        key, tokens, dangerous = auto_approve
        if dangerous:
            message = (
                f"MCP server {server.name!r} auto-approves dangerous tools "
                f"via {key} ({', '.join(tokens)[:160]})."
            )
            severity = Severity.HIGH
        else:
            message = (
                f"MCP server {server.name!r} auto-approves tool calls via {key}; "
                "explicit review is bypassed."
            )
            severity = Severity.MEDIUM
        findings.append(
            rule.make_finding(
                "MCP003",
                document,
                message,
                severity=severity,
                line=first_line(document, key, server.name) or line,
                evidence=f"{server.name}: {key}={clip(', '.join(tokens), 160)}",
                metadata={
                    "server": server.name,
                    "auto_approve": key,
                    "tools": tokens[:32],
                    "dangerous": dangerous,
                },
            )
        )

    findings.extend(_network_findings(rule, document, server, data, base, args, line))
    findings.extend(_supply_chain_findings(rule, document, server, base, args, line))
    return findings


def _split_command(command: Any, extra_args: Any) -> tuple[str, list[str]]:
    args = [str(arg) for arg in flatten_strings(extra_args)]
    if isinstance(command, (list, tuple)):
        parts = [str(part) for part in command]
        if not parts:
            return "", args
        return parts[0], [*parts[1:], *args]
    if command is None:
        return "", args
    text = str(command).strip()
    if not text:
        return "", args
    if any(character.isspace() for character in text) and not os.path.exists(text):
        try:
            parts = shlex.split(text)
        except ValueError:
            parts = text.split()
        if len(parts) > 1:
            return parts[0], [*parts[1:], *args]
    return text, args


def _unwrap_command(executable: str, args: list[str]) -> tuple[str, list[str]]:
    """Peel common launcher wrappers so ``env bash -c ...`` is still detected."""

    tokens = [executable, *args]
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not token:
            index += 1
            continue
        if ENV_ASSIGNMENT.match(token):
            index += 1
            continue

        base = _basename(token)
        if base == "env":
            index += 1
            while index < len(tokens):
                candidate = tokens[index]
                if ENV_ASSIGNMENT.match(candidate):
                    index += 1
                elif candidate == "--":
                    index += 1
                    break
                elif candidate in {"-u", "--unset", "-C", "--chdir", "-S", "--split-string"}:
                    index += 2
                elif candidate.startswith("-"):
                    index += 1
                else:
                    break
            continue
        if base in COMMAND_WRAPPERS:
            index += 1
            while index < len(tokens) and tokens[index].startswith("-"):
                if base == "exec" and tokens[index] == "-a" and index + 1 < len(tokens):
                    index += 2
                else:
                    index += 1
            continue
        if base == "nice":
            index += 1
            while index < len(tokens):
                candidate = tokens[index]
                if candidate in {"-n", "--adjustment"}:
                    index += 2
                elif candidate.startswith("-"):
                    index += 1
                else:
                    break
            continue
        if base == "stdbuf":
            index += 1
            while index < len(tokens):
                candidate = tokens[index]
                if candidate in {"-i", "-o", "-e"}:
                    index += 2
                elif candidate.startswith("-"):
                    index += 1
                else:
                    break
            continue
        if base == "timeout":
            index += 1
            while index < len(tokens) and tokens[index].startswith("-"):
                if tokens[index] in {"-s", "--signal", "-k", "--kill-after"}:
                    index += 2
                else:
                    index += 1
            if index < len(tokens):
                index += 1
            continue
        if base == "flock":
            index += 1
            while index < len(tokens) and tokens[index].startswith("-"):
                index += 1
            if index < len(tokens):
                index += 1
            continue
        break

    if index >= len(tokens):
        return "", []
    return tokens[index], tokens[index + 1 :]


def _basename(value: str) -> str:
    normalized = str(value).strip().strip("\"'").replace("\\", "/").rstrip("/")
    return normalized.rsplit("/", 1)[-1].lower()


def _docker_escape(base: str, args: list[str]) -> str | None:
    lowered_base = base.lower()
    for index, arg in enumerate(args):
        lowered = arg.lower()
        if lowered in PRIVILEGED_FLAGS or lowered.startswith("--cap-add=sys_admin"):
            return arg
        if "/var/run/docker.sock" in lowered:
            return arg
        if lowered in {"-v", "--volume", "--mount"} and index + 1 < len(args):
            volume = args[index + 1]
            parts = volume.split(":")
            source = parts[0].strip()
            if source in {"/", "//"} or "docker.sock" in volume.lower():
                return volume
        if lowered_base in {"docker", "podman", "nerdctl"} and "source=/" in lowered:
            return arg
    return None


def _auto_approve_issue(data: dict[str, Any]) -> tuple[str, list[str], bool] | None:
    for key, value in data.items():
        if str(key).lower() not in AUTO_APPROVE_KEYS:
            continue
        tokens = _approval_tokens(value)
        if not tokens:
            continue
        dangerous = any(
            token == "*" or any(marker in token.lower() for marker in DANGEROUS_TOOL_MARKERS)
            for token in tokens
        )
        return str(key), tokens, dangerous
    return None


def _approval_tokens(value: Any) -> list[str]:
    if value is True:
        return ["*"]
    if value in (False, None):
        return []
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.lower() in {"true", "yes", "all", "*", "on"}:
            return ["*"]
        return [part.strip() for part in stripped.split(",") if part.strip()]
    if isinstance(value, dict):
        tokens = [str(key) for key, enabled in value.items() if enabled]
        tokens.extend(
            flatten_strings([item for item in value.values() if not isinstance(item, bool)])
        )
        return tokens
    if isinstance(value, (list, tuple, set)):
        return flatten_strings(value)
    return [str(value)]


def _network_findings(
    rule: MCPSecurityRule,
    document: ConfigDocument,
    server: MCPServer,
    data: dict[str, Any],
    base: str,
    args: list[str],
    line: int | None,
) -> list[Finding]:
    findings: list[Finding] = []
    auth = _has_auth(data)
    wildcard_reported = False

    for key_path, url in _iter_url_values(data):
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https", "ws", "wss"}:
            continue
        host = (parsed.hostname or "").lower()
        if not host:
            continue
        safe = _safe_url(url)
        if _is_wildcard_host(host):
            findings.append(
                rule.make_finding(
                    "MCP002",
                    document,
                    (
                        f"MCP server {server.name!r} exposes a network listener on all "
                        f"interfaces ({safe})."
                    ),
                    severity=Severity.CRITICAL if not auth else Severity.HIGH,
                    line=document.find_line(url) or line,
                    evidence=f"{server.name}: {safe}",
                    metadata={
                        "server": server.name,
                        "url": safe,
                        "host_key": ".".join(key_path),
                        "authentication": auth,
                    },
                )
            )
            wildcard_reported = True
            continue

        if _is_loopback(host):
            continue

        plaintext = scheme in {"http", "ws"}
        reasons: list[str] = []
        if plaintext:
            reasons.append("uses plaintext HTTP")
        if not auth:
            reasons.append("does not declare authentication")
        if not reasons:
            continue
        findings.append(
            rule.make_finding(
                "MCP002",
                document,
                f"Remote MCP endpoint {safe} for server {server.name!r} {' and '.join(reasons)}.",
                severity=Severity.HIGH,
                line=document.find_line(url) or line,
                evidence=f"{server.name}: {safe}",
                metadata={
                    "server": server.name,
                    "url": safe,
                    "scheme": scheme,
                    "host": host,
                    "authentication": auth,
                },
            )
        )

    bind_source = _wildcard_bind_source(data, base, args)
    if bind_source and not wildcard_reported:
        findings.append(
            rule.make_finding(
                "MCP002",
                document,
                (f"MCP server {server.name!r} binds a listener to all interfaces ({bind_source})."),
                severity=Severity.HIGH if auth else Severity.CRITICAL,
                line=first_line(document, bind_source, server.name) or line,
                evidence=f"{server.name}: {bind_source}",
                metadata={"server": server.name, "bind": bind_source, "authentication": auth},
            )
        )
    return findings


def _iter_url_values(node: Any) -> Iterator[tuple[tuple[str, ...], str]]:
    seen: set[int] = set()

    def walk(
        value: Any, path: tuple[str, ...], depth: int
    ) -> Iterator[tuple[tuple[str, ...], str]]:
        if depth > 24:
            return
        if isinstance(value, dict):
            node_id = id(value)
            if node_id in seen:
                return
            seen.add(node_id)
            for key, child in value.items():
                key_text = str(key)
                lowered = key_text.lower()
                if isinstance(child, str) and ("url" in lowered or "endpoint" in lowered):
                    yield (*path, key_text), child
                elif isinstance(child, (dict, list)):
                    yield from walk(child, (*path, key_text), depth + 1)
            seen.discard(node_id)
        elif isinstance(value, list):
            node_id = id(value)
            if node_id in seen:
                return
            seen.add(node_id)
            for index, child in enumerate(value):
                if isinstance(child, (dict, list)):
                    yield from walk(child, (*path, f"[{index}]"), depth + 1)
            seen.discard(node_id)

    yield from walk(node, (), 0)


def _has_auth(server: dict[str, Any]) -> bool:
    for path, value in _iter_leaf_values(server):
        if not _is_real_auth_value(value):
            continue
        key = path[-1].lower()
        if any(marker in key for marker in AUTH_KEY_MARKERS):
            return True
        if any(part.lower() in AUTH_CONTAINER_KEYS for part in path[:-1]):
            return True

    for key, value in server.items():
        if str(key).lower() in AUTH_CONTAINER_KEYS and isinstance(value, (dict, list)) and value:
            return True

    command, args = _split_command(server.get("command"), server.get("args"))
    for arg in [command, *args]:
        lowered = arg.lower()
        if "authorization:" in lowered or lowered.startswith(("--token", "--api-key")):
            return True
    return False


def _iter_leaf_values(node: Any) -> Iterator[tuple[tuple[str, ...], Any]]:
    seen: set[int] = set()

    def walk(
        value: Any, path: tuple[str, ...], depth: int
    ) -> Iterator[tuple[tuple[str, ...], Any]]:
        if depth > 24:
            return
        if isinstance(value, dict):
            node_id = id(value)
            if node_id in seen:
                return
            seen.add(node_id)
            for key, child in value.items():
                child_path = (*path, str(key))
                if isinstance(child, (dict, list)):
                    yield from walk(child, child_path, depth + 1)
                else:
                    yield child_path, child
            seen.discard(node_id)
        elif isinstance(value, list):
            node_id = id(value)
            if node_id in seen:
                return
            seen.add(node_id)
            for index, child in enumerate(value):
                child_path = (*path, f"[{index}]")
                if isinstance(child, (dict, list)):
                    yield from walk(child, child_path, depth + 1)
                else:
                    yield child_path, child
            seen.discard(node_id)

    yield from walk(node, (), 0)


def _is_real_auth_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip()
    if not text:
        return False
    lowered = text.lower()
    if lowered in {"null", "none", "false", "0"}:
        return False
    return not any(
        marker in lowered for marker in ("changeme", "placeholder", "your_", "your-", "example")
    )


def _wildcard_bind_source(data: dict[str, Any], base: str, args: list[str]) -> str | None:
    candidates = [base, *args]
    for _, value in _iter_leaf_values(data):
        if isinstance(value, str):
            candidates.append(value)
    for candidate in candidates:
        lowered = candidate.lower()
        if lowered in {"::", "[::]"}:
            return candidate
        if re.search(r"(?:^|[=:\s])0\.0\.0\.0(?::|\b)", lowered):
            return candidate
    return None


def _supply_chain_findings(
    rule: MCPSecurityRule,
    document: ConfigDocument,
    server: MCPServer,
    base: str,
    args: list[str],
    line: int | None,
) -> list[Finding]:
    if base not in PACKAGE_RUNNERS:
        return []
    package = _package_candidate(args)
    if not package or _is_pinned_package(package):
        return []
    return [
        rule.make_finding(
            "MCP005",
            document,
            f"MCP server {server.name!r} runs unpinned package {package!r} via {base}.",
            severity=Severity.MEDIUM,
            line=first_line(document, package, base, server.name) or line,
            evidence=f"{server.name}: {base} {package}",
            metadata={"server": server.name, "runner": base, "package": package},
        )
    ]


def _package_candidate(args: list[str]) -> str | None:
    index = 0
    while index < len(args):
        arg = args[index]
        lowered = arg.lower()
        if lowered in PACKAGE_FLAGS and index + 1 < len(args):
            return args[index + 1]
        if arg.startswith("-"):
            index += 1
            continue
        if lowered in {"run", "exec", "dlx"}:
            index += 1
            continue
        return arg
    return None


def _is_pinned_package(package: str) -> bool:
    candidate = package.strip().strip("\"'")
    lowered = candidate.lower()
    if lowered.startswith(("./", "../", "/", "file:", "git+", "http://", "https://")):
        return True
    if lowered.endswith(("@latest", "@next", "@beta", "@canary")):
        return False
    if candidate.startswith("@"):
        return "@" in candidate[1:]
    return "@" in candidate


def _server_line(document: ConfigDocument, server: MCPServer) -> int | None:
    return first_line(document, f'"{server.name}"', server.name)


def _safe_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return url.split("?", 1)[0]
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, host, parsed.path, "", ""))


def _is_loopback(host: str) -> bool:
    if host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _is_wildcard_host(host: str) -> bool:
    return host in {"0.0.0.0", "::", "[::]"}


def _is_plaintext_remote_url(url: str) -> bool:
    parsed = urlsplit(url)
    if parsed.scheme.lower() not in {"http", "ws"}:
        return False
    host = (parsed.hostname or "").lower()
    return not (not host or _is_loopback(host) or _is_wildcard_host(host))
