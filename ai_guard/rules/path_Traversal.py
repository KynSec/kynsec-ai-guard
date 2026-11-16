"""Detection of dangerous host path exposure in agent and MCP configuration."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ai_guard.core.parser import ConfigDocument
from ai_guard.rules.base import Finding, Rule, RuleInfo, Severity, first_line

CATALOG: tuple[RuleInfo, ...] = (
    RuleInfo(
        id="PATH001",
        title="Filesystem root exposed",
        severity=Severity.CRITICAL,
        description=("A tool or MCP server is configured with access to the filesystem root."),
        remediation=(
            "Scope mounts and workspace roots to a dedicated project directory; "
            "never expose '/' or a full drive."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/668.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/"
            "OS_Command_Injection_Defense_Cheat_Sheet.html",
        ),
        tags=("filesystem", "mcp", "least-privilege"),
    ),
    RuleInfo(
        id="PATH002",
        title="Sensitive system path exposed",
        severity=Severity.HIGH,
        description="A configuration references a sensitive operating-system path.",
        remediation=(
            "Remove host system paths from agent configuration and expose only "
            "narrowly scoped data directories."
        ),
        references=("https://cwe.mitre.org/data/definitions/200.html",),
        tags=("filesystem", "host-exposure"),
    ),
    RuleInfo(
        id="PATH003",
        title="Credential directory exposed",
        severity=Severity.CRITICAL,
        description=(
            "A home, SSH, cloud, container, or Kubernetes credential directory is accessible."
        ),
        remediation=(
            "Move credentials out of the agent workspace and require a dedicated, "
            "short-lived credential broker."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/522.html",
            "https://cwe.mitre.org/data/definitions/538.html",
        ),
        tags=("filesystem", "credentials", "host-exposure"),
    ),
    RuleInfo(
        id="PATH004",
        title="Path traversal sequence present",
        severity=Severity.MEDIUM,
        description=("A configuration value contains parent-directory traversal sequences."),
        remediation=(
            "Canonicalize and allow-list paths before exposing them to an agent or tool server."
        ),
        references=("https://cwe.mitre.org/data/definitions/22.html",),
        tags=("filesystem", "traversal"),
    ),
    RuleInfo(
        id="PATH005",
        title="Windows system path exposed",
        severity=Severity.HIGH,
        description="A Windows root drive or protected system directory is referenced.",
        remediation=(
            "Restrict the agent to a project folder and remove drive-level or "
            "system-directory access."
        ),
        references=("https://cwe.mitre.org/data/definitions/200.html",),
        tags=("filesystem", "windows", "host-exposure"),
    ),
    RuleInfo(
        id="PATH006",
        title="Docker socket exposed",
        severity=Severity.CRITICAL,
        description=(
            "The Docker daemon socket is mounted or referenced, which commonly "
            "permits host takeover."
        ),
        remediation=(
            "Do not mount /var/run/docker.sock into untrusted tools; use a "
            "restricted proxy or rootless builder."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/250.html",
            "https://docs.docker.com/engine/security/",
        ),
        tags=("filesystem", "docker", "container-escape"),
    ),
)

DOCKER_SOCKET = re.compile(r"(?:unix://)?/var/run/docker\.sock", re.IGNORECASE)
CREDENTIAL_PATH = re.compile(
    r"""
    (?:^|[\s=:\"'])
    (
        (?:~|\$HOME|\$\{HOME\})/
        (?:\.ssh|\.aws|\.gnupg|\.kube|\.docker|\.config/gcloud)
        |
        /(?:root|home/[^/\s\"']+|Users/[^/\s\"']+)/
        (?:\.ssh|\.aws|\.gnupg|\.kube|\.docker|\.config/gcloud)
    )
    (?=[/\s\"',;]|$)
    """,
    re.IGNORECASE | re.VERBOSE,
)
HOME_ONLY = re.compile(r"(?i)^(?:~|\$HOME|\$\{HOME\})$")
SYSTEM_PATH = re.compile(
    r"""
    (?:^|[\s=:\"'])
    (
        /etc(?:/(?:passwd|shadow|sudoers|hosts|ssh|systemd|ssl|cron[a-z0-9_.-]*))?
        |
        /proc | /sys | /boot | /root
        |
        /var/(?:log|lib|spool)
        |
        /dev/(?:sd[a-z]|nvme|mem|kmem|mapper)
    )
    (?=[/\s\"',;:]|$)
    """,
    re.IGNORECASE | re.VERBOSE,
)
WINDOWS_ROOT = re.compile(r"(?i)^[A-Za-z]:[\\/]?$")
WINDOWS_SYSTEM = re.compile(
    r"""
    (?:^|[\s=:\"'])
    (
        [A-Za-z]:\\(?:Windows(?:\\System32)?|Program\ Files(?: \(x86\))?)
        |
        [A-Za-z]:\\Users\\[^\\\s\"']+\\(?:\.ssh|\.aws|\.gnupg|\.kube|\.docker)
    )
    (?=[\\/\s\"',;]|$)
    """,
    re.IGNORECASE | re.VERBOSE,
)
ROOT_MOUNT = re.compile(r"""(?:^|[\s=:"'])/(?=[:,\s"';]|$)""")
TRAVERSAL = re.compile(r"(?:^|[/\\])\.\.(?:[/\\]|$)")


@dataclass(frozen=True, slots=True)
class _PathIssue:
    rule_id: str
    severity: Severity
    label: str
    matched: str
    start: int
    end: int
    priority: int


class PathTraversalRule(Rule):
    """Find filesystem-root, credential, traversal, and host-path exposure."""

    key = "filesystem"
    name = "Filesystem & path exposure"
    catalog = CATALOG

    def scan(self, document: ConfigDocument) -> list[Finding]:
        if not document.is_structured:
            return []

        findings: list[Finding] = []
        seen: set[tuple[str, int | None, str]] = set()

        for context, value in document.iter_strings():
            stripped = value.strip()
            if not stripped:
                continue
            for issue in _evaluate(stripped):
                marker = (issue.rule_id, document.find_line(value), issue.matched)
                if marker in seen:
                    continue
                seen.add(marker)
                line = marker[1] or first_line(document, issue.matched)
                evidence = document.line_text(line) or f"{context}: {stripped}"
                findings.append(
                    self.make_finding(
                        issue.rule_id,
                        document,
                        _message(issue, stripped),
                        severity=issue.severity,
                        line=line,
                        evidence=evidence,
                        metadata={"context": context, "path": issue.matched},
                    )
                )

        return findings


def _evaluate(value: str) -> list[_PathIssue]:
    issues: list[_PathIssue] = []

    def add(
        rule_id: str,
        severity: Severity,
        label: str,
        matched: str,
        start: int,
        end: int,
        priority: int,
    ) -> None:
        issues.append(_PathIssue(rule_id, severity, label, matched, start, end, priority))

    if value in {"/", "//"}:
        add("PATH001", Severity.CRITICAL, "filesystem root", value, 0, len(value), 90)

    for match in ROOT_MOUNT.finditer(value):
        matched = "/"
        start, end = match.span()
        add(
            "PATH001",
            Severity.CRITICAL,
            "filesystem root",
            matched,
            start,
            end,
            90,
        )

    if HOME_ONLY.match(value):
        add(
            "PATH003",
            Severity.HIGH,
            "entire home directory",
            value,
            0,
            len(value),
            80,
        )

    for match in CREDENTIAL_PATH.finditer(value):
        add(
            "PATH003",
            Severity.CRITICAL,
            "credential directory",
            match.group(1),
            *match.span(1),
            80,
        )

    for match in DOCKER_SOCKET.finditer(value):
        add(
            "PATH006",
            Severity.CRITICAL,
            "Docker socket",
            match.group(0),
            *match.span(0),
            100,
        )

    for match in SYSTEM_PATH.finditer(value):
        matched = match.group(1)
        severity = _system_severity(matched)
        add(
            "PATH002",
            severity,
            "sensitive system path",
            matched,
            *match.span(1),
            60,
        )

    if WINDOWS_ROOT.match(value):
        add(
            "PATH005",
            Severity.HIGH,
            "Windows drive root",
            value,
            0,
            len(value),
            70,
        )

    for match in WINDOWS_SYSTEM.finditer(value):
        add(
            "PATH005",
            Severity.HIGH,
            "Windows system path",
            match.group(1),
            *match.span(1),
            70,
        )

    for match in TRAVERSAL.finditer(value):
        add(
            "PATH004",
            Severity.MEDIUM,
            "path traversal",
            match.group(0).strip("/\\") or "..",
            *match.span(0),
            50,
        )

    issues.sort(key=lambda item: (-item.priority, item.start))
    kept: list[_PathIssue] = []
    for issue in issues:
        if any(issue.start < existing.end and issue.end > existing.start for existing in kept):
            continue
        kept.append(issue)
    return kept


def _system_severity(path: str) -> Severity:
    lowered = path.lower()
    if any(marker in lowered for marker in ("passwd", "shadow", "sudoers", "/etc/ssh", "/etc/ssl")):
        return Severity.CRITICAL
    return Severity.HIGH


def _message(issue: _PathIssue, value: str) -> str:
    if issue.rule_id == "PATH001":
        return (
            f"Configuration grants access to the filesystem root ({value!r}); "
            "an agent could read or modify any host file."
        )
    if issue.rule_id == "PATH002":
        return (
            f"Sensitive system path {issue.matched!r} is referenced; "
            "this exposes host configuration or devices to the agent."
        )
    if issue.rule_id == "PATH003":
        return (
            f"Credential-bearing path {issue.matched!r} is accessible; "
            "SSH keys, cloud tokens, or cluster credentials may be exposed."
        )
    if issue.rule_id == "PATH004":
        return (
            f"Path traversal sequence {issue.matched!r} is present; "
            "it can escape an intended workspace or allow-list."
        )
    if issue.rule_id == "PATH005":
        return (
            f"Windows system path {issue.matched!r} is referenced; "
            "protected operating-system files may be exposed."
        )
    return (
        f"Docker socket {issue.matched!r} is referenced; "
        "access to the daemon often allows host takeover."
    )
