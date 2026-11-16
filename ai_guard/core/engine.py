"""Scan orchestration: discover files, run rules, and aggregate findings."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter

from ai_guard.core.parser import (
    MAX_FILE_BYTES,
    DiscoveryError,
    discover_files,
    display_path,
    parse_file,
)
from ai_guard.rules import (
    Finding,
    Rule,
    RuleInfo,
    Severity,
    default_rules,
    mcp_audit_rules,
)

ENGINE_RULE_INFO = RuleInfo(
    id="AI-GUARD-000",
    title="Configuration could not be parsed",
    severity=Severity.MEDIUM,
    description=(
        "A target file is malformed, unreadable, or uses an unsupported encoding, "
        "so structured analysis was skipped."
    ),
    remediation=(
        "Fix the file syntax and rerun the scan; secret detection still runs "
        "against recoverable raw text."
    ),
    references=("https://jsonlint.com/", "https://yaml.org/spec/"),
    tags=("configuration", "parser"),
)

ProgressCallback = Callable[[int, int, str | None], None]


class ScanError(RuntimeError):
    """Raised when a scan cannot be started or completed."""


@dataclass(slots=True)
class ScanResult:
    """Aggregated result for one scan invocation."""

    target: str
    findings: list[Finding]
    rules: list[RuleInfo]
    files_scanned: int
    files_skipped: int
    parse_error_files: list[str]
    errors: list[str]
    min_severity: Severity
    total_findings: int
    duration_ms: float
    generated_at: datetime

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    def summary(self) -> dict[str, object]:
        counts = {
            severity.value: 0
            for severity in (
                Severity.CRITICAL,
                Severity.HIGH,
                Severity.MEDIUM,
                Severity.LOW,
                Severity.INFO,
            )
        }
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return {
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "parse_errors": len(self.parse_error_files),
            "findings_total": self.total_findings,
            "findings_reported": len(self.findings),
            "findings_suppressed": self.total_findings - len(self.findings),
            "by_severity": counts,
            "min_severity": self.min_severity.value,
            "rule_errors": len(self.errors),
            "duration_ms": round(self.duration_ms, 2),
        }


class Engine:
    """Loads configuration documents and executes the configured rule set."""

    def __init__(self, rules: Sequence[Rule] | None = None) -> None:
        self.rules: list[Rule] = list(rules) if rules is not None else default_rules()
        if not self.rules:
            raise ScanError("At least one security rule must be configured.")

    @property
    def rule_info(self) -> list[RuleInfo]:
        infos = [info for rule in self.rules for info in rule.catalog]
        infos.append(ENGINE_RULE_INFO)
        return infos

    def scan(
        self,
        target: str | Path,
        *,
        min_severity: Severity | str = Severity.INFO,
        on_progress: ProgressCallback | None = None,
    ) -> ScanResult:
        started = perf_counter()
        threshold = Severity.parse(min_severity)
        target_path = Path(target).expanduser()

        try:
            files = discover_files(target_path)
        except DiscoveryError as exc:
            raise ScanError(str(exc)) from exc

        if not files:
            raise ScanError(
                f"No supported configuration files found under {target_path}. "
                "Pass a file directly or point --path at an AI agent config directory."
            )

        total = len(files)
        if on_progress:
            on_progress(0, total, None)

        findings: list[Finding] = []
        parse_error_files: list[str] = []
        errors: list[str] = []
        files_skipped = 0

        for index, file_path in enumerate(files, start=1):
            try:
                size = file_path.stat().st_size
            except OSError as exc:
                display = display_path(file_path)
                parse_error_files.append(display)
                errors.append(f"{display}: unable to stat file: {exc}")
                if on_progress:
                    on_progress(index, total, display)
                continue

            if size > MAX_FILE_BYTES:
                files_skipped += 1
                if on_progress:
                    on_progress(index, total, display_path(file_path))
                continue

            document = parse_file(file_path)
            if document.error:
                parse_error_files.append(document.display_path)
                findings.append(_parse_error_finding(document.error, document.display_path))

            for rule in self.rules:
                try:
                    findings.extend(rule.scan(document))
                except Exception as exc:  # pragma: no cover - defensive production guard
                    errors.append(
                        f"{document.display_path}: rule {rule.key} failed: "
                        f"{type(exc).__name__}: {exc}"
                    )

            if on_progress:
                on_progress(index, total, document.display_path)

        unique = _deduplicate(findings)
        unique.sort(
            key=lambda finding: (
                -finding.severity.rank,
                finding.file,
                finding.line or 0,
                finding.rule_id,
                finding.message,
            )
        )
        reported = [finding for finding in unique if finding.severity.rank >= threshold.rank]
        duration_ms = (perf_counter() - started) * 1000

        return ScanResult(
            target=_target_label(target_path),
            findings=reported,
            rules=self.rule_info,
            files_scanned=len(files),
            files_skipped=files_skipped,
            parse_error_files=parse_error_files,
            errors=errors,
            min_severity=threshold,
            total_findings=len(unique),
            duration_ms=duration_ms,
            generated_at=datetime.now(timezone.utc),
        )

    def audit_mcp(
        self,
        target: str | Path,
        *,
        min_severity: Severity | str = Severity.INFO,
        on_progress: ProgressCallback | None = None,
    ) -> ScanResult:
        """Run the specialized MCP rule set against a config path."""

        mcp_engine = Engine(mcp_audit_rules())
        return mcp_engine.scan(
            target,
            min_severity=min_severity,
            on_progress=on_progress,
        )


def _parse_error_finding(error: str, file: str) -> Finding:
    return Finding(
        rule_id=ENGINE_RULE_INFO.id,
        title=ENGINE_RULE_INFO.title,
        severity=ENGINE_RULE_INFO.severity,
        message=(
            f"Could not parse configuration: {error}. Structured MCP and path analysis "
            "was skipped; raw-text secret checks still ran."
        ),
        file=file,
        remediation=ENGINE_RULE_INFO.remediation,
        references=list(ENGINE_RULE_INFO.references),
        tags=list(ENGINE_RULE_INFO.tags),
        metadata={"error": error},
    )


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int | None, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.file, finding.line, finding.message)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def _target_label(target: Path) -> str:
    if target.is_file():
        return display_path(target)
    try:
        resolved = target.resolve()
        return resolved.relative_to(Path.cwd().resolve()).as_posix() or "."
    except (ValueError, OSError):
        return target.as_posix()
