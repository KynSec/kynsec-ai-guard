"""Core rule contracts and finding models."""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field

from ai_guard.core.parser import ConfigDocument


class Severity(str, Enum):
    """Finding severity, ordered from informational to critical."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def parse(cls, value: str | Severity) -> Severity:
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).strip().lower())
        except ValueError as exc:
            choices = ", ".join(item.value for item in cls)
            raise ValueError(f"Unknown severity {value!r}. Choose one of: {choices}") from exc

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank


_SEVERITY_RANK = {
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}


class RuleInfo(BaseModel):
    """Machine-readable metadata for one rule identifier."""

    model_config = ConfigDict(frozen=True)

    id: str
    title: str
    severity: Severity
    description: str
    remediation: str
    references: tuple[str, ...] = Field(default_factory=tuple)
    tags: tuple[str, ...] = Field(default_factory=tuple)


class Finding(BaseModel):
    """A single security observation produced by a rule."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    title: str
    severity: Severity
    message: str
    file: str
    line: int | None = Field(default=None, ge=1)
    evidence: str | None = None
    remediation: str | None = None
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Rule(ABC):
    """Base class implemented by every AI-Guard security rule family."""

    key: ClassVar[str]
    name: ClassVar[str]
    catalog: ClassVar[tuple[RuleInfo, ...]] = ()

    @property
    def rule_ids(self) -> frozenset[str]:
        return frozenset(info.id for info in self.catalog)

    def info(self, rule_id: str) -> RuleInfo:
        for info in self.catalog:
            if info.id == rule_id:
                return info
        raise KeyError(f"Rule {self.__class__.__name__} has no metadata for {rule_id!r}")

    def make_finding(
        self,
        rule_id: str,
        document: ConfigDocument,
        message: str,
        *,
        severity: Severity | None = None,
        line: int | None = None,
        evidence: str | None = None,
        metadata: dict[str, Any] | None = None,
        tags: list[str] | None = None,
    ) -> Finding:
        info = self.info(rule_id)
        if line is None and evidence:
            line = document.find_line(evidence)
        if line is not None and line < 1:
            line = None
        return Finding(
            rule_id=rule_id,
            title=info.title,
            severity=severity or info.severity,
            message=message,
            file=document.display_path,
            line=line,
            evidence=clip(evidence),
            remediation=info.remediation,
            references=list(info.references),
            tags=[*info.tags, *(tags or [])],
            metadata=metadata or {},
        )

    @abstractmethod
    def scan(self, document: ConfigDocument) -> list[Finding]:
        """Return all findings for ``document``. Never raise for malformed input."""


def clip(value: str | None, limit: int = 320) -> str | None:
    """Collapse whitespace and bound evidence length for reports."""

    if value is None:
        return None
    normalized = " ".join(str(value).split())
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 3].rstrip() + "..."


def first_line(document: ConfigDocument, *needles: object) -> int | None:
    """Find the first line matching any of the supplied scalar values."""

    for needle in needles:
        if needle is None or isinstance(needle, (dict, list, tuple)):
            continue
        text = str(needle)
        if not text:
            continue
        line = document.find_line(text)
        if line is not None:
            return line
    return None


def flatten_strings(value: object) -> list[str]:
    """Recursively flatten strings from lists/tuples/scalars."""

    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        output: list[str] = []
        for item in value:
            output.extend(flatten_strings(item))
        return output
    return [str(value)]
