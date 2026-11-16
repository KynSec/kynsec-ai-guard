"""Hardcoded secret and high-entropy credential detection."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field

from ai_guard.core.parser import ConfigDocument, line_number
from ai_guard.rules.base import Finding, Rule, RuleInfo, Severity

_CWE_798 = "https://cwe.mitre.org/data/definitions/798.html"


@dataclass(frozen=True, slots=True)
class SecretPattern:
    rule_id: str
    label: str
    regex: re.Pattern[str]
    group: int = 0
    tags: tuple[str, ...] = field(default_factory=tuple)


SPECIFIC_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        "SEC008",
        "private key block",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
            re.IGNORECASE,
        ),
    ),
    SecretPattern(
        "SEC002",
        "Anthropic API key",
        re.compile(r"\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{20,}\b"),
    ),
    SecretPattern(
        "SEC001",
        "OpenAI API key",
        re.compile(r"\bsk-(?!ant-|live_|test_)(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b"),
    ),
    SecretPattern(
        "SEC003",
        "Hugging Face access token",
        re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"),
    ),
    SecretPattern(
        "SEC004",
        "AWS access key ID",
        re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b"),
    ),
    SecretPattern(
        "SEC004",
        "AWS secret access key",
        re.compile(
            r"\baws_?secret_?access_?key\b[\"']?\s*[:=]\s*[\"']?(?P<value>[A-Za-z0-9/+=]{40})[\"']?",
            re.IGNORECASE,
        ),
        group=1,
    ),
    SecretPattern(
        "SEC005",
        "GitHub token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"),
    ),
    SecretPattern(
        "SEC005",
        "GitLab personal access token",
        re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    ),
    SecretPattern(
        "SEC006",
        "Google API key",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ),
    SecretPattern(
        "SEC007",
        "Slack token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ),
    SecretPattern(
        "SEC011",
        "Stripe secret key",
        re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    ),
    SecretPattern(
        "SEC010",
        "JSON Web Token (JWT)",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
)

GENERIC_ASSIGNMENT = re.compile(
    r"""
    \b(
        api[_-]?key | apikey | access[_-]?key | secret(?:[_-]?key)? |
        client[_-]?secret | auth[_-]?token | bearer[_-]?token |
        private[_-]?key | credential(?:s)? | password | passwd | token
    )\b
    [\"']?\s*[:=]\s*
    (?P<quote>[\"']?)
    (?P<value>[A-Za-z0-9_\-./+=!@$%^&*()?~;]{16,})
    (?P=quote)
    """,
    re.IGNORECASE | re.VERBOSE,
)

PLACEHOLDER_MARKERS = (
    "your_",
    "your-",
    "example",
    "sample",
    "placeholder",
    "changeme",
    "change-me",
    "change_me",
    "replace-me",
    "replace_me",
    "redacted",
    "dummy",
    "fake",
    "insert_",
    "token_here",
    "key_here",
    "xxxx",
    "****",
    "....",
)

PLACEHOLDER_VALUES = {
    "",
    "none",
    "null",
    "true",
    "false",
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "access_key",
    "private_key",
    "changeme",
    "change_me",
    "example",
    "test",
    "dummy",
}

PATH_PREFIXES = ("/", "./", "../", "~/", "\\\\", "c:\\", "d:\\", "file://")

CATALOG: tuple[RuleInfo, ...] = (
    RuleInfo(
        id="SEC001",
        title="OpenAI API key exposed",
        severity=Severity.HIGH,
        description="An OpenAI-style API key is embedded in a local configuration file.",
        remediation=(
            "Revoke the key, rotate it, and load the replacement from a secrets "
            "manager or environment variable."
        ),
        references=("https://platform.openai.com/docs/guides/production-best-practices",),
        tags=("secrets", "openai", "credentials"),
    ),
    RuleInfo(
        id="SEC002",
        title="Anthropic API key exposed",
        severity=Severity.HIGH,
        description="An Anthropic API key is embedded in a local configuration file.",
        remediation=(
            "Revoke the key in the Anthropic console and inject the replacement at runtime."
        ),
        references=("https://docs.anthropic.com/en/api/overview",),
        tags=("secrets", "anthropic", "credentials"),
    ),
    RuleInfo(
        id="SEC003",
        title="Hugging Face token exposed",
        severity=Severity.HIGH,
        description="A Hugging Face access token is hardcoded in configuration.",
        remediation=(
            "Rotate the token and use the Hugging Face CLI login, an environment "
            "variable, or a scoped token."
        ),
        references=("https://huggingface.co/docs/hub/security-tokens",),
        tags=("secrets", "huggingface", "credentials"),
    ),
    RuleInfo(
        id="SEC004",
        title="AWS credential exposed",
        severity=Severity.CRITICAL,
        description="An AWS access key or secret access key is stored in plaintext.",
        remediation=(
            "Deactivate the key pair, rotate credentials, and use short-lived IAM "
            "roles or an AWS profile."
        ),
        references=(
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
            _CWE_798,
        ),
        tags=("secrets", "aws", "credentials"),
    ),
    RuleInfo(
        id="SEC005",
        title="Git provider token exposed",
        severity=Severity.HIGH,
        description="A GitHub or GitLab access token is embedded in configuration.",
        remediation=(
            "Revoke the token, issue a least-privilege replacement, and store it "
            "outside the repository."
        ),
        references=(
            "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure",
            _CWE_798,
        ),
        tags=("secrets", "git", "credentials"),
    ),
    RuleInfo(
        id="SEC006",
        title="Google API key exposed",
        severity=Severity.HIGH,
        description="A Google API key is hardcoded in a local configuration file.",
        remediation=(
            "Restrict the key by API and referrer, rotate it, and prefer service "
            "account credentials."
        ),
        references=("https://cloud.google.com/docs/authentication/api-keys",),
        tags=("secrets", "google", "credentials"),
    ),
    RuleInfo(
        id="SEC007",
        title="Slack token exposed",
        severity=Severity.HIGH,
        description="A Slack bot, app, or user token is present in configuration.",
        remediation=(
            "Revoke and rotate the token in the Slack app dashboard; use OAuth installation flows."
        ),
        references=("https://api.slack.com/authentication/token-types",),
        tags=("secrets", "slack", "credentials"),
    ),
    RuleInfo(
        id="SEC008",
        title="Private key material exposed",
        severity=Severity.CRITICAL,
        description="A PEM/PGP private key block is stored in a configuration or prompt file.",
        remediation=(
            "Remove the key from the file, revoke the certificate if necessary, and "
            "use an OS keychain or secret store."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/321.html",
            _CWE_798,
        ),
        tags=("secrets", "private-key", "cryptography"),
    ),
    RuleInfo(
        id="SEC009",
        title="High-entropy credential value",
        severity=Severity.HIGH,
        description="A credential-looking key contains an assigned value with suspicious entropy.",
        remediation=(
            "Confirm whether the value is a live credential; if so, revoke it and "
            "load it from a secure secret store."
        ),
        references=(_CWE_798,),
        tags=("secrets", "entropy", "credentials"),
    ),
    RuleInfo(
        id="SEC010",
        title="JSON Web Token exposed",
        severity=Severity.MEDIUM,
        description="A JWT is embedded in a local file and may grant access until it expires.",
        remediation=(
            "Rotate the token, keep it out of source control, and use short "
            "expiration and audience restrictions."
        ),
        references=("https://datatracker.ietf.org/doc/html/rfc8725", _CWE_798),
        tags=("secrets", "jwt", "credentials"),
    ),
    RuleInfo(
        id="SEC011",
        title="Stripe secret key exposed",
        severity=Severity.CRITICAL,
        description="A Stripe secret or restricted key is hardcoded in configuration.",
        remediation=(
            "Roll the key in the Stripe dashboard and retrieve it from a secret manager at runtime."
        ),
        references=("https://docs.stripe.com/keys-best-practices",),
        tags=("secrets", "stripe", "credentials"),
    ),
)


class SecretsLeakRule(Rule):
    """Regex and entropy-based credential discovery across every text format."""

    key = "secrets"
    name = "Secrets & credentials"
    catalog = CATALOG

    def scan(self, document: ConfigDocument) -> list[Finding]:
        findings: list[Finding] = []
        claimed: list[tuple[int, int]] = []

        for pattern in SPECIFIC_PATTERNS:
            for match in pattern.regex.finditer(document.raw):
                value = match.group(pattern.group)
                start, end = match.span(pattern.group)
                if not value or _overlaps(claimed, start, end):
                    continue
                if _is_placeholder(value):
                    continue
                if pattern.rule_id == "SEC004" and "EXAMPLE" in value.upper():
                    continue
                claimed.append((start, end))
                findings.append(self._build_finding(document, pattern, value, start, end))

        for match in GENERIC_ASSIGNMENT.finditer(document.raw):
            value = match.group("value")
            key_name = match.group(1).lower()
            start, end = match.span("value")
            if not value or _overlaps(claimed, start, end):
                continue
            if _is_placeholder(value) or _looks_like_path(value) or _looks_like_url(value):
                continue
            if key_name in {"private_key", "privatekey"} and not value.startswith("-----BEGIN"):
                continue
            entropy = shannon_entropy(value)
            if entropy < 3.5:
                continue
            claimed.append((start, end))
            severity = Severity.HIGH if entropy >= 4.0 else Severity.MEDIUM
            findings.append(self._build_generic_finding(document, value, start, entropy, severity))

        return findings

    def _build_finding(
        self,
        document: ConfigDocument,
        pattern: SecretPattern,
        value: str,
        start: int,
        end: int,
    ) -> Finding:
        line = line_number(document.raw, start)
        evidence = _masked_evidence(document, line, value)
        return self.make_finding(
            pattern.rule_id,
            document,
            f"Potential {pattern.label} detected; the value is redacted in this report.",
            line=line,
            evidence=evidence,
            metadata={
                "secret_type": pattern.label,
                "match_length": end - start,
                "entropy": round(shannon_entropy(value), 2),
            },
            tags=list(pattern.tags),
        )

    def _build_generic_finding(
        self,
        document: ConfigDocument,
        value: str,
        start: int,
        entropy: float,
        severity: Severity,
    ) -> Finding:
        line = line_number(document.raw, start)
        evidence = _masked_evidence(document, line, value)
        return self.make_finding(
            "SEC009",
            document,
            (
                "Credential-like assignment contains a high-entropy value "
                f"(entropy={entropy:.2f}); the value is redacted in this report."
            ),
            severity=severity,
            line=line,
            evidence=evidence,
            metadata={
                "secret_type": "generic credential",
                "match_length": len(value),
                "entropy": round(entropy, 2),
            },
            tags=["entropy"],
        )


def shannon_entropy(value: str) -> float:
    """Compute the per-character Shannon entropy of ``value`` in bits."""

    if not value:
        return 0.0
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in Counter(value).values())


def _overlaps(claimed: list[tuple[int, int]], start: int, end: int) -> bool:
    return any(
        start < existing_end and end > existing_start for existing_start, existing_end in claimed
    )


def _is_placeholder(value: str) -> bool:
    normalized = value.strip().strip("\"'")
    lowered = normalized.lower()
    if not normalized or lowered in PLACEHOLDER_VALUES:
        return True
    if lowered.startswith(("$", "{{", "<", "%(")) or lowered.endswith(">"):
        return True
    if any(marker in lowered for marker in PLACEHOLDER_MARKERS):
        return True
    return len(set(normalized)) <= 2


def _looks_like_path(value: str) -> bool:
    lowered = value.lower()
    if lowered.startswith(PATH_PREFIXES):
        return True
    return bool(re.match(r"^[a-z]:[\\/]", lowered))


def _looks_like_url(value: str) -> bool:
    return "://" in value or value.lower().startswith(("http:", "https:"))


def _masked_evidence(document: ConfigDocument, line: int, value: str) -> str:
    masked = mask_secret(value)
    raw_line = document.line_text(line)
    if raw_line:
        return raw_line.replace(value, masked)
    return masked


def mask_secret(value: str) -> str:
    """Redact the middle of a secret while retaining a short fingerprint."""

    if len(value) <= 8:
        return "*" * len(value)
    visible = 4 if len(value) >= 12 else max(1, len(value) // 4)
    hidden = max(6, len(value) - (visible * 2))
    return f"{value[:visible]}{'*' * hidden}{value[-visible:]}"
