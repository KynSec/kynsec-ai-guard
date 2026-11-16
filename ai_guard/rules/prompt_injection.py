"""Static heuristic analysis for prompt injection and unsafe instructions."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ai_guard.core.parser import ConfigDocument, ConfigFormat
from ai_guard.rules.base import Finding, Rule, RuleInfo, Severity, clip

CATALOG: tuple[RuleInfo, ...] = (
    RuleInfo(
        id="PROMPT001",
        title="Instruction override or jailbreak language",
        severity=Severity.HIGH,
        description=(
            "Instructions attempt to override prior rules, impersonate a jailbroken "
            "model, or reveal the system prompt."
        ),
        remediation=(
            "Remove override language, enforce immutable system instructions, and "
            "add prompt-injection filtering."
        ),
        references=(
            "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
            "https://cwe.mitre.org/data/definitions/77.html",
        ),
        tags=("prompt", "llm01", "injection"),
    ),
    RuleInfo(
        id="PROMPT002",
        title="Exfiltration or destructive payload in instructions",
        severity=Severity.CRITICAL,
        description=(
            "A prompt or instruction contains commands associated with secret theft, "
            "remote code execution, or destructive actions."
        ),
        remediation=(
            "Remove the payload, isolate the prompt, rotate any exposed credentials, "
            "and review agent tool permissions."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/78.html",
            "https://cwe.mitre.org/data/definitions/200.html",
        ),
        tags=("prompt", "exfiltration", "rce"),
    ),
    RuleInfo(
        id="PROMPT003",
        title="Safety bypass or hidden behavior directive",
        severity=Severity.HIGH,
        description=(
            "Instructions ask the agent to hide actions, suppress warnings, or "
            "disable safety controls."
        ),
        remediation=(
            "Reject instructions that hide activity or disable safeguards; require "
            "auditable, user-visible behavior."
        ),
        references=(
            "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
            "https://cwe.mitre.org/data/definitions/693.html",
        ),
        tags=("prompt", "safety", "stealth"),
    ),
    RuleInfo(
        id="PROMPT004",
        title="Hidden Unicode control characters",
        severity=Severity.HIGH,
        description=(
            "Invisible or bidirectional Unicode control characters can conceal "
            "instructions from human reviewers."
        ),
        remediation=(
            "Strip control characters, review the canonical text, and enforce a "
            "printable-text policy for prompts."
        ),
        references=(
            "https://trojansource.codes/",
            "https://www.unicode.org/reports/tr36/",
        ),
        tags=("prompt", "unicode", "obfuscation"),
    ),
    RuleInfo(
        id="PROMPT005",
        title="Permission or privilege escalation directive",
        severity=Severity.MEDIUM,
        description=("Instructions request excessive privileges or bypass human confirmation."),
        remediation=(
            "Require explicit user confirmation and grant the minimum privileges "
            "needed for the task."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/862.html",
            "https://cwe.mitre.org/data/definitions/732.html",
        ),
        tags=("prompt", "authorization", "least-privilege"),
    ),
)


@dataclass(frozen=True, slots=True)
class PromptPattern:
    rule_id: str
    label: str
    message: str
    regex: re.Pattern[str]


@dataclass(frozen=True, slots=True)
class PromptScope:
    text: str
    start_line: int | None
    origin: str


PROMPT_PATTERNS: tuple[PromptPattern, ...] = (
    PromptPattern(
        "PROMPT001",
        "instruction override",
        "Instruction-override language attempts to replace existing safety rules.",
        re.compile(
            r"\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:of\s+)?(?:the\s+)?"
            r"(?:previous|prior|above|earlier|preceding)\s+"
            r"(?:instructions?|prompts?|rules?|directives?|messages?)",
            re.IGNORECASE,
        ),
    ),
    PromptPattern(
        "PROMPT001",
        "jailbreak persona",
        "Jailbreak or unrestricted-persona language was found.",
        re.compile(
            r"\byou\s+are\s+now\s+(?:dan|jailbroken|in\s+developer\s+mode|"
            r"unrestricted|uncensored|unfiltered|free\s+from\s+(?:all\s+)?"
            r"(?:rules|restrictions))\b",
            re.IGNORECASE,
        ),
    ),
    PromptPattern(
        "PROMPT001",
        "system prompt disclosure",
        "Instructions request disclosure of the hidden system prompt.",
        re.compile(
            r"\b(?:reveal|print|output|repeat|leak|show|display)\s+(?:me\s+)?"
            r"(?:your|the)\s+(?:hidden\s+|full\s+|original\s+|exact\s+)?"
            r"system\s+(?:prompt|message|instructions?)\b",
            re.IGNORECASE,
        ),
    ),
    PromptPattern(
        "PROMPT002",
        "secret exfiltration",
        "Instructions direct secret or credential data toward an external destination.",
        re.compile(
            r"\b(?:exfiltrate|send|post|upload|transmit|forward)\s+"
            r"(?:the\s+|all\s+|any\s+)?(?:contents?\s+of\s+|data\s+from\s+)?"
            r"[^\n]{0,80}?(?:\.env|id_rsa|\.ssh|\.aws|credentials?|secrets?|"
            r"tokens?|api[_\s-]?keys?)",
            re.IGNORECASE,
        ),
    ),
    PromptPattern(
        "PROMPT002",
        "remote script execution",
        "Instructions pipe downloaded content directly into an interpreter.",
        re.compile(
            r"\b(?:curl|wget)\b[^\n]{0,160}\|\s*(?:sudo\s+)?"
            r"(?:(?:ba|z|k)?sh|python3?|node|perl|ruby)\b",
            re.IGNORECASE,
        ),
    ),
    PromptPattern(
        "PROMPT002",
        "encoded payload execution",
        "Instructions decode and execute an encoded payload.",
        re.compile(
            r"\bbase64\s+(?:-d|--decode)\b[^\n]{0,80}\|\s*(?:ba|z|k)?sh\b",
            re.IGNORECASE,
        ),
    ),
    PromptPattern(
        "PROMPT002",
        "destructive filesystem command",
        "Instructions contain a destructive filesystem command.",
        re.compile(
            r"\brm\s+-rf\s+(?:--no-preserve-root\s+)?(?:/|~|\$HOME|\*)"
            r"(?=\s|$|[\"'])",
            re.IGNORECASE,
        ),
    ),
    PromptPattern(
        "PROMPT002",
        "reverse shell",
        "Instructions contain reverse-shell or raw network execution primitives.",
        re.compile(
            r"(?:\breverse\s+shell\b|\bnc\s+-e\b|\bncat\s+-e\b|"
            r"/dev/tcp/|\bbash\s+-i\s+>&)",
            re.IGNORECASE,
        ),
    ),
    PromptPattern(
        "PROMPT003",
        "hidden action directive",
        "Instructions ask the agent to hide activity from the user.",
        re.compile(
            r"\b(?:do\s+not|don't|never)\s+(?:tell|inform|warn|alert|notify)\s+"
            r"(?:the\s+)?user\b",
            re.IGNORECASE,
        ),
    ),
    PromptPattern(
        "PROMPT003",
        "concealment directive",
        "Instructions ask the agent to conceal its actions or behavior.",
        re.compile(
            r"\b(?:hide|conceal)\s+(?:this|the|your)\s+"
            r"(?:action|actions|instruction|instructions|activity|behaviour|behavior)\s+"
            r"from\s+(?:the\s+)?user\b",
            re.IGNORECASE,
        ),
    ),
    PromptPattern(
        "PROMPT003",
        "safety control bypass",
        "Instructions attempt to disable safety, security, or moderation controls.",
        re.compile(
            r"\b(?:disable|turn\s+off|bypass|remove)\s+(?:all\s+)?"
            r"(?:safety|security|guardrails?|filters?|restrictions?|policies|moderation)\b",
            re.IGNORECASE,
        ),
    ),
    PromptPattern(
        "PROMPT003",
        "unaudited operation",
        "Instructions ask the agent to suppress logging or auditing.",
        re.compile(
            r"\b(?:do\s+not|don't|never)\s+(?:log|record|audit|report)\b",
            re.IGNORECASE,
        ),
    ),
    PromptPattern(
        "PROMPT005",
        "automatic approval",
        "Instructions require automatic approval or execution without human review.",
        re.compile(
            r"\b(?:always|automatically)\s+(?:approve|allow|execute|run|accept)\s+"
            r"[^\n]{0,60}?(?:without|no)\s+(?:asking|confirmation|permission|review)",
            re.IGNORECASE,
        ),
    ),
    PromptPattern(
        "PROMPT005",
        "confirmation bypass",
        "Instructions prohibit asking the user for permission or confirmation.",
        re.compile(
            r"\b(?:never|do\s+not|don't)\s+(?:ask|request)\s+(?:for\s+)?"
            r"(?:confirmation|permission|approval)\b",
            re.IGNORECASE,
        ),
    ),
    PromptPattern(
        "PROMPT005",
        "unrestricted access request",
        "Instructions request unrestricted shell, filesystem, or administrative access.",
        re.compile(
            r"\b(?:unrestricted|full|root|admin(?:istrator)?)\s+"
            r"(?:shell|filesystem|file\s+system|system|admin)\s+access\b",
            re.IGNORECASE,
        ),
    ),
    PromptPattern(
        "PROMPT005",
        "privileged command directive",
        "Instructions request privileged or world-writable command execution.",
        re.compile(
            r"(?:\bsudo\s+|\bchmod\s+777\b|\bchown\s+root\b)",
            re.IGNORECASE,
        ),
    ),
)

HIDDEN_CONTROLS = {
    "\u00ad": "soft hyphen",
    "\u200b": "zero-width space",
    "\u200c": "zero-width non-joiner",
    "\u200d": "zero-width joiner",
    "\u200e": "left-to-right mark",
    "\u200f": "right-to-left mark",
    "\u202a": "left-to-right embedding",
    "\u202b": "right-to-left embedding",
    "\u202c": "pop directional formatting",
    "\u202d": "left-to-right override",
    "\u202e": "right-to-left override",
    "\u2060": "word joiner",
    "\u2066": "left-to-right isolate",
    "\u2067": "right-to-left isolate",
    "\u2068": "first strong isolate",
    "\u2069": "pop directional isolate",
    "\ufeff": "zero-width no-break space",
}


class PromptInjectionRule(Rule):
    """Heuristic detection of manipulation and unsafe directions in prompts."""

    key = "prompt"
    name = "Prompt injection heuristics"
    catalog = CATALOG

    def scan(self, document: ConfigDocument) -> list[Finding]:
        scopes = _prompt_scopes(document)

        findings: list[Finding] = []
        seen: set[tuple[str, int]] = set()

        for scope in scopes:
            for pattern in PROMPT_PATTERNS:
                for match in pattern.regex.finditer(scope.text):
                    line = _match_line(document, scope, match.start())
                    key = (pattern.rule_id, line or -1)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        self.make_finding(
                            pattern.rule_id,
                            document,
                            f"{pattern.message} Matched in {scope.origin}.",
                            severity=self.info(pattern.rule_id).severity,
                            line=line,
                            evidence=_scope_line(document, scope, match.start()),
                            metadata={
                                "pattern": pattern.label,
                                "field": scope.origin,
                            },
                        )
                    )

        findings.extend(self._hidden_unicode_findings(document, scopes))
        return findings

    def _hidden_unicode_findings(
        self,
        document: ConfigDocument,
        scopes: list[PromptScope],
    ) -> list[Finding]:
        if not scopes:
            scopes = _raw_scopes(document)

        findings: list[Finding] = []
        seen: set[int] = set()
        for scope in scopes:
            indexes = [
                (index, character)
                for index, character in enumerate(scope.text)
                if character in HIDDEN_CONTROLS
            ]
            if not indexes:
                continue
            line = _match_line(document, scope, indexes[0][0])
            marker = line or -1
            if marker in seen:
                continue
            seen.add(marker)
            counts: dict[str, int] = {}
            for _, character in indexes:
                counts[character] = counts.get(character, 0) + 1
            descriptions = ", ".join(
                f"{HIDDEN_CONTROLS[character]} x{count}" for character, count in counts.items()
            )
            physical = document.line_text(line) if line else None
            evidence = _visualize_controls(physical or scope.text)
            findings.append(
                self.make_finding(
                    "PROMPT004",
                    document,
                    (
                        "Hidden Unicode control characters were found and can conceal "
                        f"instructions from reviewers: {descriptions}."
                    ),
                    severity=Severity.HIGH,
                    line=line,
                    evidence=evidence,
                    metadata={
                        "field": scope.origin,
                        "characters": {
                            f"U+{ord(character):04X}": count for character, count in counts.items()
                        },
                    },
                )
            )
        return findings


def _prompt_scopes(document: ConfigDocument) -> list[PromptScope]:
    if document.format in {ConfigFormat.MARKDOWN, ConfigFormat.TEXT, ConfigFormat.UNKNOWN}:
        return _raw_scopes(document)
    return _all_string_scopes(document)


def _all_string_scopes(document: ConfigDocument) -> list[PromptScope]:
    scopes: list[PromptScope] = []
    for path, value in document.iter_leaf_values():
        if isinstance(value, str) and value:
            scopes.append(_structured_scope(document, value, ".".join(path)))
    return scopes


def _raw_scopes(document: ConfigDocument) -> list[PromptScope]:
    if not document.raw:
        return []
    return [PromptScope(document.raw, 1, f"{document.filename} text")]


def _structured_scope(document: ConfigDocument, value: str, origin: str) -> PromptScope:
    first_line = next(
        (line.strip() for line in value.splitlines() if line.strip()),
        "",
    )
    start_line = document.find_line(first_line) if first_line else None
    return PromptScope(value, start_line, origin)


def _match_line(document: ConfigDocument, scope: PromptScope, index: int) -> int | None:
    if scope.start_line is not None:
        return scope.start_line + scope.text.count("\n", 0, index)
    text_line = _text_line(scope.text, index)
    if text_line:
        line = document.find_line(text_line)
        if line is not None:
            return line
    return None


def _scope_line(document: ConfigDocument, scope: PromptScope, index: int) -> str | None:
    line = _match_line(document, scope, index)
    if line is not None:
        physical = document.line_text(line)
        if physical:
            return clip(physical)
    return clip(_text_line(scope.text, index))


def _text_line(text: str, index: int) -> str:
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    if end < 0:
        end = len(text)
    return text[start:end].strip()


def _visualize_controls(text: str) -> str:
    rendered = "".join("?" if character in HIDDEN_CONTROLS else character for character in text)
    return clip(rendered) or ""
