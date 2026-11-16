"""Built-in security rules shipped with AI-Guard-CLI."""

from __future__ import annotations

from ai_guard.rules.base import Finding, Rule, RuleInfo, Severity
from ai_guard.rules.mcp_security import MCPSecurityRule
from ai_guard.rules.path_Traversal import PathTraversalRule
from ai_guard.rules.prompt_injection import PromptInjectionRule
from ai_guard.rules.secrets_leak import SecretsLeakRule

ALL_RULES: tuple[Rule, ...] = (
    MCPSecurityRule(),
    SecretsLeakRule(),
    PathTraversalRule(),
    PromptInjectionRule(),
)


def default_rules() -> list[Rule]:
    """Return a fresh list of every built-in rule."""

    return list(ALL_RULES)


def mcp_audit_rules() -> list[Rule]:
    """Return the rule set used by the specialized MCP audit command."""

    return [MCPSecurityRule(), SecretsLeakRule(), PathTraversalRule()]


def all_rule_info() -> list[RuleInfo]:
    return [info for rule in ALL_RULES for info in rule.catalog]


__all__ = [
    "ALL_RULES",
    "Finding",
    "MCPSecurityRule",
    "PathTraversalRule",
    "PromptInjectionRule",
    "Rule",
    "RuleInfo",
    "SecretsLeakRule",
    "Severity",
    "all_rule_info",
    "default_rules",
    "mcp_audit_rules",
]
