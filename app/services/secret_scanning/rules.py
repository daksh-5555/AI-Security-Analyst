"""Versioned catalog of secret-detection rules (ADR-0005).

Each rule is a documented regular expression for one credential format. A rule
marks the *secret span* (the whole match or capturing group 1); only that span is
masked, fingerprinted, and never stored. Rules are ordered by ``priority``: when
spans overlap on a line, the most specific rule wins and generic rules are not
reported for the same text.

The generic assignment rules use Shannon entropy only as an additional filter on
top of a sensitive variable name. Entropy is never the sole detection mechanism.
Detecting a value proves only that a credential-shaped string is committed; the
scanner never tests whether it is valid (no provider calls, no logins).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Final, Literal

from app.core.config import CustomSecretRule

RULE_SET_VERSION: Final[str] = "secret-rules-2026.11.1"

Severity = Literal["critical", "high", "medium", "low"]
FileScope = Literal["any", "dotenv"]

_REMEDIATION_ROTATE: Final[str] = (
    "Treat the credential as exposed: revoke or rotate it with its issuer, remove it "
    "from the code and from version-control history, and load it from a secret "
    "manager or environment variable at runtime."
)
_REMEDIATION_KEY: Final[str] = (
    "Treat the private key as compromised: replace the key pair, revoke any "
    "certificates or authorizations that use it, remove it from the code and from "
    "version-control history, and store keys outside the repository."
)


@dataclass(frozen=True, slots=True)
class SecretRule:
    """One documented detection rule."""

    rule_id: str
    title: str
    description: str
    pattern: re.Pattern[str]
    severity: Severity
    confidence: float
    priority: int
    remediation: str = _REMEDIATION_ROTATE
    secret_group: int = 0
    visible_prefix: int = 0
    min_entropy: float | None = None
    file_scope: FileScope = "any"
    multiline_block: bool = False

    def secret_span(self, match: re.Match[str]) -> tuple[int, int]:
        return match.span(self.secret_group)


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character of ``value``."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


# Documented provider example values and obvious placeholders. Matches on these
# are counted as ``placeholders_ignored`` rather than reported, never dropped silently.
KNOWN_EXAMPLE_VALUES: Final[frozenset[str]] = frozenset(
    {
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    }
)
_PLACEHOLDER_WORDS: Final[frozenset[str]] = frozenset(
    {
        "password",
        "passwd",
        "changeme",
        "change_me",
        "secret",
        "token",
        "example",
        "sample",
        "dummy",
        "test",
        "testing",
        "placeholder",
        "redacted",
        "none",
        "null",
        "undefined",
        "todo",
        "fixme",
    }
)
_PLACEHOLDER_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"""^(
        \$\{?[A-Za-z_][A-Za-z0-9_]*\}?        # $VAR / ${VAR}
      | \{\{.*\}\}                             # {{ template }}
      | <[^<>]+>                               # <your-key>
      | %\([A-Za-z_]+\)s                       # %(name)s
      | (?:your|my|insert|replace)[_\-]\w*     # your_api_key, my-token
      | .*(?:example|placeholder|dummy).*      # anything labelled as such
    )$""",
    re.IGNORECASE | re.VERBOSE,
)


def is_placeholder(value: str) -> bool:
    """Return True for documented example values and obvious placeholders."""
    candidate = value.strip().strip("\"'")
    if not candidate:
        return True
    if candidate in KNOWN_EXAMPLE_VALUES:
        return True
    lowered = candidate.lower()
    if lowered in _PLACEHOLDER_WORDS:
        return True
    if len(set(candidate)) <= 2:  # "xxxxxxxx", "********", "00000000"
        return True
    return bool(_PLACEHOLDER_PATTERN.match(candidate))


_SENSITIVE_NAME = (
    r"[A-Za-z0-9_.\-]*(?:password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key|"
    r"auth[_\-]?key|client[_\-]?secret|private[_\-]?key|credential)[A-Za-z0-9_.\-]*"
)

# Excerpt-only masking (not a detection rule): any value assigned to a secret-like
# name, and any password in URL user-info, is hidden in excerpts whether or not a
# rule reported it, so short or low-entropy passwords never appear in evidence.
EXCERPT_MASK_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"(?i)\b" + _SENSITIVE_NAME + r"[\"']?\s*(?::=|=>|[:=])\s*[\"']?([^\"'\s,;)]+)"),
    re.compile(r"://[^\s:/@'\"]+:([^\s@'\"/]+)@"),
)

BUILTIN_RULES: Final[tuple[SecretRule, ...]] = (
    SecretRule(
        rule_id="secret.private_key_block",
        title="Private key",
        description="PEM/OpenSSH/PGP private key block header.",
        pattern=re.compile(
            r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"
        ),
        severity="high",
        confidence=0.95,
        priority=10,
        remediation=_REMEDIATION_KEY,
        multiline_block=True,
    ),
    SecretRule(
        rule_id="secret.aws_access_key_id",
        title="AWS access key ID",
        description="AWS access key identifier (AKIA/ASIA/ABIA/ACCA followed by 16 characters).",
        pattern=re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"),
        severity="high",
        confidence=0.9,
        priority=20,
        secret_group=1,
        visible_prefix=4,
    ),
    SecretRule(
        rule_id="secret.aws_secret_access_key",
        title="AWS secret access key",
        description="40-character AWS secret key assigned to an aws_secret_access_key name.",
        pattern=re.compile(
            r"(?i)aws_?secret_?access_?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"
        ),
        severity="critical",
        confidence=0.9,
        priority=20,
        secret_group=1,
    ),
    SecretRule(
        rule_id="secret.github_token",
        title="GitHub token",
        description="GitHub personal access, OAuth, user-to-server, or refresh token.",
        pattern=re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\b"),
        severity="high",
        confidence=0.95,
        priority=20,
        secret_group=1,
        visible_prefix=4,
    ),
    SecretRule(
        rule_id="secret.github_fine_grained_token",
        title="GitHub fine-grained token",
        description="GitHub fine-grained personal access token (github_pat_...).",
        pattern=re.compile(r"\b(github_pat_[A-Za-z0-9_]{60,255})\b"),
        severity="high",
        confidence=0.95,
        priority=20,
        secret_group=1,
        visible_prefix=11,
    ),
    SecretRule(
        rule_id="secret.gitlab_token",
        title="GitLab personal access token",
        description="GitLab personal access token (glpat-...).",
        pattern=re.compile(r"\b(glpat-[A-Za-z0-9_\-]{20,64})(?![A-Za-z0-9_\-])"),
        severity="high",
        confidence=0.9,
        priority=20,
        secret_group=1,
        visible_prefix=6,
    ),
    SecretRule(
        rule_id="secret.slack_token",
        title="Slack token",
        description="Slack bot, user, app, or refresh token (xox?-...).",
        pattern=re.compile(r"\b(xox[abprs]-[A-Za-z0-9\-]{10,255})(?![A-Za-z0-9\-])"),
        severity="high",
        confidence=0.85,
        priority=20,
        secret_group=1,
        visible_prefix=5,
    ),
    SecretRule(
        rule_id="secret.stripe_live_key",
        title="Stripe live secret key",
        description="Stripe live secret or restricted key (sk_live_/rk_live_).",
        pattern=re.compile(r"\b((?:sk|rk)_live_[A-Za-z0-9]{20,255})\b"),
        severity="critical",
        confidence=0.9,
        priority=20,
        secret_group=1,
        visible_prefix=8,
    ),
    SecretRule(
        rule_id="secret.google_api_key",
        title="Google API key",
        description="Google API key (AIza followed by 35 characters).",
        pattern=re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})(?![0-9A-Za-z_\-])"),
        severity="medium",
        confidence=0.85,
        priority=20,
        secret_group=1,
        visible_prefix=4,
    ),
    SecretRule(
        rule_id="secret.connection_string_password",
        title="Credential in a connection string",
        description="Database or broker URL with an embedded password (scheme://user:password@host).",
        pattern=re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mariadb|mssql|sqlserver|oracle|mongodb(?:\+srv)?|"
            r"redis|rediss|amqps?|ldaps?|ftp|sftp)(?:\+[a-z0-9]+)?://"
            r"[^\s:/@'\"]+:([^\s@'\"/]{3,})@[^\s'\"]+",
            re.IGNORECASE,
        ),
        severity="high",
        confidence=0.85,
        priority=30,
        secret_group=1,
    ),
    SecretRule(
        rule_id="secret.jwt",
        title="JSON Web Token",
        description="Three base64url segments with JSON headers (eyJ...eyJ...).",
        pattern=re.compile(
            r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})(?![A-Za-z0-9_\-])"
        ),
        severity="medium",
        confidence=0.7,
        priority=40,
        secret_group=1,
    ),
    SecretRule(
        rule_id="secret.dotenv_assignment",
        title="Secret value in an environment file",
        description=(
            "Non-placeholder value assigned to a secret-like variable in a committed "
            ".env-style file."
        ),
        pattern=re.compile(
            r"^\s*(?:export\s+)?" + _SENSITIVE_NAME + r"\s*=\s*[\"']?([^\s\"'#]{8,})",
            re.IGNORECASE,
        ),
        severity="high",
        confidence=0.6,
        priority=80,
        secret_group=1,
        file_scope="dotenv",
    ),
    SecretRule(
        rule_id="secret.generic_assignment",
        title="High-entropy value assigned to a secret-like name",
        description=(
            "Quoted value of at least 16 characters and 3.5 bits/character entropy "
            "assigned to a password/secret/token/key name."
        ),
        pattern=re.compile(
            r"(?i)\b" + _SENSITIVE_NAME + r"[\"']?\s*(?::=|=>|[:=])\s*[\"']([^\"'\s]{16,256})[\"']"
        ),
        severity="medium",
        confidence=0.4,
        priority=90,
        secret_group=1,
        min_entropy=3.5,
    ),
)


def custom_rules(definitions: list[CustomSecretRule]) -> tuple[SecretRule, ...]:
    """Build rules from validated project-specific configuration."""
    rules: list[SecretRule] = []
    for definition in definitions:
        compiled = re.compile(definition.pattern)
        rules.append(
            SecretRule(
                rule_id=definition.rule_id,
                title=definition.title,
                description="Project-specific rule from SECRET_SCAN_CUSTOM_RULES.",
                pattern=compiled,
                severity=definition.severity,
                confidence=0.7,
                priority=50,
                secret_group=1 if compiled.groups == 1 else 0,
            )
        )
    return tuple(rules)


def rule_catalog(definitions: list[CustomSecretRule] | None = None) -> tuple[SecretRule, ...]:
    """All active rules in deterministic priority order."""
    rules = BUILTIN_RULES + custom_rules(definitions or [])
    identifiers = [rule.rule_id for rule in rules]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("secret rule identifiers must be unique")
    return tuple(sorted(rules, key=lambda rule: (rule.priority, rule.rule_id)))


__all__ = [
    "BUILTIN_RULES",
    "EXCERPT_MASK_PATTERNS",
    "KNOWN_EXAMPLE_VALUES",
    "RULE_SET_VERSION",
    "SecretRule",
    "custom_rules",
    "is_placeholder",
    "rule_catalog",
    "shannon_entropy",
]
