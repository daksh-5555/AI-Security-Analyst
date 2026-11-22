"""Secret scanner tests (M2). Every value here is synthetic test data."""

from __future__ import annotations

import json
import logging
import os
import socket
from pathlib import Path

import pytest
from pydantic import SecretStr

from app.core.config import CustomSecretRule, SecretAllowlistEntry, settings
from app.schemas.tooling import ToolResult, ToolStatus
from app.services.analysis_execution_context import (
    AnalysisExecutionAbortedError,
    AnalysisExecutionContext,
)
from app.services.repository_discovery import discover_repository
from app.services.secret_scanning import SecretScannerTool, rule_catalog
from app.services.secret_scanning.rules import is_placeholder, shannon_entropy
from app.services.tooling import ToolContext
from app.services.tooling.files import read_bounded as _read_bounded

FINGERPRINT_KEY = "test-only-fingerprint-key-" + "z" * 32

# Synthetic secrets, assembled so that this test file itself is not a secret.
AWS_ID = "AKIA" + "Z7Q2W3E4R5T6Y7U8"
AWS_SECRET = ("Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0LzXcVbNm1" + "2")[:40]
assert len(AWS_SECRET) == 40
GITHUB = "ghp_" + "A1b2C3d4E5" * 4
GITHUB_FINE = "github_pat_" + "B2c3D4e5F6" * 7
GITLAB = "glpat-" + "x7Y8z9A0b1C2d3E4f5G6"
SLACK = "xoxb-" + "123456789012-abcdefghijKLMN"
STRIPE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
GOOGLE = "AIza" + "SyD8xJ3kQ0lN2mP4oR6sT8uV0wX2yZ4aB6c"
DB_PASSWORD = "S3cr3t-Db-Passw0rd"
JWT = (
    "eyJhbGciOiJIUzI1NiJ9"
    + "."
    + "eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    + "."
    + "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)
GENERIC = "q8Fz3LmP0xR7vT2kN9wB5yC1"
DOTENV = "correcthorsebatterystaple"
KEY_BODY = "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu"
WEAK = "hunter2"

ALL_SECRETS = [
    AWS_ID, AWS_SECRET, GITHUB, GITHUB_FINE, GITLAB, SLACK, STRIPE, GOOGLE,
    DB_PASSWORD, JWT, GENERIC, DOTENV, KEY_BODY, WEAK,
]  # fmt: skip

POSITIVE_CASES = [
    ("secret.aws_access_key_id", "app.py", f'AWS_ID = "{AWS_ID}"'),
    ("secret.aws_secret_access_key", "app.py", f'aws_secret_access_key = "{AWS_SECRET}"'),
    ("secret.github_token", "app.py", f'TOKEN = "{GITHUB}"'),
    ("secret.github_fine_grained_token", "app.py", f'TOKEN = "{GITHUB_FINE}"'),
    ("secret.gitlab_token", "app.py", f'TOKEN = "{GITLAB}"'),
    ("secret.slack_token", "app.py", f'SLACK = "{SLACK}"'),
    ("secret.stripe_live_key", "app.py", f'STRIPE = "{STRIPE}"'),
    ("secret.google_api_key", "app.py", f'MAPS = "{GOOGLE}"'),
    (
        "secret.connection_string_password",
        "settings.py",
        f'DB = "postgresql://app:{DB_PASSWORD}@db.internal:5432/app"',
    ),
    ("secret.jwt", "client.js", f'const t = "{JWT}";'),
    ("secret.generic_assignment", "config.py", f'client_secret = "{GENERIC}"'),
    ("secret.dotenv_assignment", ".env", f"DB_PASSWORD={DOTENV}"),
]


@pytest.fixture
def allowed_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "repositories"
    root.mkdir()
    monkeypatch.setattr(settings, "repository_allowed_roots", [root])
    monkeypatch.setattr(settings, "evidence_fingerprint_key", SecretStr(FINGERPRINT_KEY))
    return root


def make_repo(root: Path, files: dict[str, str | bytes], name: str = "repo") -> Path:
    repo = root / name
    for relative, content in files.items():
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
    repo.mkdir(exist_ok=True)
    return repo


def scan(repo: Path, *, execution: AnalysisExecutionContext | None = None) -> ToolResult:
    context = ToolContext(
        execution=execution or AnalysisExecutionContext(60),
        discovery=discover_repository(repo),
    )
    return SecretScannerTool().run(context)


def rules_found(result: ToolResult) -> set[str]:
    return {record.provenance.rule_id for record in result.evidence}


def assert_no_secret(text: str) -> None:
    for value in ALL_SECRETS:
        assert value not in text, "a synthetic secret leaked"


@pytest.mark.parametrize(("rule_id", "filename", "line"), POSITIVE_CASES)
def test_each_rule_detects_its_synthetic_secret(
    allowed_root: Path, rule_id: str, filename: str, line: str
) -> None:
    result = scan(make_repo(allowed_root, {filename: line + "\n"}))

    assert rule_id in rules_found(result)
    record = next(item for item in result.evidence if item.provenance.rule_id == rule_id)
    assert record.location.path == filename
    assert record.location.line == 1
    assert record.fingerprint is not None and len(record.fingerprint) == 64
    assert record.content_hash is None  # plain hashes of secrets are never stored
    assert_no_secret(result.model_dump_json())


def test_private_key_header_is_reported_and_body_never_stored(allowed_root: Path) -> None:
    key = f"-----BEGIN RSA PRIVATE KEY-----\n{KEY_BODY}\n-----END RSA PRIVATE KEY-----\n"
    result = scan(make_repo(allowed_root, {"deploy/id_rsa": key}))

    record = next(r for r in result.evidence if r.provenance.rule_id == "secret.private_key_block")
    assert record.redacted_excerpt == "-----BEGIN RSA PRIVATE KEY-----"
    assert record.metadata["severity"] == "high"
    assert KEY_BODY not in result.model_dump_json()


@pytest.mark.parametrize(
    "line",
    [
        'name = "plain string value"',
        'AWS_ID = "AKIA123"',  # too short
        'checksum = "d41d8cd98f00b204e9800998ecf8427e"',  # not a secret-like name
        'request_id = "550e8400-e29b-41d4-a716-446655440000"',
        'password = "short"',  # below generic length
        'token = "aaaaaaaaaaaaaaaaaaaaaaaa"',  # low entropy
        'url = "https://example.com/path?q=1"',
        "DB = 'postgresql://localhost:5432/app'",  # no credentials
        "# eyJ is a common prefix but not a token",
    ],
)
def test_near_misses_are_not_reported(allowed_root: Path, line: str) -> None:
    result = scan(make_repo(allowed_root, {"app.py": line + "\n"}))
    assert result.evidence == []


@pytest.mark.parametrize(
    "line",
    [
        'AWS_ID = "AKIAIOSFODNN7EXAMPLE"',
        'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
        'api_key = "${API_KEY_FROM_ENVIRONMENT}"',
        'client_secret = "<your-client-secret-here>"',
        'DB = "postgresql://app:changeme@db:5432/app"',
        'api_key = "your_api_key_goes_here_please"',
    ],
)
def test_placeholders_are_counted_not_reported(allowed_root: Path, line: str) -> None:
    result = scan(make_repo(allowed_root, {"app.py": line + "\n"}))
    assert result.evidence == []
    assert result.counts["placeholders_ignored"] >= 1
    assert "placeholders_ignored" in {item.code for item in result.limitations}


def test_dotenv_rule_only_applies_to_env_files(allowed_root: Path) -> None:
    line = f"DB_PASSWORD={DOTENV}\n"
    result = scan(make_repo(allowed_root, {"notes.txt": line, "config/.env.production": line}))
    assert {(r.provenance.rule_id, r.location.path) for r in result.evidence} == {
        ("secret.dotenv_assignment", "config/.env.production")
    }


def test_excerpts_hide_every_value_on_the_line(allowed_root: Path) -> None:
    line = f'token = "{GITHUB}" ; password = "{WEAK}" ; DB = "mysql://u:{DB_PASSWORD}@h/x"\n'
    result = scan(make_repo(allowed_root, {"app.py": line}))

    assert {"secret.github_token", "secret.connection_string_password"} <= rules_found(result)
    for record in result.evidence:
        assert record.redacted_excerpt is not None
        assert len(record.redacted_excerpt) <= 240
    assert_no_secret(result.model_dump_json())


def test_long_lines_produce_bounded_excerpts_around_the_secret(allowed_root: Path) -> None:
    line = "x = 1; " * 200 + f'key = "{GITHUB}"' + "; y = 2" * 200 + "\n"
    result = scan(make_repo(allowed_root, {"app.py": line}))
    record = result.evidence[0]
    assert record.redacted_excerpt is not None
    assert "********" in record.redacted_excerpt
    assert len(record.redacted_excerpt) <= 240


def test_same_secret_in_one_line_is_reported_once_by_the_most_specific_rule(
    allowed_root: Path,
) -> None:
    result = scan(make_repo(allowed_root, {"app.py": f'api_token = "{GITHUB}"\n'}))
    assert rules_found(result) == {"secret.github_token"}


def test_results_are_deterministic_with_a_configured_key(allowed_root: Path) -> None:
    repo = make_repo(allowed_root, {"a.py": f'T = "{GITHUB}"\n', "b.py": f'T = "{GITHUB}"\n'})
    first, second = scan(repo), scan(repo)

    assert [r.evidence_key for r in first.evidence] == [r.evidence_key for r in second.evidence]
    assert [r.fingerprint for r in first.evidence] == [r.fingerprint for r in second.evidence]
    # The same value in two files shares one fingerprint (deduplicated into one finding).
    assert len({r.fingerprint for r in first.evidence}) == 1
    assert "fingerprint_key_ephemeral" not in {item.code for item in first.limitations}


def test_fingerprints_depend_on_the_key_and_unset_key_is_reported(
    allowed_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_repo(allowed_root, {"a.py": f'T = "{GITHUB}"\n'})
    configured = scan(repo).evidence[0].fingerprint
    monkeypatch.setattr(settings, "evidence_fingerprint_key", None)
    ephemeral = scan(repo)

    assert ephemeral.evidence[0].fingerprint != configured
    assert "fingerprint_key_ephemeral" in {item.code for item in ephemeral.limitations}


def test_test_and_example_paths_are_reported_with_lower_confidence(allowed_root: Path) -> None:
    line = f'TOKEN = "{GITHUB}"\n'
    result = scan(
        make_repo(
            allowed_root,
            {"src/app.py": line, "tests/test_app.py": line, "docs/config.example.py": line},
        )
    )
    by_path = {r.location.path: r for r in result.evidence}
    assert set(by_path) == {"src/app.py", "tests/test_app.py", "docs/config.example.py"}
    assert by_path["src/app.py"].metadata["file_context"] == "source"
    assert by_path["tests/test_app.py"].metadata["file_context"] == "test_fixture"
    assert by_path["docs/config.example.py"].metadata["file_context"] == "example"
    assert (
        by_path["tests/test_app.py"].metadata["confidence"]
        < by_path["src/app.py"].metadata["confidence"]
    )


def test_policy_exclusions_are_counted_but_not_partial(allowed_root: Path) -> None:
    secret_line = f'T = "{GITHUB}"\n'
    result = scan(
        make_repo(
            allowed_root,
            {
                "package-lock.json": secret_line,
                "static/app.min.js": secret_line,
                "vendor/lib/x.py": secret_line,
                "image.png": secret_line,
                "blob.dat": b"\x00\x01" + secret_line.encode(),
                "src/ok.py": "x = 1\n",
            },
        )
    )
    assert result.evidence == []
    assert result.status is ToolStatus.COMPLETED
    for reason in ("lock_file", "generated", "vendored", "binary"):
        assert result.counts[f"skipped_{reason}"] >= 1


def test_oversized_files_make_the_result_partial(
    allowed_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "secret_scan_max_file_size_bytes", 64)
    result = scan(make_repo(allowed_root, {"big.py": f'T = "{GITHUB}"\n' + "#" * 200}))
    assert result.status is ToolStatus.PARTIAL
    assert result.counts["skipped_oversize"] == 1
    assert not result.is_clean


@pytest.mark.parametrize(
    ("setting", "value", "code"),
    [
        ("secret_scan_max_files", 1, "truncated.max_files"),
        ("secret_scan_max_total_bytes", 40, "truncated.max_total_bytes"),
        ("secret_scan_max_matches", 1, "truncated.max_matches"),
    ],
)
def test_budgets_stop_scanning_and_report_partial(
    allowed_root: Path, monkeypatch: pytest.MonkeyPatch, setting: str, value: int, code: str
) -> None:
    monkeypatch.setattr(settings, setting, value)
    files = {f"f{index}.py": f'T{index} = "{GITHUB}{index}"\n' for index in range(3)}
    result = scan(make_repo(allowed_root, files))
    assert result.status is ToolStatus.PARTIAL
    assert code in {item.code for item in result.limitations}


def test_allowlist_is_narrow_counted_and_explained(
    allowed_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        settings,
        "secret_scan_allowlist",
        [
            SecretAllowlistEntry(
                rule_id="secret.github_token",
                path_glob="docs/*.md",
                reason="Revoked token kept in the incident write-up.",
            )
        ],
    )
    line = f'TOKEN = "{GITHUB}"\n'
    result = scan(make_repo(allowed_root, {"docs/incident.md": line, "src/app.py": line}))

    assert {r.location.path for r in result.evidence} == {"src/app.py"}
    assert result.counts["allowlisted"] == 1
    limitation = next(item for item in result.limitations if item.code.startswith("allowlisted."))
    assert "incident write-up" in limitation.detail


def test_custom_rules_extend_the_catalog(
    allowed_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        settings,
        "secret_scan_custom_rules",
        [
            CustomSecretRule(
                rule_id="custom.acme_key",
                title="ACME internal key",
                pattern=r"\b(acme_[0-9a-f]{24})\b",
                severity="high",
            )
        ],
    )
    result = scan(make_repo(allowed_root, {"app.py": 'k = "acme_0123456789abcdef01234567"\n'}))
    assert "custom.acme_key" in rules_found(result)
    assert "acme_0123456789abcdef01234567" not in result.model_dump_json()


def test_catalog_is_ordered_and_unique() -> None:
    catalog = rule_catalog()
    assert [rule.priority for rule in catalog] == sorted(rule.priority for rule in catalog)
    assert len({rule.rule_id for rule in catalog}) == len(catalog)
    with pytest.raises(ValueError):
        rule_catalog(
            [CustomSecretRule(rule_id="custom.x", title="X1", pattern="abc1")] * 2  # duplicate
        )


def test_entropy_and_placeholder_helpers() -> None:
    assert shannon_entropy("aaaaaaaa") == 0
    assert shannon_entropy(GENERIC) > 3.5
    assert is_placeholder("${TOKEN}") and is_placeholder("xxxxxxxx") and is_placeholder("changeme")
    assert not is_placeholder("mySuperS3cretValue")


def test_scanner_never_follows_symlinks_or_leaves_the_root(allowed_root: Path) -> None:
    repo = make_repo(allowed_root, {"real.py": f'T = "{GITHUB}"\n'})
    outside = allowed_root.parent / "outside.py"
    outside.write_text(f'T = "{STRIPE}"\n', encoding="utf-8")
    link = repo / "link.py"
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")

    assert _read_bounded(repo, "link.py", 1024)[1] == "symlink"
    assert _read_bounded(repo, "../outside.py", 1024)[1] == "outside_root"
    assert _read_bounded(repo, "/etc/passwd", 1024)[1] == "outside_root"
    result = scan(repo)
    assert STRIPE not in result.model_dump_json()
    assert "secret.stripe_live_key" not in rules_found(result)


def test_scan_makes_no_network_calls_and_logs_no_secrets(
    allowed_root: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    caplog.set_level(logging.DEBUG)
    files = {f"f{index}{name}": line + "\n" for index, (_, name, line) in enumerate(POSITIVE_CASES)}
    result = scan(make_repo(allowed_root, files))

    assert len(result.evidence) >= len(POSITIVE_CASES) - 1
    assert_no_secret(result.model_dump_json())
    assert_no_secret(json.dumps([vars(record) for record in caplog.records], default=str))


def test_cancellation_stops_the_scan(allowed_root: Path) -> None:
    execution = AnalysisExecutionContext(60)
    execution.request_abort()
    with pytest.raises(AnalysisExecutionAbortedError):
        scan(make_repo(allowed_root, {"a.py": "x = 1\n"}), execution=execution)


def test_windows_style_relative_paths_cannot_escape(allowed_root: Path) -> None:
    repo = make_repo(allowed_root, {"a.py": "x = 1\n"})
    assert _read_bounded(repo, "..\\..\\secret.txt", 1024)[0] is None
    entry = SecretAllowlistEntry(
        rule_id="secret.jwt", path_glob="docs\\examples\\*.md", reason="Example JWTs in docs."
    )
    assert entry.path_glob == "docs/examples/*.md"
