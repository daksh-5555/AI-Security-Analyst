"""Filesystem-boundary and path-disclosure regression tests for repositories."""

import os
from pathlib import Path

import httpx
import pytest
from disclosure_helpers import assert_no_path_disclosure

from app.core.config import settings
from app.services.attack_surface import _read_source_text, _validate_source_path
from app.services.repository_targets import (
    InvalidRepositoryLocationError,
    validate_repository_location,
)
from app.services.technology_detector import _read_manifest_text, _validate_manifest_path

ASSESSMENTS_URL = "/api/v1/assessments"

pytestmark = pytest.mark.usefixtures("assessment_client")


@pytest.fixture
def repository_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    root = tmp_path / "repositories"
    root.mkdir()
    monkeypatch.setattr(settings, "repository_allowed_roots", [root])
    return root


async def create_assessment(client: httpx.AsyncClient) -> dict[str, object]:
    response = await client.post(
        ASSESSMENTS_URL,
        json={"assessment_type": "repository"},
    )
    assert response.status_code == 201
    return response.json()


async def register_target(
    client: httpx.AsyncClient,
    assessment_id: object,
    location: Path,
) -> httpx.Response:
    return await client.post(
        f"{ASSESSMENTS_URL}/{assessment_id}/repository",
        json={"source_kind": "local_path", "location": str(location)},
    )


def test_sibling_prefix_is_not_inside_allowed_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    allowed = tmp_path / "repositories"
    sibling = tmp_path / "repositories-evil"
    allowed.mkdir()
    sibling.mkdir()
    monkeypatch.setattr(settings, "repository_allowed_roots", [allowed])

    with pytest.raises(InvalidRepositoryLocationError, match="outside the allowed roots"):
        validate_repository_location(str(sibling))


@pytest.mark.skipif(os.name != "nt", reason="Windows case-insensitive path semantics")
def test_windows_case_insensitive_containment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    allowed = tmp_path / "repositories"
    target = allowed / "Project"
    allowed.mkdir()
    target.mkdir()
    monkeypatch.setattr(
        settings,
        "repository_allowed_roots",
        [Path(str(allowed).upper())],
    )

    resolved = validate_repository_location(str(target).lower())

    assert resolved == target.resolve()


@pytest.mark.skipif(os.name != "nt", reason="Windows drive-letter semantics")
def test_windows_drive_escape_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    allowed = tmp_path / "repositories"
    allowed.mkdir()
    monkeypatch.setattr(settings, "repository_allowed_roots", [allowed])
    current_drive = Path(tmp_path).drive.upper()

    for letter in "DEFGHIJKLMNOPQRSTUVWXYZ":
        other_drive = Path(f"{letter}:\\")
        if other_drive.drive.upper() == current_drive or not other_drive.exists():
            continue
        with pytest.raises(InvalidRepositoryLocationError):
            validate_repository_location(str(other_drive))
        return

    pytest.skip("No secondary drive is available for a drive-escape test")


@pytest.mark.skipif(os.name != "nt", reason="Windows UNC path semantics")
def test_windows_unc_path_is_rejected_before_resolution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    allowed = tmp_path / "repositories"
    allowed.mkdir()
    monkeypatch.setattr(settings, "repository_allowed_roots", [allowed])

    original_resolve = Path.resolve

    def guarded_resolve(self: Path, *args: object, **kwargs: object) -> Path:
        if self.drive.startswith("\\\\"):
            raise AssertionError("UNC paths must be rejected before resolution")
        return original_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", guarded_resolve)

    with pytest.raises(InvalidRepositoryLocationError):
        validate_repository_location(r"\\server\share\repository")


def test_resolved_path_outside_allowed_root_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    allowed = tmp_path / "repositories"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    monkeypatch.setattr(settings, "repository_allowed_roots", [allowed])

    original_resolve = Path.resolve
    simulated_link = allowed / "link"

    def fake_resolve(self: Path, *args: object, **kwargs: object) -> Path:
        if self == simulated_link:
            return original_resolve(outside)
        return original_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", fake_resolve)

    with pytest.raises(InvalidRepositoryLocationError, match="outside the allowed roots"):
        validate_repository_location(str(simulated_link))


def test_nested_symlink_escape_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    allowed = tmp_path / "repositories"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    (outside / "project").mkdir()
    link = allowed / "link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks are not supported on this platform")

    monkeypatch.setattr(settings, "repository_allowed_roots", [allowed])

    with pytest.raises(InvalidRepositoryLocationError, match="outside the allowed roots"):
        validate_repository_location(str(link / "project"))


def test_attack_surface_filesystem_errors_do_not_expose_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = str(tmp_path / "secret")
    original_lstat = Path.lstat
    original_open = Path.open

    def failing_lstat(self: Path) -> os.stat_result:
        if self.name == "app.py":
            raise OSError(f"metadata failure at {secret}")
        return original_lstat(self)

    def failing_open(self: Path, *args: object, **kwargs: object):
        if self.name == "app.py":
            raise OSError(f"read failure at {secret}")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", failing_lstat)
    monkeypatch.setattr(Path, "open", failing_open)

    path, issue = _validate_source_path(tmp_path, "app.py", 1024)
    assert path is None
    assert issue is not None
    assert issue.detail == "Source file metadata could not be inspected"
    assert secret not in (issue.detail or "")

    text, read_issue = _read_source_text(tmp_path / "app.py", "app.py", 1024)
    assert text is None
    assert read_issue is not None
    assert read_issue.detail == "Source file could not be read"
    assert secret not in (read_issue.detail or "")


def test_technology_filesystem_errors_do_not_expose_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = str(tmp_path / "secret")
    original_lstat = Path.lstat
    original_open = Path.open

    def failing_lstat(self: Path) -> os.stat_result:
        if self.name == "requirements.txt":
            raise OSError(f"metadata failure at {secret}")
        return original_lstat(self)

    def failing_open(self: Path, *args: object, **kwargs: object):
        if self.name == "requirements.txt":
            raise OSError(f"read failure at {secret}")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", failing_lstat)
    monkeypatch.setattr(Path, "open", failing_open)

    path, issue = _validate_manifest_path(tmp_path, "requirements.txt", 1024)
    assert path is None
    assert issue is not None
    assert issue.detail == "Manifest metadata could not be inspected"
    assert secret not in (issue.detail or "")

    text, read_issue = _read_manifest_text(
        tmp_path / "requirements.txt",
        "requirements.txt",
        1024,
    )
    assert text is None
    assert read_issue is not None
    assert read_issue.detail == "Manifest could not be read"
    assert secret not in (read_issue.detail or "")


@pytest.mark.anyio
async def test_summary_response_uses_relative_repository_path(
    client: httpx.AsyncClient,
    repository_root: Path,
) -> None:
    assessment = await create_assessment(client)
    repository = repository_root / "project"
    repository.mkdir()
    (repository / "app.py").write_text("print('hello')\n", encoding="utf-8")

    registered = await register_target(client, assessment["id"], repository)
    assert registered.status_code == 201

    response = await client.get(f"{ASSESSMENTS_URL}/{assessment['id']}/attack-surface/summary")

    assert response.status_code == 200
    body = response.json()
    assert "root" not in body
    assert body["repository"] == "project"
    assert_no_path_disclosure(body, repository, repository_root)
    # Repository-wide flow issues are labelled relative to the repository.
    flow_issue_files = {
        issue["source_file"]
        for issue in body["issues"]
        if issue["category"] in {"no_input_evidence", "no_sensitive_operation_evidence"}
    }
    assert flow_issue_files == {"."}


@pytest.mark.anyio
async def test_analysis_run_responses_and_metadata_do_not_disclose_host_paths(
    client: httpx.AsyncClient,
    repository_root: Path,
) -> None:
    assessment = await create_assessment(client)
    repository = repository_root / "project"
    repository.mkdir()
    (repository / "app.py").write_text("print('hello')\n", encoding="utf-8")
    assert (await register_target(client, assessment["id"], repository)).status_code == 201

    created = await client.post(f"{ASSESSMENTS_URL}/{assessment['id']}/analysis-runs")
    assert created.status_code == 201
    run_id = created.json()["id"]
    detail = await client.get(f"{ASSESSMENTS_URL}/{assessment['id']}/analysis-runs/{run_id}")
    findings = await client.get(f"{ASSESSMENTS_URL}/{assessment['id']}/findings")

    for response in (created, detail, findings):
        assert response.status_code in {200, 201}
        assert_no_path_disclosure(response.json(), repository, repository_root)


def test_path_disclosure_helper_detects_windows_style_escaping() -> None:
    windows_path = "C:\\Users\\alice\\repositories\\project"
    with pytest.raises(AssertionError):
        assert_no_path_disclosure({"issues": [{"source_file": windows_path}]}, windows_path)
    assert_no_path_disclosure({"issues": [{"source_file": "."}]}, windows_path)
