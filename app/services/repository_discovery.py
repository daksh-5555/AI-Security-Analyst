"""Deterministic, read-only filesystem discovery for registered repositories.

The service inventories regular files below a validated repository root. It never
opens file contents, executes repository code, invokes Git or shell commands, or
performs network requests.

TOCTOU limitations
------------------
The filesystem can change between validation and traversal. Discovery re-checks
entries with ``lstat``/``scandir`` without following symlinks and verifies that
child paths resolve inside the root, but a path could still be replaced by a
symlink or moved outside the root after those checks. File sizes are snapshots,
and files that disappear mid-run are reported as skipped. Fully race-free
traversal would require platform-specific directory-handle operations that are
outside the scope of this milestone.
"""

import os
import stat
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from sqlalchemy.orm import Session

from app.core.config import settings
from app.schemas.enums import (
    DiscoveryItemKind,
    DiscoverySkipReason,
    DiscoveryTruncationReason,
)
from app.schemas.repository_discovery import (
    DiscoveryLimits,
    DiscoverySummary,
    FileInventoryEntry,
    RepositoryDiscoveryResult,
    SkippedItem,
)
from app.services.analysis_execution_context import AnalysisExecutionContext
from app.services.repository_targets import (
    InvalidRepositoryLocationError,
    get_repository_target,
    validate_repository_location,
)

EXCLUDED_DIRECTORY_NAMES: Final[frozenset[str]] = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".next",
        "dist",
        "build",
    }
)

_UNEXPECTED_SKIP_REASONS: Final[frozenset[DiscoverySkipReason]] = frozenset(
    {
        DiscoverySkipReason.PERMISSION_DENIED,
        DiscoverySkipReason.DISAPPEARED,
        DiscoverySkipReason.INACCESSIBLE,
        DiscoverySkipReason.OUTSIDE_ROOT,
    }
)

_TRUNCATION_ORDER: Final[dict[DiscoveryTruncationReason, int]] = {
    DiscoveryTruncationReason.MAX_DEPTH: 0,
    DiscoveryTruncationReason.MAX_FILE_COUNT: 1,
    DiscoveryTruncationReason.MAX_TOTAL_SIZE: 2,
}


class RepositoryDiscoveryError(ValueError):
    """Base error for repository discovery operations."""


class InvalidRepositoryRootError(RepositoryDiscoveryError):
    """Raised when a discovery root is not a safe, existing directory."""


@dataclass
class _DiscoveryState:
    files: list[FileInventoryEntry] = field(default_factory=list)
    skipped: list[SkippedItem] = field(default_factory=list)
    directory_count: int = 0
    total_size_bytes: int = 0
    truncation_reasons: list[DiscoveryTruncationReason] = field(default_factory=list)
    stopped: bool = False

    def skip(
        self,
        relative_path: str,
        kind: DiscoveryItemKind,
        reason: DiscoverySkipReason,
        detail: str | None = None,
    ) -> None:
        self.skipped.append(
            SkippedItem(
                relative_path=relative_path,
                kind=kind,
                reason=reason,
                detail=detail,
            )
        )

    def truncate(self, reason: DiscoveryTruncationReason) -> None:
        if reason not in self.truncation_reasons:
            self.truncation_reasons.append(reason)


def _resolve_limits(
    max_file_count: int | None,
    max_depth: int | None,
    max_total_size_bytes: int | None,
) -> DiscoveryLimits:
    return DiscoveryLimits(
        max_file_count=(
            settings.repository_max_file_count if max_file_count is None else max_file_count
        ),
        max_depth=settings.repository_max_depth if max_depth is None else max_depth,
        max_total_size_bytes=(
            settings.repository_max_total_size_bytes
            if max_total_size_bytes is None
            else max_total_size_bytes
        ),
    )


def _scan_directory(directory: Path) -> list[os.DirEntry[str]]:
    with os.scandir(directory) as entries:
        return sorted(entries, key=lambda entry: entry.name)


def _relative_path(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _extension(path: Path) -> str | None:
    suffix = path.suffix
    return suffix[1:].lower() if suffix else None


def _is_within_root(path: Path, root: Path) -> bool:
    try:
        return path.resolve(strict=False).is_relative_to(root)
    except (OSError, RuntimeError):
        return False


def _entry_size(entry: os.DirEntry[str]) -> int:
    return os.stat(entry.path, follow_symlinks=False).st_size


def _is_reparse_point(entry: os.DirEntry[str]) -> bool:
    """Return True for Windows junctions and other reparse points."""
    if os.name != "nt":
        return False
    try:
        attributes = entry.stat(follow_symlinks=False).st_file_attributes
    except (AttributeError, OSError):
        return False
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _walk(
    directory: Path,
    root: Path,
    depth: int,
    *,
    limits: DiscoveryLimits,
    state: _DiscoveryState,
    execution_context: AnalysisExecutionContext | None = None,
) -> None:
    if state.stopped:
        return
    if execution_context is not None:
        execution_context.check()

    try:
        entries = _scan_directory(directory)
    except FileNotFoundError:
        state.skip(
            _relative_path(directory, root),
            DiscoveryItemKind.DIRECTORY,
            DiscoverySkipReason.DISAPPEARED,
            "Directory disappeared during discovery",
        )
        return
    except PermissionError:
        state.skip(
            _relative_path(directory, root),
            DiscoveryItemKind.DIRECTORY,
            DiscoverySkipReason.PERMISSION_DENIED,
            "Permission denied while reading directory",
        )
        return
    except OSError:
        state.skip(
            _relative_path(directory, root),
            DiscoveryItemKind.DIRECTORY,
            DiscoverySkipReason.INACCESSIBLE,
            "Directory could not be accessed",
        )
        return

    for entry in entries:
        if state.stopped:
            return
        if execution_context is not None:
            execution_context.check()
        _process_entry(
            entry,
            root,
            depth,
            limits=limits,
            state=state,
            execution_context=execution_context,
        )


def _process_entry(
    entry: os.DirEntry[str],
    root: Path,
    depth: int,
    *,
    limits: DiscoveryLimits,
    state: _DiscoveryState,
    execution_context: AnalysisExecutionContext | None = None,
) -> None:
    path = Path(entry.path)
    relative_path = _relative_path(path, root)

    try:
        is_symlink = entry.is_symlink()
    except FileNotFoundError:
        state.skip(
            relative_path,
            DiscoveryItemKind.OTHER,
            DiscoverySkipReason.DISAPPEARED,
            "Entry disappeared during discovery",
        )
        return
    except OSError:
        state.skip(
            relative_path,
            DiscoveryItemKind.OTHER,
            DiscoverySkipReason.INACCESSIBLE,
            "Entry could not be accessed",
        )
        return

    if is_symlink:
        state.skip(
            relative_path,
            DiscoveryItemKind.SYMLINK,
            DiscoverySkipReason.SYMLINK,
            "Symbolic links are not followed",
        )
        return

    try:
        is_directory = entry.is_dir(follow_symlinks=False)
    except FileNotFoundError:
        state.skip(
            relative_path,
            DiscoveryItemKind.OTHER,
            DiscoverySkipReason.DISAPPEARED,
            "Entry disappeared during discovery",
        )
        return
    except OSError:
        state.skip(
            relative_path,
            DiscoveryItemKind.OTHER,
            DiscoverySkipReason.INACCESSIBLE,
            "Entry could not be accessed",
        )
        return

    if is_directory:
        if _is_reparse_point(entry):
            state.skip(
                relative_path,
                DiscoveryItemKind.SYMLINK,
                DiscoverySkipReason.SYMLINK,
                "Reparse points are not followed",
            )
            return

        if entry.name in EXCLUDED_DIRECTORY_NAMES:
            state.skip(
                relative_path,
                DiscoveryItemKind.DIRECTORY,
                DiscoverySkipReason.EXCLUDED_DIRECTORY,
            )
            return

        if depth + 1 > limits.max_depth:
            state.skip(
                relative_path,
                DiscoveryItemKind.DIRECTORY,
                DiscoverySkipReason.MAX_DEPTH,
                "Maximum traversal depth reached",
            )
            state.truncate(DiscoveryTruncationReason.MAX_DEPTH)
            return

        if not _is_within_root(path, root):
            state.skip(
                relative_path,
                DiscoveryItemKind.DIRECTORY,
                DiscoverySkipReason.OUTSIDE_ROOT,
            )
            return

        state.directory_count += 1
        _walk(
            path,
            root,
            depth + 1,
            limits=limits,
            state=state,
            execution_context=execution_context,
        )
        return

    try:
        is_file = entry.is_file(follow_symlinks=False)
    except FileNotFoundError:
        state.skip(
            relative_path,
            DiscoveryItemKind.OTHER,
            DiscoverySkipReason.DISAPPEARED,
            "Entry disappeared during discovery",
        )
        return
    except OSError:
        state.skip(
            relative_path,
            DiscoveryItemKind.OTHER,
            DiscoverySkipReason.INACCESSIBLE,
            "Entry could not be accessed",
        )
        return

    if not is_file:
        state.skip(
            relative_path,
            DiscoveryItemKind.OTHER,
            DiscoverySkipReason.NOT_REGULAR_FILE,
        )
        return

    if not _is_within_root(path, root):
        state.skip(
            relative_path,
            DiscoveryItemKind.FILE,
            DiscoverySkipReason.OUTSIDE_ROOT,
        )
        return

    if len(state.files) >= limits.max_file_count:
        state.skip(
            relative_path,
            DiscoveryItemKind.FILE,
            DiscoverySkipReason.MAX_FILE_COUNT,
            "Maximum file count reached",
        )
        state.truncate(DiscoveryTruncationReason.MAX_FILE_COUNT)
        state.stopped = True
        return

    try:
        size_bytes = _entry_size(entry)
    except FileNotFoundError:
        state.skip(
            relative_path,
            DiscoveryItemKind.FILE,
            DiscoverySkipReason.DISAPPEARED,
            "File disappeared during discovery",
        )
        return
    except PermissionError:
        state.skip(
            relative_path,
            DiscoveryItemKind.FILE,
            DiscoverySkipReason.PERMISSION_DENIED,
            "Permission denied while reading file metadata",
        )
        return
    except OSError:
        state.skip(
            relative_path,
            DiscoveryItemKind.FILE,
            DiscoverySkipReason.INACCESSIBLE,
            "File metadata could not be read",
        )
        return

    if state.total_size_bytes + size_bytes > limits.max_total_size_bytes:
        state.skip(
            relative_path,
            DiscoveryItemKind.FILE,
            DiscoverySkipReason.MAX_TOTAL_SIZE,
            "Maximum total file size reached",
        )
        state.truncate(DiscoveryTruncationReason.MAX_TOTAL_SIZE)
        state.stopped = True
        return

    state.files.append(
        FileInventoryEntry(
            relative_path=relative_path,
            extension=_extension(path),
            size_bytes=size_bytes,
        )
    )
    state.total_size_bytes += size_bytes


def discover_repository(
    root: str | Path,
    *,
    max_file_count: int | None = None,
    max_depth: int | None = None,
    max_total_size_bytes: int | None = None,
    execution_context: AnalysisExecutionContext | None = None,
) -> RepositoryDiscoveryResult:
    """Build a deterministic inventory for a validated repository root."""
    limits = _resolve_limits(max_file_count, max_depth, max_total_size_bytes)

    candidate = Path(root).expanduser()
    if candidate.is_symlink():
        raise InvalidRepositoryRootError("Repository root must not be a symbolic link")

    try:
        resolved_root = validate_repository_location(str(candidate))
    except InvalidRepositoryLocationError as exc:
        raise InvalidRepositoryRootError(str(exc)) from exc

    state = _DiscoveryState()
    _walk(
        resolved_root,
        resolved_root,
        0,
        limits=limits,
        state=state,
        execution_context=execution_context,
    )

    files = sorted(state.files, key=lambda entry: entry.relative_path)
    skipped = sorted(
        state.skipped,
        key=lambda item: (item.relative_path, item.reason.value, item.kind.value),
    )
    truncation_reasons = sorted(
        state.truncation_reasons,
        key=lambda reason: _TRUNCATION_ORDER[reason],
    )
    is_complete = not truncation_reasons and not any(
        item.reason in _UNEXPECTED_SKIP_REASONS for item in skipped
    )

    return RepositoryDiscoveryResult(
        root=str(resolved_root),
        files=files,
        skipped=skipped,
        summary=DiscoverySummary(
            directory_count=state.directory_count,
            file_count=len(files),
            total_size_bytes=state.total_size_bytes,
            skipped_count=len(skipped),
            is_complete=is_complete,
            truncation_reasons=truncation_reasons,
            limits=limits,
        ),
    )


def discover_registered_repository(
    db: Session,
    assessment_id: uuid.UUID,
    *,
    max_file_count: int | None = None,
    max_depth: int | None = None,
    max_total_size_bytes: int | None = None,
    execution_context: AnalysisExecutionContext | None = None,
) -> RepositoryDiscoveryResult | None:
    """Discover the repository target registered for an assessment, if any.

    The target must have an ``authorized`` assessment-target record
    (``TargetNotAuthorizedError`` otherwise) and, with per-user isolation, must
    still lie inside the owner's sub-root.
    """
    from app.models.assessment import AssessmentJob
    from app.services.repository_targets import (
        InvalidRepositoryLocationError,
        repository_roots_for_owner,
    )
    from app.services.target_authorization import require_authorized_repository_target

    target = get_repository_target(db, assessment_id)
    if target is None:
        return None
    require_authorized_repository_target(db, assessment_id, target)
    assessment = db.get(AssessmentJob, assessment_id)
    owner_roots = repository_roots_for_owner(assessment.owner_id if assessment else None)
    if owner_roots is not None:
        try:
            validate_repository_location(target.location, allowed_roots=owner_roots)
        except InvalidRepositoryLocationError as exc:
            raise InvalidRepositoryRootError("Repository is outside the owner's root") from exc
    return discover_repository(
        target.location,
        max_file_count=max_file_count,
        max_depth=max_depth,
        max_total_size_bytes=max_total_size_bytes,
        execution_context=execution_context,
    )
