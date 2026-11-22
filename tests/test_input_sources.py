import json
import os
import stat
import textwrap
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest

from app.core.config import settings
from app.schemas.attack_surface import AnalysisIssueReason, AttackSurfaceResult
from app.schemas.enums import (
    DiscoveryItemKind,
    DiscoverySkipReason,
    DiscoveryTruncationReason,
)
from app.schemas.input_sources import (
    InputCandidate,
    InputResolutionStatus,
    InputSourceResult,
    InputType,
)
from app.schemas.repository_discovery import (
    DiscoveryLimits,
    DiscoverySummary,
    FileInventoryEntry,
    RepositoryDiscoveryResult,
    SkippedItem,
)
from app.schemas.technology import (
    TechnologyCategory,
    TechnologyDetection,
    TechnologyDetectionMethod,
    TechnologyDetectionResult,
    TechnologyDetectionSummary,
    TechnologyEvidence,
)
from app.services.attack_surface import identify_attack_surface
from app.services.input_sources import (
    InputSourceAnalysisError,
    InvalidInputSourceRootError,
    identify_input_sources,
)
from app.services.repository_discovery import discover_repository
from app.services.technology_detector import detect_technologies


@pytest.fixture
def allowed_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    root = tmp_path / "repositories"
    root.mkdir()
    monkeypatch.setattr(settings, "repository_allowed_roots", [root])
    return root


@pytest.fixture
def repository(allowed_root: Path) -> Path:
    repository = allowed_root / "project"
    repository.mkdir()
    return repository


def source(text: str) -> str:
    return textwrap.dedent(text).lstrip("\n")


def write_text(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def write_bytes(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def write_requirements(repository: Path, *names: str) -> Path:
    return write_text(repository / "requirements.txt", "\n".join(names) + "\n")


def write_package_json(repository: Path, dependencies: dict[str, str]) -> Path:
    return write_text(
        repository / "package.json",
        json.dumps({"dependencies": dependencies}),
    )


def manual_inventory(
    root: Path,
    relative_paths: list[str],
    *,
    skipped: list[SkippedItem] | None = None,
    is_complete: bool = True,
    truncation_reasons: list[DiscoveryTruncationReason] | None = None,
) -> RepositoryDiscoveryResult:
    files: list[FileInventoryEntry] = []
    total_size_bytes = 0
    for relative_path in relative_paths:
        path = root / relative_path
        try:
            size_bytes = path.lstat().st_size
        except OSError:
            size_bytes = 0
        suffix = PurePosixPath(relative_path.replace("\\", "/")).suffix
        files.append(
            FileInventoryEntry(
                relative_path=relative_path,
                extension=suffix[1:].lower() if suffix else None,
                size_bytes=size_bytes,
            )
        )
        total_size_bytes += size_bytes

    skipped_items = list(skipped or [])
    return RepositoryDiscoveryResult(
        root=str(root.resolve()),
        files=sorted(files, key=lambda entry: entry.relative_path),
        skipped=skipped_items,
        summary=DiscoverySummary(
            directory_count=0,
            file_count=len(files),
            total_size_bytes=total_size_bytes,
            skipped_count=len(skipped_items),
            is_complete=is_complete,
            truncation_reasons=list(truncation_reasons or []),
            limits=DiscoveryLimits(
                max_file_count=settings.repository_max_file_count,
                max_depth=settings.repository_max_depth,
                max_total_size_bytes=settings.repository_max_total_size_bytes,
            ),
        ),
    )


def manual_technologies(
    root: Path,
    framework_names: list[str],
) -> TechnologyDetectionResult:
    detections = [
        TechnologyDetection(
            name=name,
            category=TechnologyCategory.FRAMEWORK,
            confidence=0.95,
            evidence=[
                TechnologyEvidence(
                    path="requirements.txt",
                    detail=f"{name} is declared.",
                )
            ],
            method=TechnologyDetectionMethod.MANIFEST_DEPENDENCY,
            file_count=1,
        )
        for name in framework_names
    ]
    return TechnologyDetectionResult(
        root=str(root.resolve()),
        detections=detections,
        issues=[],
        summary=TechnologyDetectionSummary(
            detection_count=len(detections),
            language_count=0,
            framework_count=len(detections),
            library_count=0,
            database_count=0,
            infrastructure_count=0,
            build_tool_count=0,
            manifest_files_read=1 if detections else 0,
            issue_count=0,
            discovery_is_complete=True,
            discovery_truncation_reasons=[],
        ),
    )


def analyze(
    repository: Path,
    *,
    inventory: RepositoryDiscoveryResult | None = None,
    technologies: TechnologyDetectionResult | None = None,
    attack_surface: AttackSurfaceResult | None = None,
    **kwargs: object,
) -> InputSourceResult:
    resolved_inventory = inventory or discover_repository(repository)
    resolved_technologies = technologies or detect_technologies(
        repository,
        resolved_inventory,
    )
    resolved_surface = attack_surface or identify_attack_surface(
        repository,
        resolved_inventory,
        resolved_technologies,
    )
    return identify_input_sources(
        repository,
        resolved_inventory,
        resolved_technologies,
        resolved_surface,
        **kwargs,
    )


def find_input(
    result: InputSourceResult,
    input_type: InputType,
    parameter_name: str | None = None,
    handler_name: str | None = None,
    variable_name: str | None = None,
) -> InputCandidate | None:
    for candidate in result.inputs:
        if candidate.input_type is not input_type:
            continue
        if parameter_name is not None and candidate.parameter_name != parameter_name:
            continue
        if handler_name is not None and candidate.handler_name != handler_name:
            continue
        if variable_name is not None and candidate.variable_name != variable_name:
            continue
        return candidate
    return None


def line_of(text: str, needle: str) -> int:
    for index, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return index
    raise AssertionError(f"Line containing {needle!r} was not found")


def test_fastapi_parameter_declarations_and_annotations(repository: Path) -> None:
    write_requirements(repository, "fastapi")
    text = source(
        """
        from fastapi import (
            Body,
            Cookie,
            FastAPI,
            File,
            Form,
            Header,
            Path,
            Query,
            Request,
            UploadFile,
        )

        app = FastAPI()

        @app.get("/items/{item_id}")
        async def read_item(
            request: Request,
            item_id: int = Path(...),
            q: str | None = Query(None),
            x_token: str = Header(...),
            session: str = Cookie(...),
            payload: dict = Body(...),
            name: str = Form(...),
            upload: UploadFile = File(...),
        ):
            agent = request.headers.get("user-agent")
            return await request.json()
        """
    )
    write_text(repository / "main.py", text)

    result = analyze(repository)

    expected = {
        InputType.PATH: "item_id",
        InputType.QUERY: "q",
        InputType.HEADER: "x_token",
        InputType.COOKIE: "session",
        InputType.BODY: "payload",
        InputType.FORM: "name",
        InputType.FILE: "upload",
    }
    for input_type, parameter_name in expected.items():
        candidate = find_input(result, input_type, parameter_name, "read_item")
        assert candidate is not None
        assert candidate.associated_routes[0].path == "/items/{item_id}"

    request_object = find_input(result, InputType.REQUEST_OBJECT, None, "read_item")
    assert request_object is not None
    assert request_object.variable_name == "request"
    assert find_input(result, InputType.HEADER, "user-agent", "read_item") is not None
    body_access = next(
        item
        for item in result.inputs
        if item.input_type is InputType.BODY
        and item.handler_name == "read_item"
        and item.declaration_or_access.endswith(".json()")
    )
    assert body_access is not None
    assert result.summary.input_count == 10
    assert result.summary.named_parameter_count == 8
    assert result.summary.route_association_count == 10
    assert result.summary.unresolved_association_count == 0


def test_fastapi_annotated_upload_and_multiple_routes(repository: Path) -> None:
    write_requirements(repository, "fastapi")
    text = source(
        """
        from typing import Annotated
        from fastapi import FastAPI, File, Query, UploadFile

        app = FastAPI()

        @app.get("/first")
        @app.post("/second")
        async def upload(
            file: Annotated[UploadFile, File(...)],
            q: Annotated[str, Query(...)],
        ):
            return None
        """
    )
    write_text(repository / "main.py", text)

    result = analyze(repository)

    upload = find_input(result, InputType.FILE, "file", "upload")
    query = find_input(result, InputType.QUERY, "q", "upload")
    assert upload is not None
    assert query is not None
    assert [route.path for route in upload.associated_routes] == ["/first", "/second"]
    assert [route.path for route in query.associated_routes] == ["/first", "/second"]
    assert result.summary.route_association_count == 4


def test_flask_request_access_mappings(repository: Path) -> None:
    write_requirements(repository, "flask")
    text = source(
        """
        from flask import Flask, request

        app = Flask(__name__)

        @app.route("/search", methods=["GET", "POST"])
        def search():
            q = request.args.get("q")
            page = request.args.get("page", "1")
            name = request.form.get("name")
            payload = request.get_json()
            raw_json = request.json
            upload = request.files.get("avatar")
            combined = request.values.get("combined")
            token = request.headers.get("X-Token")
            session = request.cookies.get("session")
            raw = request.get_data()
            body = request.data
            return "ok"
        """
    )
    write_text(repository / "app.py", text)

    result = analyze(repository)

    expected = {
        (InputType.QUERY, "q"),
        (InputType.QUERY, "page"),
        (InputType.FORM, "name"),
        (InputType.FILE, "avatar"),
        (InputType.OTHER, "combined"),
        (InputType.HEADER, "X-Token"),
        (InputType.COOKIE, "session"),
    }
    for input_type, parameter_name in expected:
        candidate = find_input(result, input_type, parameter_name, "search")
        assert candidate is not None
        assert [route.http_method.value for route in candidate.associated_routes] == ["GET", "POST"]

    for declaration in ("request.get_json()", "request.json", "request.get_data()", "request.data"):
        assert any(item.declaration_or_access == declaration for item in result.inputs)
    assert result.summary.input_count == 11
    assert result.summary.route_association_count == 22
    assert result.summary.unresolved_association_count == 0


def test_flask_chained_json_access(repository: Path) -> None:
    write_requirements(repository, "flask")
    text = source(
        """
        from flask import Flask, request

        app = Flask(__name__)

        @app.post("/submit")
        def submit():
            return request.get_json().get("email")
        """
    )
    write_text(repository / "app.py", text)

    result = analyze(repository)

    email = find_input(result, InputType.BODY, "email", "submit")
    assert email is not None
    assert email.declaration_or_access == "request.get_json().get('email')"
    assert [route.path for route in email.associated_routes] == ["/submit"]


def test_django_request_access_and_class_view_association(repository: Path) -> None:
    write_requirements(repository, "django")
    write_text(
        repository / "views.py",
        source(
            """
            def search(request):
                q = request.GET.get("q")
                name = request.POST["name"]
                upload = request.FILES.get("avatar")
                raw = request.body
                token = request.headers.get("X-Token")
                session = request.COOKIES.get("session")
                return None

            class DetailView:
                def get(self, request):
                    return request.GET.get("detail")
            """
        ),
    )
    write_text(
        repository / "urls.py",
        source(
            """
            from django.urls import path
            from . import views

            urlpatterns = [
                path("search/", views.search),
                path("detail/", views.DetailView.as_view()),
            ]
            """
        ),
    )

    result = analyze(repository)

    expected = {
        (InputType.QUERY, "q"),
        (InputType.FORM, "name"),
        (InputType.FILE, "avatar"),
        (InputType.HEADER, "X-Token"),
        (InputType.COOKIE, "session"),
    }
    for input_type, parameter_name in expected:
        candidate = find_input(result, input_type, parameter_name, "search")
        assert candidate is not None
        assert [route.path for route in candidate.associated_routes] == ["search/"]

    body = next(
        item
        for item in result.inputs
        if item.input_type is InputType.BODY and item.handler_name == "search"
    )
    assert body is not None
    assert [route.path for route in body.associated_routes] == ["search/"]

    detail = find_input(result, InputType.QUERY, "detail", "get")
    assert detail is not None
    assert [route.path for route in detail.associated_routes] == ["detail/"]
    assert result.summary.unresolved_association_count == 0


def test_express_property_accesses_and_destructuring(repository: Path) -> None:
    write_package_json(repository, {"express": "^4.18.0"})
    text = source(
        """
        const express = require('express');
        const app = express();

        function handle(req, res) {
          const { name, email: contact } = req.body;
          const { id } = req.params;
          const { q } = req.query;
          const session = req.cookies.session;
          const token = req.headers.authorization;
          return res.json({ name, contact, id, q, session, token });
        }

        app.get('/users/:id', handle);
        app.post('/submit', (req, res) => {
          const upload = req.files.avatar;
          return upload;
        });
        """
    )
    write_text(repository / "server.js", text)

    result = analyze(repository)

    expected = {
        (InputType.BODY, "name", "name"),
        (InputType.BODY, "email", "contact"),
        (InputType.PATH, "id", "id"),
        (InputType.QUERY, "q", "q"),
        (InputType.COOKIE, "session", "session"),
        (InputType.HEADER, "authorization", "token"),
    }
    for input_type, parameter_name, variable_name in expected:
        candidate = find_input(result, input_type, parameter_name, "handle", variable_name)
        assert candidate is not None
        assert [route.path for route in candidate.associated_routes] == ["/users/:id"]

    upload = find_input(result, InputType.FILE, "avatar", None, "upload")
    assert upload is not None
    assert [route.path for route in upload.associated_routes] == ["/submit"]
    assert result.summary.unresolved_association_count == 0


def test_express_route_level_direct_access(repository: Path) -> None:
    write_package_json(repository, {"express": "^4.18.0"})
    text = source(
        """
        const express = require('express');
        const app = express();

        app.get('/users/:id', (req, res) => {
          const id = req.params.id;
          const q = req.query.q;
          const page = req.query["page"];
          const email = req.body.email;
          const token = req.headers.authorization;
          const session = req.cookies.session;
          const upload = req.files.avatar;
          return res.json({ id, q, page, email, token, session, upload });
        });
        """
    )
    write_text(repository / "server.js", text)

    result = analyze(repository)

    expected = {
        (InputType.PATH, "id"),
        (InputType.QUERY, "q"),
        (InputType.QUERY, "page"),
        (InputType.BODY, "email"),
        (InputType.HEADER, "authorization"),
        (InputType.COOKIE, "session"),
        (InputType.FILE, "avatar"),
    }
    for input_type, parameter_name in expected:
        candidate = find_input(result, input_type, parameter_name)
        assert candidate is not None
        assert [route.path for route in candidate.associated_routes] == ["/users/:id"]
    assert result.summary.input_count == 7
    assert result.summary.route_association_count == 7


def test_nestjs_parameter_decorators_and_request_access(repository: Path) -> None:
    write_package_json(repository, {"@nestjs/common": "^10.0.0"})
    text = source(
        """
        import {
          Body,
          Controller,
          Get,
          Headers,
          Param,
          Post,
          Query,
          Req,
          UploadedFile,
          UploadedFiles,
        } from '@nestjs/common';

        @Controller('items')
        export class ItemsController {
          @Get(':id')
          findOne(
            @Param('id') id: string,
            @Query('q') q: string,
            @Headers('x-token') token: string,
            @Req() req,
          ) {
            const agent = req.headers['user-agent'];
            return id;
          }

          @Post()
          create(
            @Body() dto: object,
            @UploadedFile() file: object,
            @UploadedFiles() files: object[],
          ) {
            return dto;
          }
        }
        """
    )
    write_text(repository / "items.controller.ts", text)

    result = analyze(repository)

    expected = {
        (InputType.PATH, "id"),
        (InputType.QUERY, "q"),
        (InputType.HEADER, "x-token"),
        (InputType.HEADER, "user-agent"),
    }
    for input_type, parameter_name in expected:
        candidate = find_input(result, input_type, parameter_name, "findOne")
        assert candidate is not None
        assert [route.path for route in candidate.associated_routes] == ["/items/:id"]

    request_object = find_input(result, InputType.REQUEST_OBJECT, None, "findOne")
    assert request_object is not None
    assert request_object.variable_name == "req"
    for input_type, parameter_name, handler_name in (
        (InputType.BODY, None, "create"),
        (InputType.FILE, None, "create"),
    ):
        candidate = find_input(result, input_type, parameter_name, handler_name)
        assert candidate is not None
        assert [route.path for route in candidate.associated_routes] == ["/items"]
    assert result.summary.unresolved_association_count == 0


def test_dynamic_keys_are_reported_without_inventing_names(repository: Path) -> None:
    write_requirements(repository, "flask")
    write_package_json(
        repository,
        {"express": "^4.18.0", "@nestjs/common": "^10.0.0"},
    )
    write_text(
        repository / "app.py",
        source(
            """
            from flask import Flask, request

            app = Flask(__name__)

            @app.get("/search")
            def search():
                key = "q"
                return request.args.get(key)
            """
        ),
    )
    write_text(
        repository / "server.js",
        source(
            """
            const express = require('express');
            const app = express();

            app.get('/users', (req, res) => {
              const key = 'id';
              return req.query[key];
            });
            """
        ),
    )
    write_text(
        repository / "items.controller.ts",
        source(
            """
            import { Controller, Get, Query } from '@nestjs/common';

            @Controller('items')
            export class ItemsController {
              @Get()
              find(@Query({ transform: true }) q: string) {
                return q;
              }
            }
            """
        ),
    )

    result = analyze(repository)

    assert any(issue.reason is AnalysisIssueReason.UNSUPPORTED_SYNTAX for issue in result.issues)
    unnamed = [item for item in result.inputs if item.parameter_name is None]
    assert len(unnamed) == 3
    assert all(item.resolution_status is InputResolutionStatus.UNRESOLVED for item in unnamed)


def test_comments_and_string_literals_are_not_inputs(repository: Path) -> None:
    write_requirements(repository, "flask")
    write_package_json(repository, {"express": "^4.18.0"})
    write_text(
        repository / "app.py",
        source(
            """
            from flask import Flask, request

            app = Flask(__name__)

            @app.get("/real")
            def real():
                # request.args.get("comment")
                note = 'request.form["string"]'
                return request.args.get("actual")
            """
        ),
    )
    write_text(
        repository / "server.js",
        source(
            """
            const express = require('express');
            const app = express();

            // req.body.comment
            const note = "req.query.string";
            app.get('/real', (req, res) => {
              return req.body.actual;
            });
            """
        ),
    )

    result = analyze(repository)

    assert find_input(result, InputType.QUERY, "actual", "real") is not None
    assert find_input(result, InputType.BODY, "actual") is not None
    assert find_input(result, InputType.QUERY, "string") is None
    assert find_input(result, InputType.FORM, "string") is None
    assert find_input(result, InputType.BODY, "comment") is None


def test_invalid_syntax_and_encoding_are_reported(repository: Path) -> None:
    write_requirements(repository, "fastapi")
    write_package_json(repository, {"express": "^4.18.0"})
    write_text(repository / "broken.py", "def broken(:\n    pass\n")
    write_text(
        repository / "broken.js",
        "const express = require('express');\nconst x = 'unterminated\n",
    )
    write_bytes(repository / "bad.py", b"\xff\xfe\x00")

    result = analyze(repository)

    reasons = {(issue.source_file, issue.reason) for issue in result.issues}
    assert ("broken.py", AnalysisIssueReason.INVALID_SYNTAX) in reasons
    assert ("broken.js", AnalysisIssueReason.INVALID_SYNTAX) in reasons
    assert ("bad.py", AnalysisIssueReason.INVALID_ENCODING) in reasons
    assert result.summary.source_files_inspected == 2
    assert result.summary.is_complete is False


def test_duplicate_candidates_are_collapsed_without_losing_lines(repository: Path) -> None:
    write_requirements(repository, "flask")
    text = source(
        """
        from flask import Flask, request

        app = Flask(__name__)

        @app.get("/search")
        def search():
            first = request.args.get("q"), request.args.get("q")
            second = request.args.get("q")
            return first, second
        """
    )
    write_text(repository / "app.py", text)

    result = analyze(repository)

    matches = [
        item
        for item in result.inputs
        if item.input_type is InputType.QUERY and item.parameter_name == "q"
    ]
    assert len(matches) == 2
    assert len({item.line_number for item in matches}) == 2
    assert result.summary.input_count == 2


def test_source_size_and_file_count_limits(repository: Path) -> None:
    write_requirements(repository, "fastapi")
    write_text(repository / "large.py", "x = 1\n" * 100)
    oversized = analyze(repository, max_source_file_size_bytes=10)
    assert any(
        issue.source_file == "large.py" and issue.reason is AnalysisIssueReason.TOO_LARGE
        for issue in oversized.issues
    )
    assert oversized.summary.source_files_inspected == 0

    write_text(repository / "a.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    write_text(repository / "b.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    limited = analyze(repository, max_source_files=1)
    assert limited.summary.source_files_inspected == 1
    assert any(issue.reason is AnalysisIssueReason.MAX_SOURCE_FILES for issue in limited.issues)
    assert limited.summary.is_complete is False


def test_symlink_source_is_rejected(repository: Path, tmp_path: Path) -> None:
    outside = write_text(
        tmp_path / "outside.py",
        "from flask import Flask, request\napp = Flask(__name__)\n",
    )
    link = repository / "link.py"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks are not supported on this platform")

    inventory = manual_inventory(repository, ["link.py"])
    technologies = manual_technologies(repository, ["Flask"])
    surface = identify_attack_surface(repository, inventory, technologies)
    result = identify_input_sources(repository, inventory, technologies, surface)

    assert any(issue.reason is AnalysisIssueReason.SYMLINK for issue in result.issues)
    assert result.inputs == []


def test_symlink_metadata_is_rejected(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_text(
        repository / "app.py",
        "from flask import Flask, request\napp = Flask(__name__)\n",
    )
    inventory = manual_inventory(repository, ["app.py"])
    technologies = manual_technologies(repository, ["Flask"])
    surface = identify_attack_surface(repository, inventory, technologies)
    real_lstat = Path.lstat

    def fake_lstat(path: Path) -> os.stat_result:
        if path.name == "app.py":
            return os.stat_result((stat.S_IFLNK | 0o777, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", fake_lstat)

    result = identify_input_sources(repository, inventory, technologies, surface)

    assert any(issue.reason is AnalysisIssueReason.SYMLINK for issue in result.issues)
    assert result.inputs == []


@pytest.mark.skipif(
    os.name != "nt",
    reason="Windows reparse-point metadata is Windows-specific",
)
def test_windows_reparse_point_is_rejected(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_text(
        repository / "app.py",
        "from flask import Flask, request\napp = Flask(__name__)\n",
    )
    inventory = manual_inventory(repository, ["app.py"])
    technologies = manual_technologies(repository, ["Flask"])
    surface = identify_attack_surface(repository, inventory, technologies)
    real_lstat = Path.lstat

    def fake_lstat(path: Path) -> object:
        if path.name == "app.py":
            return SimpleNamespace(
                st_mode=stat.S_IFREG,
                st_size=10,
                st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT,
            )
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", fake_lstat)

    result = identify_input_sources(repository, inventory, technologies, surface)

    assert any(issue.reason is AnalysisIssueReason.SYMLINK for issue in result.issues)
    assert result.inputs == []


def test_traversal_and_absolute_paths_are_rejected(
    repository: Path,
    tmp_path: Path,
) -> None:
    outside = write_text(
        tmp_path / "outside.py",
        "from flask import Flask, request\napp = Flask(__name__)\n",
    )
    inventory = manual_inventory(repository, ["../outside.py", str(outside)])
    technologies = manual_technologies(repository, ["Flask"])
    surface = identify_attack_surface(repository, inventory, technologies)

    result = identify_input_sources(repository, inventory, technologies, surface)

    reasons = {issue.reason for issue in result.issues}
    assert AnalysisIssueReason.OUTSIDE_ROOT in reasons
    assert AnalysisIssueReason.INVALID_PATH in reasons
    assert result.inputs == []


def test_sensitive_and_excluded_files_are_never_read(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_text(repository / ".env", "SECRET=super-secret\n")
    write_text(
        repository / "credentials.py",
        "from flask import Flask, request\napp = Flask(__name__)\n",
    )
    write_text(
        repository / "node_modules" / "pkg" / "index.js",
        "const express = require('express');\nconst app = express();\n",
    )
    write_text(
        repository / "main.py",
        "from flask import Flask, request\napp = Flask(__name__)\n",
    )

    inventory = manual_inventory(
        repository,
        [".env", "credentials.py", "node_modules/pkg/index.js", "main.py"],
    )
    technologies = manual_technologies(repository, ["Flask"])
    surface = identify_attack_surface(repository, inventory, technologies)
    real_open = Path.open

    def guarded_open(path: Path, *args: object, **kwargs: object) -> object:
        if path.name in {".env", "credentials.py", "index.js"}:
            raise AssertionError("Input analysis must not read sensitive files")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)

    result = identify_input_sources(repository, inventory, technologies, surface)

    assert result.summary.source_files_inspected == 1
    assert any(
        issue.source_file == "credentials.py" and issue.reason is AnalysisIssueReason.SENSITIVE_FILE
        for issue in result.issues
    )
    assert any(
        issue.source_file == "node_modules/pkg/index.js"
        and issue.reason is AnalysisIssueReason.EXCLUDED_PATH
        for issue in result.issues
    )
    assert all(issue.source_file != ".env" for issue in result.issues)


def test_source_not_in_inventory_is_never_inspected(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_text(
        repository / "listed.py",
        "from flask import Flask, request\napp = Flask(__name__)\n",
    )
    write_text(
        repository / "unlisted.py",
        "from flask import Flask, request\napp = Flask(__name__)\n",
    )
    inventory = manual_inventory(repository, ["listed.py"])
    technologies = manual_technologies(repository, ["Flask"])
    surface = identify_attack_surface(repository, inventory, technologies)
    real_open = Path.open

    def guarded_open(path: Path, *args: object, **kwargs: object) -> object:
        if path.name == "unlisted.py":
            raise AssertionError("Unlisted source files must not be read")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)

    result = identify_input_sources(repository, inventory, technologies, surface)

    assert result.summary.source_files_inspected == 1
    assert result.inputs == []


def test_empty_repository_and_deterministic_output(repository: Path) -> None:
    empty = analyze(repository)
    assert empty.inputs == []
    assert empty.issues == []
    assert empty.summary.source_files_inspected == 0
    assert empty.summary.is_complete is True

    write_requirements(repository, "flask")
    write_text(
        repository / "app.py",
        source(
            """
            from flask import Flask, request

            app = Flask(__name__)

            @app.get("/search")
            def search():
                return request.args.get("q")
            """
        ),
    )

    inventory = discover_repository(repository)
    technologies = detect_technologies(repository, inventory)
    surface = identify_attack_surface(repository, inventory, technologies)
    first = identify_input_sources(repository, inventory, technologies, surface)
    second = identify_input_sources(repository, inventory, technologies, surface)
    assert first.model_dump() == second.model_dump()

    shuffled = inventory.model_copy(deep=True)
    shuffled.files.reverse()
    third = identify_input_sources(repository, shuffled, technologies, surface)
    assert third.model_dump() == first.model_dump()


def test_incomplete_discovery_is_propagated(repository: Path) -> None:
    write_requirements(repository, "flask")
    write_text(
        repository / "app.py",
        "from flask import Flask, request\napp = Flask(__name__)\n",
    )
    inventory = manual_inventory(
        repository,
        ["app.py"],
        is_complete=False,
        truncation_reasons=[DiscoveryTruncationReason.MAX_FILE_COUNT],
    )
    technologies = manual_technologies(repository, ["Flask"])
    surface = identify_attack_surface(repository, inventory, technologies)

    result = identify_input_sources(repository, inventory, technologies, surface)

    assert result.summary.discovery_is_complete is False
    assert result.summary.discovery_truncation_reasons == [DiscoveryTruncationReason.MAX_FILE_COUNT]
    assert result.summary.is_complete is False


def test_discovery_skipped_source_file_is_reported(repository: Path) -> None:
    inventory = manual_inventory(
        repository,
        [],
        skipped=[
            SkippedItem(
                relative_path="skipped.py",
                kind=DiscoveryItemKind.FILE,
                reason=DiscoverySkipReason.SYMLINK,
                detail="Symbolic links are not followed",
            )
        ],
    )
    technologies = manual_technologies(repository, [])
    surface = identify_attack_surface(repository, inventory, technologies)

    result = identify_input_sources(repository, inventory, technologies, surface)

    assert any(
        issue.source_file == "skipped.py" and issue.reason is AnalysisIssueReason.SYMLINK
        for issue in result.issues
    )
    assert result.summary.is_complete is False


def test_root_mismatches_are_rejected(
    repository: Path,
    tmp_path: Path,
) -> None:
    inventory = manual_inventory(repository, [])
    technologies = manual_technologies(repository, [])
    surface = identify_attack_surface(repository, inventory, technologies)

    mismatched_technologies = technologies.model_copy(deep=True)
    mismatched_technologies.root = str((tmp_path / "other").resolve())
    with pytest.raises(InvalidInputSourceRootError):
        identify_input_sources(repository, inventory, mismatched_technologies, surface)

    mismatched_surface = surface.model_copy(deep=True)
    mismatched_surface.root = str((tmp_path / "other").resolve())
    with pytest.raises(InvalidInputSourceRootError):
        identify_input_sources(repository, inventory, technologies, mismatched_surface)


def test_root_outside_allowed_roots_is_rejected(
    allowed_root: Path,
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    inventory = manual_inventory(outside, [])
    technologies = manual_technologies(outside, [])
    surface = SimpleNamespace(root=str(outside.resolve()), routes=[])

    with pytest.raises(InvalidInputSourceRootError):
        identify_input_sources(outside, inventory, technologies, surface)


def test_negative_limits_are_rejected(repository: Path) -> None:
    inventory = manual_inventory(repository, [])
    technologies = manual_technologies(repository, [])
    surface = SimpleNamespace(root=str(repository.resolve()), routes=[])

    with pytest.raises(InputSourceAnalysisError):
        identify_input_sources(
            repository,
            inventory,
            technologies,
            surface,
            max_source_file_size_bytes=-1,
        )
    with pytest.raises(InputSourceAnalysisError):
        identify_input_sources(
            repository,
            inventory,
            technologies,
            surface,
            max_source_files=-1,
        )


def test_output_never_contains_runtime_values(repository: Path) -> None:
    write_requirements(repository, "fastapi")
    text = source(
        """
        from fastapi import FastAPI, Query

        app = FastAPI()

        @app.get("/search")
        def search(q: str = Query("default-secret-value")):
            api_key = "super-secret-value"
            return q
        """
    )
    write_text(repository / "main.py", text)

    result = analyze(repository)

    dumped = json.dumps(result.model_dump(mode="json"), sort_keys=True)
    assert "default-secret-value" not in dumped
    assert "super-secret-value" not in dumped
    candidate = find_input(result, InputType.QUERY, "q", "search")
    assert candidate is not None
    assert candidate.declaration_or_access == "q: Query(...)"
