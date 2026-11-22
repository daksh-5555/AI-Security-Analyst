import json
import os
import stat
import textwrap
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest

from app.core.config import settings
from app.schemas.attack_surface import (
    AnalysisIssueReason,
    AttackSurfaceResult,
)
from app.schemas.auth_controls import (
    AuthControlCandidate,
    AuthControlResult,
    ControlResolutionStatus,
    ControlScopeType,
    ControlType,
)
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
from app.schemas.technology import (
    TechnologyCategory,
    TechnologyDetection,
    TechnologyDetectionMethod,
    TechnologyDetectionResult,
    TechnologyDetectionSummary,
    TechnologyEvidence,
)
from app.services.attack_surface import identify_attack_surface
from app.services.auth_controls import (
    AuthControlAnalysisError,
    InvalidAuthControlRootError,
    identify_auth_controls,
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
) -> AuthControlResult:
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
    return identify_auth_controls(
        repository,
        resolved_inventory,
        resolved_technologies,
        resolved_surface,
        **kwargs,
    )


def find_control(
    result: AuthControlResult,
    control_type: ControlType,
    mechanism: str | None = None,
    symbol_name: str | None = None,
) -> AuthControlCandidate | None:
    for control in result.controls:
        if control.control_type is not control_type:
            continue
        if mechanism is not None and control.mechanism != mechanism:
            continue
        if symbol_name is not None and control.symbol_name != symbol_name:
            continue
        return control
    return None


def line_of(text: str, needle: str) -> int:
    for index, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return index
    raise AssertionError(f"Line containing {needle!r} was not found")


def test_fastapi_route_level_depends_and_security(repository: Path) -> None:
    write_requirements(repository, "fastapi")
    text = source(
        """
        from fastapi import Depends, FastAPI, Security

        app = FastAPI()

        def get_current_user():
            return {}

        def oauth2_scheme():
            return {}

        @app.get("/me")
        def me(user=Depends(get_current_user), token=Security(oauth2_scheme)):
            return {}
        """
    )
    write_text(repository / "main.py", text)

    result = analyze(repository)

    depends = find_control(result, ControlType.AUTHENTICATION, "Depends", "get_current_user")
    security = find_control(result, ControlType.AUTHENTICATION, "Security", "oauth2_scheme")
    assert depends is not None
    assert security is not None
    assert depends.scope_type is ControlScopeType.ROUTE
    assert security.scope_type is ControlScopeType.ROUTE
    assert depends.line_number == line_of(text, "def me(")
    assert [route.path for route in depends.associated_routes] == ["/me"]
    assert [route.path for route in security.associated_routes] == ["/me"]
    assert depends.resolution_status is ControlResolutionStatus.RESOLVED
    assert result.summary.authentication_control_count == 2
    assert result.summary.authorization_control_count == 0
    assert result.summary.route_association_count == 2


def test_fastapi_router_and_application_dependencies(repository: Path) -> None:
    write_requirements(repository, "fastapi")
    text = source(
        """
        from fastapi import APIRouter, Depends, FastAPI

        def get_current_user():
            return {}

        def require_admin():
            return {}

        app = FastAPI(dependencies=[Depends(get_current_user)])
        router = APIRouter(prefix="/api", dependencies=[Depends(require_admin)])

        @router.get("/items")
        def items():
            return []

        @app.get("/health")
        def health():
            return {}
        """
    )
    write_text(repository / "main.py", text)

    result = analyze(repository)

    application = find_control(
        result,
        ControlType.AUTHENTICATION,
        "FastAPI(dependencies=...)",
        "app",
    )
    router = find_control(
        result,
        ControlType.AUTHORIZATION,
        "APIRouter(dependencies=...)",
        "router",
    )
    assert application is not None
    assert application.scope_type is ControlScopeType.APPLICATION
    assert {route.path for route in application.associated_routes} == {"/api/items", "/health"}
    assert router is not None
    assert router.scope_type is ControlScopeType.ROUTER
    assert [route.path for route in router.associated_routes] == ["/api/items"]
    assert router.resolution_status is ControlResolutionStatus.RESOLVED


def test_fastapi_include_router_dependencies(repository: Path) -> None:
    write_requirements(repository, "fastapi")
    text = source(
        """
        from fastapi import APIRouter, Depends, FastAPI

        def require_permission():
            return {}

        app = FastAPI()
        router = APIRouter(prefix="/api")

        @router.get("/items")
        def items():
            return []

        app.include_router(router, dependencies=[Depends(require_permission)])
        """
    )
    write_text(repository / "main.py", text)

    result = analyze(repository)

    control = find_control(
        result,
        ControlType.AUTHORIZATION,
        "include_router(dependencies=...)",
        "router",
    )
    assert control is not None
    assert control.scope_type is ControlScopeType.ROUTER
    assert [route.path for route in control.associated_routes] == ["/api/items"]


def test_flask_authentication_decorators_and_before_request(repository: Path) -> None:
    write_requirements(repository, "flask")
    text = source(
        """
        from flask import Blueprint, Flask
        from flask_login import login_required
        from auth_helpers import permission_required

        app = Flask(__name__)
        bp = Blueprint("bp", __name__)

        @bp.before_request
        def load_user():
            return None

        @bp.route("/admin")
        @login_required
        @permission_required("admin")
        def admin():
            return "ok"

        app.register_blueprint(bp)
        """
    )
    write_text(repository / "app.py", text)

    result = analyze(repository)

    before_request = find_control(
        result,
        ControlType.AUTHENTICATION,
        "@before_request",
        "load_user",
    )
    login = find_control(result, ControlType.AUTHENTICATION, "@login_required", "admin")
    permission = find_control(
        result,
        ControlType.AUTHORIZATION,
        "@permission_required",
        "admin",
    )
    assert before_request is not None
    assert before_request.scope_type is ControlScopeType.ROUTER
    assert [route.path for route in before_request.associated_routes] == ["/admin"]
    assert login is not None
    assert login.scope_type is ControlScopeType.ROUTE
    assert [route.path for route in login.associated_routes] == ["/admin"]
    assert permission is not None
    assert permission.scope_type is ControlScopeType.ROUTE
    assert result.summary.authentication_control_count == 2
    assert result.summary.authorization_control_count == 1


def test_django_authentication_and_permission_declarations(repository: Path) -> None:
    write_requirements(repository, "django")
    views = source(
        """
        from django.contrib.auth.decorators import login_required, permission_required
        from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin

        @login_required
        def dashboard(request):
            return None

        @permission_required("app.change_item")
        def manage(request):
            return None

        class AdminView(LoginRequiredMixin, PermissionRequiredMixin):
            permission_required = "app.change_item"

            def get(self, request):
                return None
        """
    )
    write_text(repository / "views.py", views)
    write_text(
        repository / "urls.py",
        source(
            """
            from django.urls import path
            from . import views

            urlpatterns = [
                path("dashboard/", views.dashboard),
                path("manage/", views.manage),
                path("admin/", views.AdminView.as_view()),
            ]
            """
        ),
    )

    result = analyze(repository)

    login = find_control(result, ControlType.AUTHENTICATION, "@login_required", "dashboard")
    permission = find_control(
        result,
        ControlType.AUTHORIZATION,
        "@permission_required",
        "manage",
    )
    login_mixin = find_control(
        result,
        ControlType.AUTHENTICATION,
        "class LoginRequiredMixin",
        "AdminView",
    )
    permission_mixin = find_control(
        result,
        ControlType.AUTHORIZATION,
        "class PermissionRequiredMixin",
        "AdminView",
    )
    assert login is not None
    assert [route.path for route in login.associated_routes] == ["dashboard/"]
    assert permission is not None
    assert [route.path for route in permission.associated_routes] == ["manage/"]
    assert login_mixin is not None
    assert login_mixin.scope_type is ControlScopeType.CLASS
    assert [route.path for route in login_mixin.associated_routes] == ["admin/"]
    assert permission_mixin is not None
    assert permission_mixin.scope_type is ControlScopeType.CLASS
    assert [route.path for route in permission_mixin.associated_routes] == ["admin/"]


def test_express_route_level_middleware(repository: Path) -> None:
    write_package_json(repository, {"express": "^4.18.0"})
    text = source(
        """
        const express = require('express');
        const app = express();

        app.get('/admin', authenticate, isAdmin, handler);
        app.get('/public', logger, handler);
        """
    )
    write_text(repository / "server.js", text)

    result = analyze(repository)

    authenticate = find_control(result, ControlType.AUTHENTICATION, "app.get", "authenticate")
    is_admin = find_control(result, ControlType.AUTHORIZATION, "app.get", "isAdmin")
    assert authenticate is not None
    assert is_admin is not None
    assert authenticate.scope_type is ControlScopeType.ROUTE
    assert is_admin.scope_type is ControlScopeType.ROUTE
    assert [route.path for route in authenticate.associated_routes] == ["/admin"]
    assert [route.path for route in is_admin.associated_routes] == ["/admin"]
    assert find_control(result, ControlType.AUTHENTICATION, "app.get", "logger") is None


def test_express_router_and_application_middleware(repository: Path) -> None:
    write_package_json(repository, {"express": "^4.18.0"})
    text = source(
        """
        const express = require('express');
        const app = express();
        const router = express.Router();

        app.use(passport.authenticate('jwt', { session: false }));
        router.use(requireRole('admin'));
        router.get('/items', handler);
        app.use('/api', router);
        """
    )
    write_text(repository / "server.js", text)

    result = analyze(repository)

    application = find_control(
        result,
        ControlType.AUTHENTICATION,
        "app.use",
        "authenticate",
    )
    router = find_control(
        result,
        ControlType.AUTHORIZATION,
        "router.use",
        "requireRole",
    )
    assert application is not None
    assert application.scope_type is ControlScopeType.APPLICATION
    assert [route.path for route in application.associated_routes] == ["/api/items"]
    assert router is not None
    assert router.scope_type is ControlScopeType.ROUTER
    assert [route.path for route in router.associated_routes] == ["/api/items"]


def test_nestjs_guards_and_role_declarations(repository: Path) -> None:
    write_package_json(repository, {"@nestjs/common": "^10.0.0"})
    text = source(
        """
        import { Controller, Get, UseGuards, Roles, Public } from '@nestjs/common';

        @Injectable()
        export class JwtAuthGuard implements CanActivate {
          canActivate(context) { return true; }
        }

        @Controller('admin')
        @UseGuards(AuthGuard)
        export class AdminController {
          @Get()
          @Roles('admin')
          findAll() {}

          @Public()
          @Get('public')
          publicRoute() {}
        }
        """
    )
    write_text(repository / "admin.controller.ts", text)

    result = analyze(repository)

    guard = find_control(result, ControlType.AUTHENTICATION, "@UseGuards", "AuthGuard")
    roles = find_control(result, ControlType.AUTHORIZATION, "@Roles", "findAll")
    public = find_control(result, ControlType.AUTHENTICATION, "@Public", "publicRoute")
    guard_class = find_control(result, ControlType.AUTHENTICATION, "guard class", "JwtAuthGuard")
    assert guard is not None
    assert guard.scope_type is ControlScopeType.CONTROLLER
    assert {route.path for route in guard.associated_routes} == {"/admin", "/admin/public"}
    assert roles is not None
    assert roles.scope_type is ControlScopeType.ROUTE
    assert [route.path for route in roles.associated_routes] == ["/admin"]
    assert public is not None
    assert [route.path for route in public.associated_routes] == ["/admin/public"]
    assert guard_class is not None
    assert guard_class.scope_type is ControlScopeType.CLASS
    assert guard_class.line_number == line_of(text, "export class JwtAuthGuard")


def test_dynamic_dependencies_and_guards_are_structured_issues(repository: Path) -> None:
    write_requirements(repository, "fastapi")
    write_package_json(repository, {"@nestjs/common": "^10.0.0"})
    write_text(
        repository / "main.py",
        source(
            """
            from fastapi import Depends, FastAPI

            app = FastAPI()

            @app.get("/dynamic")
            def dynamic(user=Depends(build_dependency())):
                return {}
            """
        ),
    )
    write_text(
        repository / "dynamic.controller.ts",
        source(
            """
            import { Controller, Get, UseGuards } from '@nestjs/common';

            @Controller('dynamic')
            export class DynamicController {
              @UseGuards(getGuard())
              @Get()
              find() {}
            }
            """
        ),
    )

    result = analyze(repository)

    assert result.controls == []
    details = [issue.detail or "" for issue in result.issues]
    assert any("Dynamic Depends target" in detail for detail in details)
    assert any("NestJS guard" in detail for detail in details)
    assert all(issue.reason is AnalysisIssueReason.UNSUPPORTED_SYNTAX for issue in result.issues)


def test_arbitrary_names_are_not_controls(repository: Path) -> None:
    write_requirements(repository, "fastapi")
    write_package_json(repository, {"express": "^4.18.0", "@nestjs/common": "^10.0.0"})
    write_text(
        repository / "main.py",
        source(
            """
            from fastapi import Depends, FastAPI

            app = FastAPI()

            def get_db():
                return None

            @app.get("/items")
            def items(db=Depends(get_db)):
                return []
            """
        ),
    )
    write_text(
        repository / "server.js",
        source(
            """
            const express = require('express');
            const app = express();

            app.get('/items', logger, bodyParser.json(), cors(), handler);
            """
        ),
    )
    write_text(
        repository / "logging.controller.ts",
        source(
            """
            import { Controller, Get, UseGuards } from '@nestjs/common';

            @Controller('items')
            export class ItemsController {
              @UseGuards(LoggingGuard)
              @Get()
              find() {}
            }
            """
        ),
    )

    result = analyze(repository)

    assert all(control.symbol_name != "get_db" for control in result.controls)
    assert all(control.symbol_name != "logger" for control in result.controls)
    assert all(control.symbol_name != "bodyParser" for control in result.controls)
    assert all(control.symbol_name != "cors" for control in result.controls)
    assert all(control.symbol_name != "LoggingGuard" for control in result.controls)
    assert any("LoggingGuard" in (issue.detail or "") for issue in result.issues)


def test_multiple_controls_on_one_route(repository: Path) -> None:
    write_package_json(repository, {"express": "^4.18.0"})
    write_text(
        repository / "server.js",
        source(
            """
            const express = require('express');
            const app = express();

            app.post('/admin', authenticate, requireRole('admin'), handler);
            """
        ),
    )

    result = analyze(repository)

    associated = [
        control
        for control in result.controls
        if any(route.path == "/admin" for route in control.associated_routes)
    ]
    assert len(associated) == 2
    assert {control.control_type for control in associated} == {
        ControlType.AUTHENTICATION,
        ControlType.AUTHORIZATION,
    }


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
        "from fastapi import Depends, FastAPI\napp = FastAPI()\n",
    )
    link = repository / "link.py"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks are not supported on this platform")

    result = identify_auth_controls(
        repository,
        manual_inventory(repository, ["link.py"]),
        manual_technologies(repository, ["FastAPI"]),
        identify_attack_surface(
            repository,
            manual_inventory(repository, ["link.py"]),
            manual_technologies(repository, ["FastAPI"]),
        ),
    )

    assert any(issue.reason is AnalysisIssueReason.SYMLINK for issue in result.issues)
    assert result.controls == []


def test_symlink_metadata_is_rejected(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_text(
        repository / "app.py",
        "from fastapi import Depends, FastAPI\napp = FastAPI()\n",
    )
    inventory = manual_inventory(repository, ["app.py"])
    technologies = manual_technologies(repository, ["FastAPI"])
    surface = identify_attack_surface(repository, inventory, technologies)
    real_lstat = Path.lstat

    def fake_lstat(path: Path) -> os.stat_result:
        if path.name == "app.py":
            return os.stat_result((stat.S_IFLNK | 0o777, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", fake_lstat)

    result = identify_auth_controls(repository, inventory, technologies, surface)

    assert any(issue.reason is AnalysisIssueReason.SYMLINK for issue in result.issues)
    assert result.controls == []


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
        "from fastapi import FastAPI\napp = FastAPI()\n",
    )
    inventory = manual_inventory(repository, ["app.py"])
    technologies = manual_technologies(repository, ["FastAPI"])
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

    result = identify_auth_controls(repository, inventory, technologies, surface)

    assert any(issue.reason is AnalysisIssueReason.SYMLINK for issue in result.issues)
    assert result.controls == []


def test_traversal_and_absolute_paths_are_rejected(
    repository: Path,
    tmp_path: Path,
) -> None:
    outside = write_text(
        tmp_path / "outside.py",
        "from fastapi import FastAPI\napp = FastAPI()\n",
    )
    inventory = manual_inventory(repository, ["../outside.py", str(outside)])
    technologies = manual_technologies(repository, ["FastAPI"])
    surface = identify_attack_surface(repository, inventory, technologies)

    result = identify_auth_controls(repository, inventory, technologies, surface)

    reasons = {issue.reason for issue in result.issues}
    assert AnalysisIssueReason.OUTSIDE_ROOT in reasons
    assert AnalysisIssueReason.INVALID_PATH in reasons
    assert result.controls == []


def test_sensitive_and_excluded_files_are_never_read(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_text(repository / ".env", "SECRET=super-secret\n")
    write_text(
        repository / "credentials.py",
        "from fastapi import FastAPI\napp = FastAPI()\n",
    )
    write_text(
        repository / "node_modules" / "pkg" / "index.js",
        "const express = require('express');\nconst app = express();\n",
    )
    write_text(
        repository / "main.py",
        "from fastapi import FastAPI\napp = FastAPI()\n",
    )

    inventory = manual_inventory(
        repository,
        [".env", "credentials.py", "node_modules/pkg/index.js", "main.py"],
    )
    technologies = manual_technologies(repository, ["FastAPI"])
    surface = identify_attack_surface(repository, inventory, technologies)
    real_open = Path.open

    def guarded_open(path: Path, *args: object, **kwargs: object) -> object:
        if path.name in {".env", "credentials.py", "index.js"}:
            raise AssertionError("Authentication analysis must not read sensitive files")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)

    result = identify_auth_controls(repository, inventory, technologies, surface)

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
        "from fastapi import FastAPI\napp = FastAPI()\n",
    )
    write_text(
        repository / "unlisted.py",
        "from fastapi import Depends, FastAPI\napp = FastAPI()\n",
    )
    inventory = manual_inventory(repository, ["listed.py"])
    technologies = manual_technologies(repository, ["FastAPI"])
    surface = identify_attack_surface(repository, inventory, technologies)
    real_open = Path.open

    def guarded_open(path: Path, *args: object, **kwargs: object) -> object:
        if path.name == "unlisted.py":
            raise AssertionError("Unlisted source files must not be read")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)

    result = identify_auth_controls(repository, inventory, technologies, surface)

    assert result.summary.source_files_inspected == 1
    assert result.controls == []


def test_unresolved_scope_is_reported_without_guessing(repository: Path) -> None:
    write_requirements(repository, "fastapi")
    write_text(
        repository / "main.py",
        source(
            """
            from fastapi import Depends, FastAPI

            app = FastAPI()

            def get_current_user():
                return {}

            @app.get(dynamic_path)
            def dynamic(user=Depends(get_current_user)):
                return {}
            """
        ),
    )

    result = analyze(repository)

    assert len(result.controls) == 1
    control = result.controls[0]
    assert control.resolution_status is ControlResolutionStatus.UNRESOLVED
    assert result.summary.unresolved_scope_count == 1


def test_empty_repository_and_deterministic_output(repository: Path) -> None:
    empty = analyze(repository)
    assert empty.controls == []
    assert empty.issues == []
    assert empty.summary.source_files_inspected == 0
    assert empty.summary.is_complete is True

    write_requirements(repository, "fastapi")
    write_text(
        repository / "main.py",
        source(
            """
            from fastapi import Depends, FastAPI

            app = FastAPI()

            def get_current_user():
                return {}

            @app.get("/me")
            def me(user=Depends(get_current_user)):
                return {}
            """
        ),
    )

    inventory = discover_repository(repository)
    technologies = detect_technologies(repository, inventory)
    surface = identify_attack_surface(repository, inventory, technologies)
    first = identify_auth_controls(repository, inventory, technologies, surface)
    second = identify_auth_controls(repository, inventory, technologies, surface)
    assert first.model_dump() == second.model_dump()

    shuffled = inventory.model_copy(deep=True)
    shuffled.files.reverse()
    third = identify_auth_controls(repository, shuffled, technologies, surface)
    assert third.model_dump() == first.model_dump()


def test_incomplete_discovery_is_propagated(repository: Path) -> None:
    write_requirements(repository, "fastapi")
    write_text(
        repository / "main.py",
        "from fastapi import FastAPI\napp = FastAPI()\n",
    )
    inventory = manual_inventory(
        repository,
        ["main.py"],
        is_complete=False,
        truncation_reasons=[DiscoveryTruncationReason.MAX_FILE_COUNT],
    )
    technologies = manual_technologies(repository, ["FastAPI"])
    surface = identify_attack_surface(repository, inventory, technologies)

    result = identify_auth_controls(repository, inventory, technologies, surface)

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

    result = identify_auth_controls(repository, inventory, technologies, surface)

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
    with pytest.raises(InvalidAuthControlRootError):
        identify_auth_controls(repository, inventory, mismatched_technologies, surface)

    mismatched_surface = surface.model_copy(deep=True)
    mismatched_surface.root = str((tmp_path / "other").resolve())
    with pytest.raises(InvalidAuthControlRootError):
        identify_auth_controls(repository, inventory, technologies, mismatched_surface)


def test_root_outside_allowed_roots_is_rejected(
    allowed_root: Path,
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    inventory = manual_inventory(outside, [])
    technologies = manual_technologies(outside, [])
    surface = SimpleNamespace(root=str(outside.resolve()), routes=[])

    with pytest.raises(InvalidAuthControlRootError):
        identify_auth_controls(outside, inventory, technologies, surface)


def test_negative_limits_are_rejected(repository: Path) -> None:
    inventory = manual_inventory(repository, [])
    technologies = manual_technologies(repository, [])
    surface = identify_attack_surface(repository, inventory, technologies)

    with pytest.raises(AuthControlAnalysisError):
        identify_auth_controls(
            repository,
            inventory,
            technologies,
            surface,
            max_source_files=-1,
        )
