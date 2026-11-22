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
    HttpMethod,
    RouteCandidate,
    RouteFramework,
    RouteResolutionStatus,
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
from app.services.attack_surface import (
    AttackSurfaceError,
    InvalidAttackSurfaceRootError,
    identify_attack_surface,
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
    **kwargs: object,
) -> AttackSurfaceResult:
    resolved_inventory = inventory or discover_repository(repository)
    resolved_technologies = technologies or detect_technologies(
        repository,
        resolved_inventory,
    )
    return identify_attack_surface(
        repository,
        resolved_inventory,
        resolved_technologies,
        **kwargs,
    )


def find_route(
    result: AttackSurfaceResult,
    path: str,
    method: HttpMethod | None = None,
    framework: RouteFramework | None = None,
) -> RouteCandidate | None:
    for route in result.routes:
        if route.path != path:
            continue
        if method is not None and route.http_method is not method:
            continue
        if framework is not None and route.framework is not framework:
            continue
        return route
    return None


def line_of(text: str, needle: str) -> int:
    for index, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return index
    raise AssertionError(f"Line containing {needle!r} was not found")


def test_fastapi_get_post_and_router_prefix(repository: Path) -> None:
    write_requirements(repository, "fastapi")
    text = source(
        """
        from fastapi import APIRouter, FastAPI

        app = FastAPI()
        router = APIRouter(prefix="/api")

        @app.get("/health")
        def health():
            return {}

        @router.post("/items")
        def create_item():
            return {}

        app.include_router(router, prefix="/v1")
        """
    )
    write_text(repository / "main.py", text)

    result = analyze(repository)

    health = find_route(result, "/health", HttpMethod.GET, RouteFramework.FASTAPI)
    assert health is not None
    assert health.handler_name == "health"
    assert health.line_number == line_of(text, '@app.get("/health")')
    assert health.detection_confidence == 0.95
    assert health.resolution_status is RouteResolutionStatus.RESOLVED

    item = find_route(result, "/api/v1/items", HttpMethod.POST, RouteFramework.FASTAPI)
    assert item is not None
    assert item.handler_name == "create_item"
    assert item.line_number == line_of(text, '@router.post("/items")')
    assert result.summary.route_count == 2


def test_fastapi_multiple_decorators_and_keyword_path(repository: Path) -> None:
    write_requirements(repository, "fastapi")
    text = source(
        """
        from fastapi import FastAPI

        app = FastAPI()

        @app.get("/items")
        @app.post(path="/items")
        def items():
            return []
        """
    )
    write_text(repository / "main.py", text)

    result = analyze(repository)

    duplicates = [route for route in result.routes if route.path == "/items"]
    assert len(duplicates) == 2
    assert {route.http_method for route in duplicates} == {
        HttpMethod.GET,
        HttpMethod.POST,
    }
    assert all(route.handler_name == "items" for route in duplicates)


def test_python_static_constant_and_concatenation(repository: Path) -> None:
    write_requirements(repository, "fastapi")
    text = source(
        """
        from fastapi import FastAPI

        BASE = "/api"
        app = FastAPI()

        @app.get(BASE + "/items")
        def items():
            return []
        """
    )
    write_text(repository / "main.py", text)

    result = analyze(repository)

    route = find_route(result, "/api/items", HttpMethod.GET)
    assert route is not None
    assert route.resolution_status is RouteResolutionStatus.RESOLVED


def test_python_dynamic_route_is_unresolved(repository: Path) -> None:
    write_requirements(repository, "fastapi")
    text = source(
        """
        from fastapi import FastAPI

        app = FastAPI()

        @app.get(get_path())
        def dynamic():
            return {}
        """
    )
    write_text(repository / "main.py", text)

    result = analyze(repository)

    assert len(result.routes) == 1
    route = result.routes[0]
    assert route.path == "get_path()"
    assert route.resolution_status is RouteResolutionStatus.UNRESOLVED
    assert route.detection_confidence == 0.50
    assert result.summary.resolved_route_count == 0
    assert result.summary.unresolved_route_count == 1


def test_unresolved_router_prefix_is_unresolved(repository: Path) -> None:
    write_requirements(repository, "fastapi")
    text = source(
        """
        import os
        from fastapi import APIRouter

        router = APIRouter(prefix=os.environ["API_PREFIX"])

        @router.get("/items")
        def items():
            return []
        """
    )
    write_text(repository / "main.py", text)

    result = analyze(repository)

    assert len(result.routes) == 1
    route = result.routes[0]
    assert route.resolution_status is RouteResolutionStatus.UNRESOLVED
    assert "os.environ" in route.path
    assert route.path.endswith("/items")


def test_flask_routes_methods_and_blueprint_prefix(repository: Path) -> None:
    write_requirements(repository, "flask")
    text = source(
        """
        from flask import Blueprint, Flask

        app = Flask(__name__)
        bp = Blueprint("bp", __name__, url_prefix="/api")

        @app.route("/")
        def index():
            return "ok"

        @bp.route("/items", methods=["GET", "POST"])
        def items():
            return "items"

        app.register_blueprint(bp, url_prefix="/v1")
        """
    )
    write_text(repository / "app.py", text)

    result = analyze(repository)

    index = find_route(result, "/", HttpMethod.GET, RouteFramework.FLASK)
    assert index is not None
    assert index.handler_name == "index"
    assert index.line_number == line_of(text, '@app.route("/")')

    get_item = find_route(result, "/api/v1/items", HttpMethod.GET, RouteFramework.FLASK)
    post_item = find_route(result, "/api/v1/items", HttpMethod.POST, RouteFramework.FLASK)
    assert get_item is not None
    assert post_item is not None
    assert get_item.handler_name == "items"
    assert result.summary.route_count == 3


def test_flask_shortcut_decorator(repository: Path) -> None:
    write_requirements(repository, "flask")
    text = source(
        """
        from flask import Flask

        app = Flask(__name__)

        @app.get("/shortcut")
        def shortcut():
            return "ok"
        """
    )
    write_text(repository / "app.py", text)

    result = analyze(repository)

    route = find_route(result, "/shortcut", HttpMethod.GET, RouteFramework.FLASK)
    assert route is not None
    assert route.handler_name == "shortcut"


def test_flask_dynamic_methods_are_reported(repository: Path) -> None:
    write_requirements(repository, "flask")
    text = source(
        """
        from flask import Flask

        app = Flask(__name__)
        METHODS = ["GET", "POST"]

        @app.route("/dynamic-methods", methods=METHODS)
        def dynamic_methods():
            return ""
        """
    )
    write_text(repository / "app.py", text)

    result = analyze(repository)

    route = find_route(result, "/dynamic-methods", HttpMethod.ANY, RouteFramework.FLASK)
    assert route is not None
    assert any(issue.reason is AnalysisIssueReason.UNSUPPORTED_SYNTAX for issue in result.issues)


def test_django_path_and_re_path(repository: Path) -> None:
    write_requirements(repository, "django")
    text = source(
        """
        from django.urls import path, re_path
        from . import views

        urlpatterns = [
            path("users/<int:pk>/", views.user_detail, name="user-detail"),
            re_path(r"^articles/(?P<year>[0-9]{4})/$", views.articles),
        ]
        """
    )
    write_text(repository / "urls.py", text)

    result = analyze(repository)

    user = find_route(result, "users/<int:pk>/", HttpMethod.ANY, RouteFramework.DJANGO)
    assert user is not None
    assert user.handler_name == "user_detail"
    assert user.line_number == line_of(text, 'path("users/')

    articles = find_route(
        result,
        "^articles/(?P<year>[0-9]{4})/$",
        HttpMethod.ANY,
        RouteFramework.DJANGO,
    )
    assert articles is not None
    assert articles.handler_name == "articles"
    assert result.summary.route_count == 2


def test_django_dynamic_path_is_unresolved(repository: Path) -> None:
    write_requirements(repository, "django")
    text = source(
        """
        from django.urls import path
        from . import views

        urlpatterns = [path(build_path(), views.index)]
        """
    )
    write_text(repository / "urls.py", text)

    result = analyze(repository)

    assert len(result.routes) == 1
    route = result.routes[0]
    assert route.path == "build_path()"
    assert route.resolution_status is RouteResolutionStatus.UNRESOLVED


def test_python_multiline_declarations(repository: Path) -> None:
    write_requirements(repository, "fastapi", "flask")
    text = source(
        """
        from fastapi import FastAPI
        from flask import Flask

        app = FastAPI()
        flask_app = Flask(__name__)

        @app.get(
            "/multi",
        )
        def multi():
            return {}

        @flask_app.route(
            "/multi-flask",
            methods=[
                "GET",
                "POST",
            ],
        )
        def multi_flask():
            return ""
        """
    )
    write_text(repository / "main.py", text)

    result = analyze(repository)

    assert find_route(result, "/multi", HttpMethod.GET, RouteFramework.FASTAPI) is not None
    assert find_route(result, "/multi-flask", HttpMethod.GET, RouteFramework.FLASK) is not None
    assert find_route(result, "/multi-flask", HttpMethod.POST, RouteFramework.FLASK) is not None


def test_python_triple_quoted_route(repository: Path) -> None:
    write_requirements(repository, "fastapi")
    text = source(
        """
        from fastapi import FastAPI

        app = FastAPI()

        @app.get('''/triple''')
        def triple():
            return {}
        """
    )
    write_text(repository / "main.py", text)

    result = analyze(repository)

    route = find_route(result, "/triple", HttpMethod.GET, RouteFramework.FASTAPI)
    assert route is not None
    assert route.handler_name == "triple"


def test_duplicate_route_declarations_are_preserved(repository: Path) -> None:
    write_requirements(repository, "fastapi")
    text = source(
        """
        from fastapi import FastAPI

        app = FastAPI()

        @app.get("/dup")
        def first():
            return {}

        @app.get("/dup")
        def second():
            return {}
        """
    )
    write_text(repository / "main.py", text)

    result = analyze(repository)

    duplicates = [route for route in result.routes if route.path == "/dup"]
    assert len(duplicates) == 2
    assert {route.handler_name for route in duplicates} == {"first", "second"}


def test_invalid_python_syntax_is_reported(repository: Path) -> None:
    write_requirements(repository, "fastapi")
    write_text(repository / "broken.py", "def broken(:\n    pass\n")

    result = analyze(repository)

    assert result.routes == []
    assert any(
        issue.source_file == "broken.py" and issue.reason is AnalysisIssueReason.INVALID_SYNTAX
        for issue in result.issues
    )
    assert result.summary.source_files_inspected == 1
    assert result.summary.is_complete is False


def test_express_app_and_router_routes(repository: Path) -> None:
    write_package_json(repository, {"express": "^4.18.0"})
    text = source(
        """
        const express = require('express');
        const app = express();
        const router = express.Router();

        app.get('/health', healthCheck);
        router.post('/users', createUser);
        app.use('/api', router);

        function healthCheck(req, res) {}
        function createUser(req, res) {}
        """
    )
    write_text(repository / "server.js", text)

    result = analyze(repository)

    health = find_route(result, "/health", HttpMethod.GET, RouteFramework.EXPRESS)
    assert health is not None
    assert health.handler_name == "healthCheck"
    assert health.line_number == line_of(text, "app.get('/health'")
    assert health.detection_confidence == 0.85

    user = find_route(result, "/api/users", HttpMethod.POST, RouteFramework.EXPRESS)
    assert user is not None
    assert user.handler_name == "createUser"
    assert user.line_number == line_of(text, "router.post('/users'")
    assert result.summary.route_count == 2


def test_express_use_concrete_route(repository: Path) -> None:
    write_package_json(repository, {"express": "^4.18.0"})
    text = source(
        """
        const express = require('express');
        const app = express();

        app.use('/metrics', metricsHandler);
        app.use('/static', express.static('public'));
        app.use('/api', router);
        """
    )
    write_text(repository / "server.js", text)

    result = analyze(repository)

    metrics = find_route(result, "/metrics", HttpMethod.ANY, RouteFramework.EXPRESS)
    assert metrics is not None
    assert metrics.handler_name == "metricsHandler"
    assert result.summary.route_count == 1


def test_express_multiple_methods_and_quote_styles(repository: Path) -> None:
    write_package_json(repository, {"express": "^4.18.0"})
    text = source(
        """
        const express = require("express");
        const app = express();

        app.get("/double", h1);
        app.post('/single', h2);
        app.put(`/template`, h3);
        app.patch('/api' + '/concat', h4);
        app.delete('/all', h5);
        """
    )
    write_text(repository / "server.js", text)

    result = analyze(repository)

    assert find_route(result, "/double", HttpMethod.GET) is not None
    assert find_route(result, "/single", HttpMethod.POST) is not None
    assert find_route(result, "/template", HttpMethod.PUT) is not None
    assert find_route(result, "/api/concat", HttpMethod.PATCH) is not None
    assert find_route(result, "/all", HttpMethod.DELETE) is not None


def test_express_dynamic_paths_are_unresolved(repository: Path) -> None:
    write_package_json(repository, {"express": "^4.18.0"})
    text = source(
        """
        const express = require('express');
        const app = express();
        const BASE_PATH = process.env.BASE_PATH;

        app.get(BASE_PATH + '/users', handler);
        app.post(`${BASE_PATH}/items`, handler);
        """
    )
    write_text(repository / "server.js", text)

    result = analyze(repository)

    assert len(result.routes) == 2
    assert all(
        route.resolution_status is RouteResolutionStatus.UNRESOLVED for route in result.routes
    )
    assert any("BASE_PATH" in route.path for route in result.routes)
    assert result.summary.unresolved_route_count == 2


def test_express_comments_and_strings_do_not_create_routes(repository: Path) -> None:
    write_package_json(repository, {"express": "^4.18.0"})
    text = source(
        """
        const express = require('express');
        const app = express();

        // app.get('/comment-fake', handler);
        /* app.post('/block-fake', handler); */
        const message = "app.put('/string-fake', handler)";
        app.get('/real', handler);
        """
    )
    write_text(repository / "server.js", text)

    result = analyze(repository)

    assert find_route(result, "/real", HttpMethod.GET) is not None
    assert find_route(result, "/comment-fake") is None
    assert find_route(result, "/block-fake") is None
    assert find_route(result, "/string-fake") is None
    assert result.summary.route_count == 1


def test_express_multiline_declaration(repository: Path) -> None:
    write_package_json(repository, {"express": "^4.18.0"})
    text = source(
        """
        const express = require('express');
        const app = express();

        app.get(
          '/multi',
          handler,
        );
        """
    )
    write_text(repository / "server.js", text)

    result = analyze(repository)

    route = find_route(result, "/multi", HttpMethod.GET)
    assert route is not None
    assert route.line_number == line_of(text, "app.get(")


def test_express_anonymous_and_named_function_handlers(repository: Path) -> None:
    write_package_json(repository, {"express": "^4.18.0"})
    text = source(
        """
        const express = require('express');
        const app = express();

        app.get('/anonymous', (req, res) => res.send('ok'));
        app.post('/named', function namedHandler(req, res) {});
        app.put('/member', controller.handler);
        """
    )
    write_text(repository / "server.js", text)

    result = analyze(repository)

    anonymous = find_route(result, "/anonymous", HttpMethod.GET)
    named = find_route(result, "/named", HttpMethod.POST)
    member = find_route(result, "/member", HttpMethod.PUT)
    assert anonymous is not None
    assert anonymous.handler_name is None
    assert named is not None
    assert named.handler_name == "namedHandler"
    assert member is not None
    assert member.handler_name == "handler"


def test_express_router_multiple_mounts(repository: Path) -> None:
    write_package_json(repository, {"express": "^4.18.0"})
    text = source(
        """
        const express = require('express');
        const app = express();
        const router = express.Router();

        router.get('/items', handler);
        app.use('/api', router);
        app.use('/v2', router);
        """
    )
    write_text(repository / "server.js", text)

    result = analyze(repository)

    paths = {route.path for route in result.routes if route.http_method is HttpMethod.GET}
    assert paths == {"/api/items", "/v2/items"}


def test_express_dynamic_mount_prefix_is_unresolved(repository: Path) -> None:
    write_package_json(repository, {"express": "^4.18.0"})
    text = source(
        """
        const express = require('express');
        const app = express();
        const router = express.Router();
        const prefix = process.env.PREFIX;

        router.get('/items', handler);
        app.use(prefix, router);
        """
    )
    write_text(repository / "server.js", text)

    result = analyze(repository)

    assert len(result.routes) == 1
    route = result.routes[0]
    assert route.resolution_status is RouteResolutionStatus.UNRESOLVED
    assert "prefix" in route.path
    assert route.path.endswith("/items")


def test_invalid_javascript_syntax_is_reported(repository: Path) -> None:
    write_package_json(repository, {"express": "^4.18.0"})
    write_text(
        repository / "broken.js",
        "const express = require('express');\nconst x = 'unterminated\n",
    )

    result = analyze(repository)

    assert any(
        issue.source_file == "broken.js" and issue.reason is AnalysisIssueReason.INVALID_SYNTAX
        for issue in result.issues
    )
    assert result.summary.source_files_inspected == 1
    assert result.summary.is_complete is False


def test_nestjs_controller_and_method_decorators(repository: Path) -> None:
    write_package_json(repository, {"@nestjs/common": "^10.0.0"})
    text = source(
        """
        import { Controller, Delete, Get, Patch, Post, Put } from '@nestjs/common';

        @Controller('users')
        export class UsersController {
          @Get()
          findAll() {}

          @Get(':id')
          findOne() {}

          @Post()
          create() {}

          @Put(':id')
          update() {}

          @Patch(':id')
          patch() {}

          @Delete(':id')
          remove() {}
        }
        """
    )
    write_text(repository / "users.controller.ts", text)

    result = analyze(repository)

    expected = [
        ("/users", HttpMethod.GET, "findAll"),
        ("/users/:id", HttpMethod.GET, "findOne"),
        ("/users", HttpMethod.POST, "create"),
        ("/users/:id", HttpMethod.PUT, "update"),
        ("/users/:id", HttpMethod.PATCH, "patch"),
        ("/users/:id", HttpMethod.DELETE, "remove"),
    ]
    for path, method, handler in expected:
        route = find_route(result, path, method, RouteFramework.NESTJS)
        assert route is not None
        assert route.handler_name == handler
        assert route.detection_confidence == 0.85

    assert result.summary.route_count == 6
    assert find_route(result, "/users", HttpMethod.GET).line_number == line_of(text, "@Get()")


def test_nestjs_multiple_controllers_reset_prefix(repository: Path) -> None:
    write_package_json(repository, {"@nestjs/common": "^10.0.0"})
    text = source(
        """
        import { Controller, Get } from '@nestjs/common';

        @Controller('users')
        export class UsersController {
          @Get()
          findAll() {}
        }

        @Controller('admin')
        export class AdminController {
          @Get('stats')
          stats() {}
        }
        """
    )
    write_text(repository / "controllers.ts", text)

    result = analyze(repository)

    users = find_route(result, "/users", HttpMethod.GET)
    admin = find_route(result, "/admin/stats", HttpMethod.GET)
    assert users is not None
    assert users.handler_name == "findAll"
    assert admin is not None
    assert admin.handler_name == "stats"


def test_nestjs_object_controller_reports_unsupported_syntax(repository: Path) -> None:
    write_package_json(repository, {"@nestjs/common": "^10.0.0"})
    text = source(
        """
        import { Controller, Get } from '@nestjs/common';

        @Controller({ path: 'users' })
        export class UsersController {
          @Get()
          findAll() {}
        }
        """
    )
    write_text(repository / "users.controller.ts", text)

    result = analyze(repository)

    assert any(
        issue.reason is AnalysisIssueReason.UNSUPPORTED_SYNTAX and "object" in (issue.detail or "")
        for issue in result.issues
    )
    assert len(result.routes) == 1
    assert result.routes[0].resolution_status is RouteResolutionStatus.UNRESOLVED


def test_nestjs_dynamic_route_is_unresolved(repository: Path) -> None:
    write_package_json(repository, {"@nestjs/common": "^10.0.0"})
    text = source(
        """
        import { Controller, Get } from '@nestjs/common';

        @Controller('users')
        export class UsersController {
          @Get(dynamicPath)
          find() {}
        }
        """
    )
    write_text(repository / "users.controller.ts", text)

    result = analyze(repository)

    assert len(result.routes) == 1
    route = result.routes[0]
    assert route.path == "/users/dynamicPath"
    assert route.resolution_status is RouteResolutionStatus.UNRESOLVED
    assert route.detection_confidence == 0.40


def test_invalid_source_encoding_is_reported(repository: Path) -> None:
    write_requirements(repository, "fastapi")
    write_bytes(repository / "bad.py", b"\xff\xfe\x00")

    result = analyze(repository)

    assert any(
        issue.source_file == "bad.py" and issue.reason is AnalysisIssueReason.INVALID_ENCODING
        for issue in result.issues
    )
    assert result.summary.source_files_inspected == 0
    assert result.summary.is_complete is False


def test_oversized_source_file_is_reported(repository: Path) -> None:
    write_requirements(repository, "fastapi")
    write_text(repository / "large.py", "x = 1\n" * 100)

    result = analyze(repository, max_source_file_size_bytes=10)

    assert any(
        issue.source_file == "large.py" and issue.reason is AnalysisIssueReason.TOO_LARGE
        for issue in result.issues
    )
    assert result.summary.source_files_inspected == 0


def test_maximum_source_file_count(repository: Path) -> None:
    write_requirements(repository, "fastapi")
    for name in ("a.py", "b.py", "c.py"):
        write_text(
            repository / name,
            "from fastapi import FastAPI\napp = FastAPI()\n",
        )

    result = analyze(repository, max_source_files=1)

    assert result.summary.source_files_inspected == 1
    assert any(issue.reason is AnalysisIssueReason.MAX_SOURCE_FILES for issue in result.issues)
    assert result.summary.is_complete is False


def test_symlink_source_is_rejected(repository: Path, tmp_path: Path) -> None:
    outside = write_text(
        tmp_path / "outside.py",
        (
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/outside')\n"
            "def outside(): ...\n"
        ),
    )
    link = repository / "link.py"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks are not supported on this platform")

    result = identify_attack_surface(
        repository,
        manual_inventory(repository, ["link.py"]),
        manual_technologies(repository, ["FastAPI"]),
    )

    assert any(issue.reason is AnalysisIssueReason.SYMLINK for issue in result.issues)
    assert result.routes == []


def test_symlink_metadata_is_rejected(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_text(
        repository / "app.py",
        ("from fastapi import FastAPI\napp = FastAPI()\n@app.get('/x')\ndef x(): ...\n"),
    )
    inventory = manual_inventory(repository, ["app.py"])
    technologies = manual_technologies(repository, ["FastAPI"])
    real_lstat = Path.lstat

    def fake_lstat(path: Path) -> os.stat_result:
        if path.name == "app.py":
            return os.stat_result((stat.S_IFLNK | 0o777, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", fake_lstat)

    result = identify_attack_surface(repository, inventory, technologies)

    assert any(issue.reason is AnalysisIssueReason.SYMLINK for issue in result.issues)
    assert result.routes == []


def test_outside_root_path_is_rejected(repository: Path, tmp_path: Path) -> None:
    write_text(
        tmp_path / "outside.py",
        (
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/outside')\n"
            "def outside(): ...\n"
        ),
    )

    result = identify_attack_surface(
        repository,
        manual_inventory(repository, ["../outside.py"]),
        manual_technologies(repository, ["FastAPI"]),
    )

    assert any(
        issue.source_file == "../outside.py" and issue.reason is AnalysisIssueReason.OUTSIDE_ROOT
        for issue in result.issues
    )
    assert result.routes == []


def test_absolute_source_path_is_rejected(repository: Path, tmp_path: Path) -> None:
    outside = write_text(
        tmp_path / "outside.py",
        "from fastapi import FastAPI\napp = FastAPI()\n",
    )

    result = identify_attack_surface(
        repository,
        manual_inventory(repository, [str(outside)]),
        manual_technologies(repository, ["FastAPI"]),
    )

    assert any(issue.reason is AnalysisIssueReason.INVALID_PATH for issue in result.issues)
    assert result.routes == []


def test_env_and_credential_files_are_never_read(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_requirements(repository, "fastapi")
    write_text(repository / ".env", "SECRET=super-secret\n")
    write_text(
        repository / "credentials.py",
        ("from fastapi import FastAPI\napp = FastAPI()\n@app.get('/secret')\ndef secret(): ...\n"),
    )
    write_text(
        repository / "main.py",
        ("from fastapi import FastAPI\napp = FastAPI()\n@app.get('/public')\ndef public(): ...\n"),
    )

    real_open = Path.open

    def guarded_open(path: Path, *args: object, **kwargs: object) -> object:
        if path.name in {".env", "credentials.py"}:
            raise AssertionError("Attack surface analysis must not read sensitive files")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)

    result = analyze(repository)

    assert find_route(result, "/public") is not None
    assert find_route(result, "/secret") is None
    assert any(
        issue.source_file == "credentials.py" and issue.reason is AnalysisIssueReason.SENSITIVE_FILE
        for issue in result.issues
    )
    assert all(issue.source_file != ".env" for issue in result.issues)


def test_source_not_in_inventory_is_never_inspected(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_requirements(repository, "fastapi")
    write_text(
        repository / "listed.py",
        "from fastapi import FastAPI\napp = FastAPI()\n",
    )
    write_text(
        repository / "unlisted.py",
        (
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/unlisted')\n"
            "def unlisted(): ...\n"
        ),
    )

    inventory = manual_inventory(repository, ["listed.py"])
    technologies = manual_technologies(repository, ["FastAPI"])
    real_open = Path.open

    def guarded_open(path: Path, *args: object, **kwargs: object) -> object:
        if path.name == "unlisted.py":
            raise AssertionError("Unlisted source files must not be read")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)

    result = identify_attack_surface(repository, inventory, technologies)

    assert result.routes == []
    assert result.summary.source_files_inspected == 1


def test_dependency_directory_path_is_not_inspected(repository: Path) -> None:
    write_text(
        repository / "node_modules" / "pkg" / "index.js",
        (
            "const express = require('express');\n"
            "const app = express();\n"
            "app.get('/dep', handler);\n"
        ),
    )

    result = identify_attack_surface(
        repository,
        manual_inventory(repository, ["node_modules/pkg/index.js"]),
        manual_technologies(repository, ["Express"]),
    )

    assert result.routes == []
    assert any(issue.reason is AnalysisIssueReason.EXCLUDED_PATH for issue in result.issues)


def test_empty_repository(repository: Path) -> None:
    result = analyze(repository)

    assert result.routes == []
    assert result.issues == []
    assert result.summary.source_files_inspected == 0
    assert result.summary.route_count == 0
    assert result.summary.is_complete is True


def test_deterministic_output_and_inventory_order(repository: Path) -> None:
    write_requirements(repository, "fastapi", "flask")
    write_package_json(repository, {"express": "^4.18.0"})
    write_text(
        repository / "main.py",
        ("from fastapi import FastAPI\napp = FastAPI()\n@app.get('/health')\ndef health(): ...\n"),
    )
    write_text(
        repository / "server.js",
        (
            "const express = require('express');\n"
            "const app = express();\n"
            "app.get('/health', handler);\n"
        ),
    )

    inventory = discover_repository(repository)
    technologies = detect_technologies(repository, inventory)

    first = identify_attack_surface(repository, inventory, technologies)
    second = identify_attack_surface(repository, inventory, technologies)
    assert first.model_dump() == second.model_dump()

    shuffled = inventory.model_copy(deep=True)
    shuffled.files.reverse()
    third = identify_attack_surface(repository, shuffled, technologies)
    assert third.model_dump() == first.model_dump()


def test_incomplete_discovery_is_propagated(repository: Path) -> None:
    write_requirements(repository, "fastapi")
    write_text(
        repository / "main.py",
        ("from fastapi import FastAPI\napp = FastAPI()\n@app.get('/x')\ndef x(): ...\n"),
    )

    inventory = manual_inventory(
        repository,
        ["main.py"],
        is_complete=False,
        truncation_reasons=[DiscoveryTruncationReason.MAX_FILE_COUNT],
    )

    result = identify_attack_surface(
        repository,
        inventory,
        manual_technologies(repository, ["FastAPI"]),
    )

    assert result.summary.discovery_is_complete is False
    assert result.summary.discovery_truncation_reasons == [DiscoveryTruncationReason.MAX_FILE_COUNT]
    assert result.summary.is_complete is False
    assert find_route(result, "/x") is not None


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

    result = identify_attack_surface(
        repository,
        inventory,
        manual_technologies(repository, []),
    )

    assert any(
        issue.source_file == "skipped.py" and issue.reason is AnalysisIssueReason.SYMLINK
        for issue in result.issues
    )
    assert result.summary.is_complete is False


def test_technology_root_mismatch_is_rejected(
    repository: Path,
    tmp_path: Path,
) -> None:
    inventory = manual_inventory(repository, [])
    technologies = manual_technologies(repository, [])
    technologies.root = str((tmp_path / "other").resolve())

    with pytest.raises(InvalidAttackSurfaceRootError):
        identify_attack_surface(repository, inventory, technologies)


def test_inventory_root_mismatch_is_rejected(
    repository: Path,
    tmp_path: Path,
) -> None:
    inventory = manual_inventory(repository, [])
    inventory.root = str((tmp_path / "other").resolve())

    with pytest.raises(InvalidAttackSurfaceRootError):
        identify_attack_surface(
            repository,
            inventory,
            manual_technologies(repository, []),
        )


def test_root_outside_allowed_roots_is_rejected(
    allowed_root: Path,
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()

    with pytest.raises(InvalidAttackSurfaceRootError):
        identify_attack_surface(
            outside,
            manual_inventory(outside, []),
            manual_technologies(outside, []),
        )


def test_negative_limits_are_rejected(repository: Path) -> None:
    with pytest.raises(AttackSurfaceError):
        identify_attack_surface(
            repository,
            manual_inventory(repository, []),
            manual_technologies(repository, []),
            max_source_files=-1,
        )


def test_unresolved_routes_do_not_mark_analysis_incomplete(repository: Path) -> None:
    write_requirements(repository, "fastapi")
    write_text(
        repository / "main.py",
        (
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get(dynamic_path)\n"
            "def dynamic(): ...\n"
        ),
    )

    result = analyze(repository)

    assert result.summary.unresolved_route_count == 1
    assert result.summary.is_complete is True


def test_permission_denied_source_is_reported(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_text(
        repository / "app.py",
        "from fastapi import FastAPI\napp = FastAPI()\n",
    )
    inventory = manual_inventory(repository, ["app.py"])
    technologies = manual_technologies(repository, ["FastAPI"])
    real_open = Path.open

    def guarded_open(path: Path, *args: object, **kwargs: object) -> object:
        if path.name == "app.py":
            raise PermissionError("denied")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)

    result = identify_attack_surface(repository, inventory, technologies)

    assert any(
        issue.source_file == "app.py" and issue.reason is AnalysisIssueReason.PERMISSION_DENIED
        for issue in result.issues
    )
    assert result.summary.source_files_inspected == 0


def test_disappeared_source_is_reported(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_text(
        repository / "app.py",
        "from fastapi import FastAPI\napp = FastAPI()\n",
    )
    inventory = manual_inventory(repository, ["app.py"])
    technologies = manual_technologies(repository, ["FastAPI"])
    real_lstat = Path.lstat

    def fake_lstat(path: Path) -> os.stat_result:
        if path.name == "app.py":
            raise FileNotFoundError("gone")
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", fake_lstat)

    result = identify_attack_surface(repository, inventory, technologies)

    assert any(
        issue.source_file == "app.py" and issue.reason is AnalysisIssueReason.DISAPPEARED
        for issue in result.issues
    )
    assert result.summary.source_files_inspected == 0


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

    result = identify_attack_surface(repository, inventory, technologies)

    assert any(
        issue.source_file == "app.py" and issue.reason is AnalysisIssueReason.SYMLINK
        for issue in result.issues
    )
    assert result.routes == []
