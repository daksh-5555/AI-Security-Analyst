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
from app.schemas.repository_discovery import (
    DiscoveryLimits,
    DiscoverySummary,
    FileInventoryEntry,
    RepositoryDiscoveryResult,
    SkippedItem,
)
from app.schemas.sensitive_operations import (
    OperationCategory,
    OperationResolutionStatus,
    SensitiveOperationResult,
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
from app.services.repository_discovery import discover_repository
from app.services.sensitive_operations import (
    InvalidSensitiveOperationRootError,
    SensitiveOperationAnalysisError,
    identify_sensitive_operations,
)
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
) -> SensitiveOperationResult:
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
    return identify_sensitive_operations(
        repository,
        resolved_inventory,
        resolved_technologies,
        resolved_surface,
        **kwargs,
    )


def find_operation(
    result: SensitiveOperationResult,
    category: OperationCategory,
    operation_name: str | None = None,
    receiver_name: str | None = None,
    enclosing_function: str | None = None,
) -> list:
    matches = []
    for operation in result.operations:
        if operation.operation_category is not category:
            continue
        if operation_name is not None and operation.operation_name != operation_name:
            continue
        if receiver_name is not None and operation.receiver_name != receiver_name:
            continue
        if enclosing_function is not None and operation.enclosing_function != enclosing_function:
            continue
        matches.append(operation)
    return matches


def line_of(text: str, needle: str) -> int:
    for index, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return index
    raise AssertionError(f"Line containing {needle!r} was not found")


def test_sqlalchemy_session_and_engine_operations(repository: Path) -> None:
    write_requirements(repository, "sqlalchemy")
    text = source(
        """
        from sqlalchemy import create_engine
        from sqlalchemy.orm import Session

        def read_data():
            engine = create_engine("sqlite://")
            session = Session()
            session.add(object())
            session.delete(object())
            session.execute("SELECT 1")
            session.scalars("SELECT 1")
            session.scalar("SELECT 1")
            session.query(User)
            session.commit()
            session.flush()
            engine.execute("SELECT 1")
            engine.exec_driver_sql("SELECT 1")
        """
    )
    write_text(repository / "app.py", text)

    result = analyze(repository)

    expected = {
        (OperationCategory.DATABASE_WRITE, "add", "session"),
        (OperationCategory.DATABASE_DELETE, "delete", "session"),
        (OperationCategory.DATABASE_EXECUTE, "execute", "session"),
        (OperationCategory.DATABASE_READ, "scalars", "session"),
        (OperationCategory.DATABASE_READ, "scalar", "session"),
        (OperationCategory.DATABASE_READ, "query", "session"),
        (OperationCategory.DATABASE_TRANSACTION, "commit", "session"),
        (OperationCategory.DATABASE_TRANSACTION, "flush", "session"),
        (OperationCategory.DATABASE_EXECUTE, "execute", "engine"),
        (OperationCategory.DATABASE_EXECUTE, "exec_driver_sql", "engine"),
    }
    for category, operation_name, receiver_name in expected:
        matches = find_operation(result, category, operation_name, receiver_name)
        assert matches, (category, operation_name, receiver_name)
        assert matches[0].framework_or_library == "SQLAlchemy"
        assert matches[0].enclosing_function == "read_data"

    query = find_operation(result, OperationCategory.DATABASE_READ, "query")[0]
    assert query.resource_name == "User"
    assert result.summary.operation_count == 10
    assert result.summary.database_operation_count == 10
    assert result.summary.unresolved_association_count == 10


def test_database_like_methods_need_library_or_receiver_evidence(
    repository: Path,
) -> None:
    write_requirements(repository, "sqlalchemy")
    text = source(
        """
        from sqlalchemy import create_engine

        def run():
            record.delete()
            worker.execute()
            builder.query()
            data.filter()
        """
    )
    write_text(repository / "app.py", text)

    result = analyze(repository)

    assert result.operations == []
    assert result.issues == []


def test_django_orm_operations_and_class_view_association(repository: Path) -> None:
    write_requirements(repository, "django")
    write_text(
        repository / "views.py",
        source(
            """
            class ItemView:
                def get(self, request):
                    Item.objects.get(pk=1)
                    Item.objects.filter(name="x")
                    Item.objects.exclude(name="x")
                    Item.objects.create(name="x")
                    Item.objects.update(name="x")
                    Item.objects.filter(name="x").delete()
                    Item.objects.bulk_create([])
                    Item.objects.raw("SELECT * FROM item")

            def create_item(request):
                return Item.objects.create(name="x")
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
                path("items/", views.ItemView.as_view()),
                path("create/", views.create_item),
            ]
            """
        ),
    )

    result = analyze(repository)

    expected = {
        ("get", OperationCategory.DATABASE_READ),
        ("filter", OperationCategory.DATABASE_READ),
        ("exclude", OperationCategory.DATABASE_READ),
        ("create", OperationCategory.DATABASE_WRITE),
        ("update", OperationCategory.DATABASE_WRITE),
        ("delete", OperationCategory.DATABASE_DELETE),
        ("bulk_create", OperationCategory.DATABASE_WRITE),
        ("raw", OperationCategory.DATABASE_EXECUTE),
    }
    for operation_name, category in expected:
        matches = find_operation(result, category, operation_name, enclosing_function="get")
        assert matches, (operation_name, category)
        assert matches[0].resource_name == "Item"
        assert matches[0].enclosing_class == "ItemView"
        assert [route.path for route in matches[0].associated_routes] == ["items/"]

    create = find_operation(
        result,
        OperationCategory.DATABASE_WRITE,
        "create",
        enclosing_function="create_item",
    )[0]
    assert create.resource_name == "Item"
    assert [route.path for route in create.associated_routes] == ["create/"]
    assert result.summary.database_operation_count == 10


def test_sqlite_and_raw_cursor_operations(repository: Path) -> None:
    text = source(
        """
        import sqlite3

        def run():
            conn = sqlite3.connect("app.db")
            cursor = conn.cursor()
            cursor.execute("INSERT INTO t VALUES (1)")
            conn.commit()
            cursor.executemany("INSERT INTO t VALUES (?)", [])
            cursor.executescript("CREATE TABLE t (id INT)")
            sqlite3.connect("app.db").execute("DELETE FROM t")
        """
    )
    write_text(repository / "app.py", text)

    result = analyze(repository)

    assert len(find_operation(result, OperationCategory.DATABASE_EXECUTE, "execute")) == 2
    assert len(find_operation(result, OperationCategory.DATABASE_EXECUTE, "executemany")) == 1
    assert len(find_operation(result, OperationCategory.DATABASE_EXECUTE, "executescript")) == 1
    assert len(find_operation(result, OperationCategory.DATABASE_TRANSACTION, "commit")) == 1
    assert all(operation.framework_or_library == "SQLite" for operation in result.operations)
    assert result.summary.operation_count == 5
    assert result.summary.database_operation_count == 5


def test_prisma_operations_and_resources(repository: Path) -> None:
    write_package_json(repository, {"@prisma/client": "^5.0.0", "express": "^4.18.0"})
    text = source(
        """
        const { PrismaClient } = require('@prisma/client');
        const express = require('express');
        const prisma = new PrismaClient();
        const app = express();

        async function listUsers() {
          await prisma.user.findMany({});
          await prisma.user.findUnique({ where: { id: 1 } });
          await prisma.user.create({ data: {} });
          await prisma.user.update({ where: {}, data: {} });
          await prisma.user.delete({ where: {} });
          await prisma.$queryRawUnsafe('SELECT 1');
          await prisma.$executeRawUnsafe('DELETE FROM x');
          await prisma.$transaction([]);
        }

        app.get('/users', listUsers);
        """
    )
    write_text(repository / "server.js", text)

    result = analyze(repository)

    expected = {
        (OperationCategory.DATABASE_READ, "findMany"),
        (OperationCategory.DATABASE_READ, "findUnique"),
        (OperationCategory.DATABASE_WRITE, "create"),
        (OperationCategory.DATABASE_WRITE, "update"),
        (OperationCategory.DATABASE_DELETE, "delete"),
        (OperationCategory.DATABASE_EXECUTE, "$queryRawUnsafe"),
        (OperationCategory.DATABASE_EXECUTE, "$executeRawUnsafe"),
        (OperationCategory.DATABASE_TRANSACTION, "$transaction"),
    }
    for category, operation_name in expected:
        matches = find_operation(result, category, operation_name, enclosing_function="listUsers")
        assert matches, (category, operation_name)
        assert matches[0].framework_or_library == "Prisma"
        assert [route.path for route in matches[0].associated_routes] == ["/users"]

    for operation_name in ("findMany", "findUnique", "create", "update", "delete"):
        operation = find_operation(result, OperationCategory.DATABASE_READ, operation_name)
        if not operation:
            operation = find_operation(result, OperationCategory.DATABASE_WRITE, operation_name)
        if not operation:
            operation = find_operation(result, OperationCategory.DATABASE_DELETE, operation_name)
        assert operation[0].resource_name == "user"
    assert result.summary.operation_count == 8
    assert result.summary.route_association_count == 8
    assert result.summary.unresolved_association_count == 0


def test_sequelize_operations(repository: Path) -> None:
    write_package_json(repository, {"sequelize": "^6.0.0"})
    text = source(
        """
        const { Sequelize, Model } = require('sequelize');
        const sequelize = new Sequelize('sqlite::memory:');

        class User extends Model {}

        async function run() {
          await User.findOne({});
          await User.findAll({});
          await User.create({});
          await User.update({});
          await User.destroy({});
          await sequelize.query('SELECT 1');
          await sequelize.transaction(async (transaction) => {});
        }
        """
    )
    write_text(repository / "server.js", text)

    result = analyze(repository)

    for operation_name in ("findOne", "findAll"):
        operation = find_operation(result, OperationCategory.DATABASE_READ, operation_name)[0]
        assert operation.resource_name == "User"
        assert operation.framework_or_library == "Sequelize"
    for operation_name in ("create", "update"):
        assert find_operation(result, OperationCategory.DATABASE_WRITE, operation_name)
    assert find_operation(result, OperationCategory.DATABASE_DELETE, "destroy")
    assert find_operation(result, OperationCategory.DATABASE_EXECUTE, "query")
    assert find_operation(result, OperationCategory.DATABASE_TRANSACTION, "transaction")
    assert result.summary.operation_count == 7


def test_typeorm_operations(repository: Path) -> None:
    write_package_json(repository, {"typeorm": "^0.3.0"})
    text = source(
        """
        const { DataSource } = require('typeorm');
        const dataSource = new DataSource({ type: 'sqlite' });
        const userRepository = dataSource.getRepository(User);

        async function run() {
          await userRepository.find();
          await userRepository.findOne(1);
          await userRepository.save({});
          await userRepository.insert({});
          await userRepository.update(1, {});
          await userRepository.delete(1);
          await userRepository.remove({});
          await userRepository.query('SELECT 1');
          await dataSource.transaction(async (manager) => {});
        }
        """
    )
    write_text(repository / "server.js", text)

    result = analyze(repository)

    for operation_name in ("find", "findOne"):
        operation = find_operation(result, OperationCategory.DATABASE_READ, operation_name)[0]
        assert operation.resource_name == "User"
        assert operation.framework_or_library == "TypeORM"
    for operation_name in ("save", "insert", "update"):
        assert find_operation(result, OperationCategory.DATABASE_WRITE, operation_name)
    for operation_name in ("delete", "remove"):
        assert find_operation(result, OperationCategory.DATABASE_DELETE, operation_name)
    assert find_operation(result, OperationCategory.DATABASE_EXECUTE, "query")
    assert find_operation(result, OperationCategory.DATABASE_TRANSACTION, "transaction")
    assert result.summary.operation_count == 9


def test_knex_operations_and_table_resource(repository: Path) -> None:
    write_package_json(repository, {"knex": "^3.0.0"})
    text = source(
        """
        const knex = require('knex')({ client: 'sqlite3' });

        async function run() {
          await knex('users').select('*');
          await knex('users').insert({ name: 'x' });
          await knex('users').update({ name: 'x' });
          await knex('users').delete();
          await knex.raw('SELECT 1');
          await knex.transaction(async (trx) => {});
        }
        """
    )
    write_text(repository / "server.js", text)

    result = analyze(repository)

    for operation_name in ("select",):
        operation = find_operation(result, OperationCategory.DATABASE_READ, operation_name)[0]
        assert operation.resource_name == "users"
        assert operation.framework_or_library == "Knex"
    for operation_name in ("insert", "update"):
        assert find_operation(result, OperationCategory.DATABASE_WRITE, operation_name)
    assert find_operation(result, OperationCategory.DATABASE_DELETE, "delete")
    assert find_operation(result, OperationCategory.DATABASE_EXECUTE, "raw")
    assert find_operation(result, OperationCategory.DATABASE_TRANSACTION, "transaction")
    assert result.summary.operation_count == 6


def test_mongoose_and_direct_database_clients(repository: Path) -> None:
    write_package_json(
        repository,
        {
            "mongoose": "^8.0.0",
            "pg": "^8.0.0",
            "sqlite3": "^5.0.0",
            "mysql2": "^3.0.0",
        },
    )
    text = source(
        """
        const mongoose = require('mongoose');
        const { Pool } = require('pg');
        const sqlite3 = require('sqlite3');
        const mysql = require('mysql2');

        const User = mongoose.model('User', schema);
        const pool = new Pool();
        const db = new sqlite3.Database('app.db');
        const connection = mysql.createConnection({});

        async function run() {
          await User.find({});
          await User.findOne({});
          await User.create({});
          await User.deleteOne({});
          await pool.query('SELECT 1');
          await connection.execute('SELECT 1');
          db.all('SELECT 1');
          db.run('DELETE FROM x');
          db.get('SELECT 1');
        }
        """
    )
    write_text(repository / "server.js", text)

    result = analyze(repository)

    assert result.summary.database_operation_count == 9
    assert result.summary.operation_count == 9

    for operation_name in ("find", "findOne"):
        operation = find_operation(result, OperationCategory.DATABASE_READ, operation_name)[0]
        assert operation.framework_or_library == "Mongoose"
        assert operation.resource_name == "User"
    assert find_operation(result, OperationCategory.DATABASE_WRITE, "create")
    assert find_operation(result, OperationCategory.DATABASE_DELETE, "deleteOne")

    pool = find_operation(result, OperationCategory.DATABASE_EXECUTE, "query", "pool")[0]
    assert pool.framework_or_library == "PostgreSQL"

    connection = find_operation(
        result, OperationCategory.DATABASE_EXECUTE, "execute", "connection"
    )[0]
    assert connection.framework_or_library == "MySQL"

    db = find_operation(result, OperationCategory.DATABASE_READ, "all", "db")[0]
    assert db.framework_or_library == "SQLite"
    assert find_operation(result, OperationCategory.DATABASE_EXECUTE, "run", "db")
    assert find_operation(result, OperationCategory.DATABASE_READ, "get", "db")


def test_python_database_drivers_preserve_library_evidence(repository: Path) -> None:
    text = source(
        """
        import psycopg2
        import pymysql
        from mysql.connector import connect

        def run():
            connection = psycopg2.connect("postgresql://localhost/db")
            cursor = connection.cursor()
            cursor.execute("SELECT 1")
            connection.commit()
            raw = pymysql.connect(host="localhost")
            raw.cursor().execute("DELETE FROM t")
            mysql_conn = connect(user="x")
            mysql_conn.cursor().executemany("INSERT INTO t VALUES (1)", [])
        """
    )
    write_text(repository / "app.py", text)

    result = analyze(repository)

    execute = find_operation(result, OperationCategory.DATABASE_EXECUTE, "execute")
    assert len(execute) == 2
    assert {operation.framework_or_library for operation in execute} == {
        "PostgreSQL",
        "MySQL",
    }
    executemany = find_operation(result, OperationCategory.DATABASE_EXECUTE, "executemany")[0]
    assert executemany.framework_or_library == "MySQL"
    assert find_operation(result, OperationCategory.DATABASE_TRANSACTION, "commit")
    assert result.summary.database_operation_count == 4


# === PART 2: FILESYSTEM, PROCESS, SENSITIVE, SECURITY TESTS ===


def test_python_filesystem_operations(repository: Path) -> None:
    text = source(
        """
        import os
        import shutil
        from pathlib import Path

        def run():
            open("a.txt", "w")
            path = Path("a.txt")
            path.read_text()
            path.write_text("x")
            path.unlink()
            Path("b").mkdir()
            os.remove("b")
            os.rename("a", "b")
            os.makedirs("c")
            os.walk(".")
            shutil.copy("a", "b")
            shutil.rmtree("c")
            shutil.unpack_archive("a.zip")
        """
    )
    write_text(repository / "app.py", text)

    result = analyze(repository)

    expected = {
        (OperationCategory.FILE_WRITE, "open"),
        (OperationCategory.FILE_READ, "read_text"),
        (OperationCategory.FILE_WRITE, "write_text"),
        (OperationCategory.FILE_DELETE, "unlink"),
        (OperationCategory.FILE_WRITE, "mkdir"),
        (OperationCategory.FILE_DELETE, "remove"),
        (OperationCategory.FILE_WRITE, "rename"),
        (OperationCategory.FILE_WRITE, "makedirs"),
        (OperationCategory.FILE_READ, "walk"),
        (OperationCategory.FILE_WRITE, "copy"),
        (OperationCategory.FILE_DELETE, "rmtree"),
        (OperationCategory.ARCHIVE_EXTRACTION, "unpack_archive"),
    }
    for category, operation_name in expected:
        assert find_operation(result, category, operation_name), (
            category,
            operation_name,
        )
    assert result.summary.operation_count == 12
    assert result.summary.filesystem_operation_count == 11
    assert result.summary.other_sensitive_operation_count == 1


def test_node_filesystem_and_path_operations(repository: Path) -> None:
    text = source(
        """
        const fs = require('fs');
        const fsp = require('fs/promises');
        const path = require('path');

        function run() {
          fs.readFile('a');
          fs.writeFile('a', 'x');
          fs.appendFile('a', 'x');
          fs.unlink('a');
          fs.rename('a', 'b');
          fs.mkdir('d');
          fs.rmdir('d');
          fs.rm('d');
          fs.readdir('.');
          fs.stat('a');
          fs.createReadStream('a');
          fs.createWriteStream('a');
          fsp.readFile('a');
          path.join('a', 'b');
        }
        """
    )
    write_text(repository / "server.js", text)

    result = analyze(repository)

    expected = {
        (OperationCategory.FILE_READ, "readFile"),
        (OperationCategory.FILE_WRITE, "writeFile"),
        (OperationCategory.FILE_WRITE, "appendFile"),
        (OperationCategory.FILE_DELETE, "unlink"),
        (OperationCategory.FILE_WRITE, "rename"),
        (OperationCategory.FILE_WRITE, "mkdir"),
        (OperationCategory.FILE_DELETE, "rmdir"),
        (OperationCategory.FILE_DELETE, "rm"),
        (OperationCategory.FILE_READ, "readdir"),
        (OperationCategory.FILE_METADATA, "stat"),
        (OperationCategory.FILE_READ, "createReadStream"),
        (OperationCategory.FILE_WRITE, "createWriteStream"),
        (OperationCategory.FILE_METADATA, "join"),
    }
    for category, operation_name in expected:
        assert find_operation(result, category, operation_name), (
            category,
            operation_name,
        )
    assert len(find_operation(result, OperationCategory.FILE_READ, "readFile")) == 2
    assert result.summary.operation_count == 14


def test_python_and_node_process_execution(repository: Path) -> None:
    write_requirements(repository, "none")
    write_text(
        repository / "app.py",
        source(
            """
            import asyncio
            import subprocess
            from os import system

            def run():
                subprocess.run(["rm", "-rf", "/tmp/x"])
                subprocess.Popen(["echo", "secret"])
                system("rm -rf /tmp/x")
                asyncio.create_subprocess_shell("echo secret")
            """
        ),
    )
    write_text(
        repository / "server.js",
        source(
            """
            const { exec, spawn } = require('child_process');
            const cp = require('child_process');

            function run() {
              exec('rm -rf /tmp/x');
              spawn('cat', ['secret']);
              cp.fork('worker.js');
            }
            """
        ),
    )

    result = analyze(repository)

    assert result.summary.process_execution_count == 7
    assert len(find_operation(result, OperationCategory.PROCESS_EXECUTION)) == 7
    dumped = json.dumps(result.model_dump(mode="json"), sort_keys=True)
    assert "rm -rf" not in dumped
    assert "secret" not in dumped
    assert "worker.js" not in dumped


def test_deserialization_archive_and_dynamic_code(repository: Path) -> None:
    write_text(
        repository / "app.py",
        source(
            """
            import pickle
            import tarfile
            import yaml
            import zipfile

            def run(data):
                pickle.load(data)
                pickle.loads(data)
                yaml.load(data)
                yaml.safe_load(data)
                zipfile.ZipFile("a.zip").extractall()
                tarfile.open("a.tar").extractall()
                eval("1+1")
                exec("x=1")
            """
        ),
    )
    write_text(
        repository / "server.js",
        source(
            """
            function run(code) {
              eval(code);
              new Function('return 1')();
            }
            """
        ),
    )

    result = analyze(repository)

    assert len(find_operation(result, OperationCategory.DESERIALIZATION)) == 3
    assert len(find_operation(result, OperationCategory.ARCHIVE_EXTRACTION)) == 2
    assert len(find_operation(result, OperationCategory.DYNAMIC_CODE_EXECUTION)) == 4
    assert result.summary.other_sensitive_operation_count == 9
    dumped = json.dumps(result.model_dump(mode="json"), sort_keys=True)
    assert "1+1" not in dumped
    assert "return 1" not in dumped
    assert "a.zip" not in dumped


def test_file_upload_and_redirect_operations(repository: Path) -> None:
    write_requirements(repository, "flask")
    text = source(
        """
        from flask import Flask, redirect, request

        app = Flask(__name__)

        @app.post("/upload")
        def upload():
            uploaded = request.files.get("avatar")
            uploaded.save("/tmp/x")
            return redirect("/next")
        """
    )
    write_text(repository / "app.py", text)

    result = analyze(repository)

    upload = find_operation(result, OperationCategory.FILE_UPLOAD, "save")[0]
    assert upload.enclosing_function == "upload"
    assert [route.path for route in upload.associated_routes] == ["/upload"]

    redirect = find_operation(result, OperationCategory.REDIRECT, "redirect")[0]
    assert redirect.enclosing_function == "upload"
    assert [route.path for route in redirect.associated_routes] == ["/upload"]
    assert result.summary.filesystem_operation_count == 1
    assert result.summary.other_sensitive_operation_count == 1


def test_django_upload_storage_and_redirect(repository: Path) -> None:
    write_requirements(repository, "django")
    write_text(
        repository / "views.py",
        source(
            """
            from django.core.files.storage import FileSystemStorage
            from django.http import HttpResponseRedirect

            def store():
                storage = FileSystemStorage()
                storage.save("name", b"x")
                return HttpResponseRedirect("/next")
            """
        ),
    )

    result = analyze(repository)

    assert find_operation(result, OperationCategory.FILE_UPLOAD, "save")
    assert find_operation(result, OperationCategory.REDIRECT, "HttpResponseRedirect")
    assert result.summary.unresolved_association_count == 2


def test_express_file_upload_and_redirect(repository: Path) -> None:
    write_package_json(repository, {"express": "^4.18.0"})
    text = source(
        """
        const express = require('express');
        const app = express();

        app.post('/upload', (req, res) => {
          const uploaded = req.file;
          uploaded.mv('/tmp/x');
          res.redirect('/next');
        });
        """
    )
    write_text(repository / "server.js", text)

    result = analyze(repository)

    upload = find_operation(result, OperationCategory.FILE_UPLOAD, "mv")[0]
    redirect = find_operation(result, OperationCategory.REDIRECT, "redirect")[0]
    assert [route.path for route in upload.associated_routes] == ["/upload"]
    assert [route.path for route in redirect.associated_routes] == ["/upload"]
    assert result.summary.operation_count == 2


def test_nestjs_redirect_decorator(repository: Path) -> None:
    write_package_json(repository, {"@nestjs/common": "^10.0.0"})
    text = source(
        """
        import { Controller, Get, Redirect } from '@nestjs/common';

        @Controller('items')
        export class ItemsController {
          @Get()
          @Redirect('/next')
          find() {
            return null;
          }
        }
        """
    )
    write_text(repository / "items.controller.ts", text)

    result = analyze(repository)

    redirect = find_operation(result, OperationCategory.REDIRECT, "Redirect")
    assert redirect
    assert redirect[0].enclosing_function == "find"
    assert [route.path for route in redirect[0].associated_routes] == ["/items"]


def test_comments_and_string_literals_are_not_operations(repository: Path) -> None:
    write_requirements(repository, "sqlalchemy")
    write_text(
        repository / "app.py",
        source(
            """
            from sqlalchemy.orm import Session

            def run():
                # session.execute("SELECT 1")
                note = "session.execute('SELECT 1')"
                other = 'subprocess.run(["rm"])'
                return note, other
            """
        ),
    )
    write_text(
        repository / "server.js",
        source(
            """
            const fs = require('fs');

            // fs.readFile('a');
            const note = "fs.readFile('a')";
            const other = 'child_process.exec("rm")';
            function run() {
              return note, other;
            }
            """
        ),
    )

    result = analyze(repository)

    assert result.operations == []


def test_enclosing_function_class_and_line_numbers(repository: Path) -> None:
    write_requirements(repository, "sqlalchemy")
    text = source(
        """
        from sqlalchemy.orm import Session

        class Store:
            def save(self):
                session = Session()
                session.execute("SELECT 1")

        def handler():
            session = Session()
            session.commit()
        """
    )
    write_text(repository / "app.py", text)

    result = analyze(repository)

    execute = find_operation(result, OperationCategory.DATABASE_EXECUTE, "execute")[0]
    assert execute.enclosing_function == "save"
    assert execute.enclosing_class == "Store"
    assert execute.line_number == line_of(text, "session.execute")

    commit = find_operation(result, OperationCategory.DATABASE_TRANSACTION, "commit")[0]
    assert commit.enclosing_function == "handler"
    assert commit.enclosing_class is None
    assert commit.line_number == line_of(text, "session.commit")


def test_route_association_and_unresolved_helper(repository: Path) -> None:
    write_requirements(repository, "flask")
    text = source(
        """
        import subprocess

        from flask import Flask

        app = Flask(__name__)

        @app.get("/run")
        def run():
            subprocess.run(["safe"])
            return "ok"

        def helper():
            subprocess.run(["helper"])
        """
    )
    write_text(repository / "app.py", text)

    result = analyze(repository)

    run = find_operation(result, OperationCategory.PROCESS_EXECUTION, enclosing_function="run")[0]
    helper = find_operation(
        result, OperationCategory.PROCESS_EXECUTION, enclosing_function="helper"
    )[0]
    assert [route.path for route in run.associated_routes] == ["/run"]
    assert helper.associated_routes == []
    assert helper.resolution_status is OperationResolutionStatus.UNRESOLVED
    assert result.summary.route_association_count == 1
    assert result.summary.unresolved_association_count == 1


def test_multiple_route_decorators_are_preserved(repository: Path) -> None:
    write_requirements(repository, "fastapi")
    text = source(
        """
        import subprocess

        from fastapi import FastAPI

        app = FastAPI()

        @app.get("/first")
        @app.post("/second")
        def both():
            subprocess.run(["safe"])
        """
    )
    write_text(repository / "main.py", text)

    result = analyze(repository)

    operation = find_operation(result, OperationCategory.PROCESS_EXECUTION)[0]
    assert [route.path for route in operation.associated_routes] == [
        "/first",
        "/second",
    ]
    assert result.summary.route_association_count == 2
    assert result.summary.unresolved_association_count == 0


def test_dynamic_and_unsupported_expressions(repository: Path) -> None:
    write_text(
        repository / "app.py",
        source(
            """
            import os

            def run():
                getattr(os, "remove")("a")
                name = "remove"
                getattr(os, name)("a")
            """
        ),
    )
    write_text(
        repository / "server.js",
        source(
            """
            const fs = require('fs');

            function run(method) {
              fs[method]('a');
            }
            """
        ),
    )

    result = analyze(repository)

    assert find_operation(result, OperationCategory.FILE_DELETE, "remove")
    assert any(issue.reason is AnalysisIssueReason.UNSUPPORTED_SYNTAX for issue in result.issues)
    assert not find_operation(result, OperationCategory.FILE_READ, "method")


def test_dynamic_file_mode_is_an_issue_not_a_guess(repository: Path) -> None:
    write_text(
        repository / "app.py",
        source(
            """
            def run(mode):
                open("a.txt", mode)
                open("b.txt", "w")
            """
        ),
    )

    result = analyze(repository)

    dynamic = find_operation(result, OperationCategory.OTHER, "open")
    assert len(dynamic) == 1
    assert dynamic[0].resolution_status is OperationResolutionStatus.UNRESOLVED
    assert not find_operation(result, OperationCategory.FILE_READ, "open")
    assert find_operation(result, OperationCategory.FILE_WRITE, "open")
    assert any(
        issue.reason is AnalysisIssueReason.UNSUPPORTED_SYNTAX
        and "Dynamic file mode" in (issue.detail or "")
        for issue in result.issues
    )


def test_duplicate_handling_and_deterministic_ordering(repository: Path) -> None:
    write_requirements(repository, "sqlalchemy")
    text = source(
        """
        from sqlalchemy.orm import Session

        def run():
            session = Session()
            session.execute("a"); session.execute("b")
            session.commit()
        """
    )
    write_text(repository / "app.py", text)
    write_text(
        repository / "other.py",
        source(
            """
            from sqlalchemy.orm import Session

            session = Session()
            session.flush()
            """
        ),
    )

    inventory = discover_repository(repository)
    technologies = detect_technologies(repository, inventory)
    surface = identify_attack_surface(repository, inventory, technologies)
    first = identify_sensitive_operations(repository, inventory, technologies, surface)
    second = identify_sensitive_operations(repository, inventory, technologies, surface)
    assert first.model_dump() == second.model_dump()
    assert len(find_operation(first, OperationCategory.DATABASE_EXECUTE, "execute")) == 1
    assert first.summary.operation_count == 3
    assert [operation.source_file for operation in first.operations] == [
        "app.py",
        "app.py",
        "other.py",
    ]

    shuffled = inventory.model_copy(deep=True)
    shuffled.files.reverse()
    third = identify_sensitive_operations(repository, shuffled, technologies, surface)
    assert third.model_dump() == first.model_dump()


def test_invalid_syntax_and_encoding_are_reported(repository: Path) -> None:
    write_text(repository / "broken.py", "def broken(:\n    pass\n")
    write_text(
        repository / "broken.js",
        "const fs = require('fs');\nconst x = 'unterminated\n",
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
    write_text(repository / "large.py", "x = 1\n" * 100)
    oversized = analyze(repository, max_source_file_size_bytes=10)
    assert any(
        issue.source_file == "large.py" and issue.reason is AnalysisIssueReason.TOO_LARGE
        for issue in oversized.issues
    )
    assert oversized.summary.source_files_inspected == 0

    write_text(repository / "a.py", "x = 1\n")
    write_text(repository / "b.py", "y = 2\n")
    limited = analyze(repository, max_source_files=1)
    assert limited.summary.source_files_inspected == 1
    assert any(issue.reason is AnalysisIssueReason.MAX_SOURCE_FILES for issue in limited.issues)
    assert limited.summary.is_complete is False


def test_traversal_and_absolute_paths_are_rejected(
    repository: Path,
    tmp_path: Path,
) -> None:
    outside = write_text(tmp_path / "outside.py", "import os\nos.remove('a')\n")
    inventory = manual_inventory(repository, ["../outside.py", str(outside)])
    technologies = manual_technologies(repository, [])
    surface = identify_attack_surface(repository, inventory, technologies)

    result = identify_sensitive_operations(repository, inventory, technologies, surface)

    reasons = {issue.reason for issue in result.issues}
    assert AnalysisIssueReason.OUTSIDE_ROOT in reasons
    assert AnalysisIssueReason.INVALID_PATH in reasons
    assert result.operations == []


def test_symlink_source_is_rejected(repository: Path, tmp_path: Path) -> None:
    outside = write_text(tmp_path / "outside.py", "import os\nos.remove('a')\n")
    link = repository / "link.py"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks are not supported on this platform")

    inventory = manual_inventory(repository, ["link.py"])
    technologies = manual_technologies(repository, [])
    surface = identify_attack_surface(repository, inventory, technologies)
    result = identify_sensitive_operations(repository, inventory, technologies, surface)

    assert any(issue.reason is AnalysisIssueReason.SYMLINK for issue in result.issues)
    assert result.operations == []


def test_symlink_metadata_is_rejected(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_text(repository / "app.py", "import os\nos.remove('a')\n")
    inventory = manual_inventory(repository, ["app.py"])
    technologies = manual_technologies(repository, [])
    surface = identify_attack_surface(repository, inventory, technologies)
    real_lstat = Path.lstat

    def fake_lstat(path: Path) -> os.stat_result:
        if path.name == "app.py":
            return os.stat_result((stat.S_IFLNK | 0o777, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", fake_lstat)

    result = identify_sensitive_operations(repository, inventory, technologies, surface)

    assert any(issue.reason is AnalysisIssueReason.SYMLINK for issue in result.issues)
    assert result.operations == []


@pytest.mark.skipif(
    os.name != "nt",
    reason="Windows reparse-point metadata is Windows-specific",
)
def test_windows_reparse_point_is_rejected(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_text(repository / "app.py", "import os\nos.remove('a')\n")
    inventory = manual_inventory(repository, ["app.py"])
    technologies = manual_technologies(repository, [])
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

    result = identify_sensitive_operations(repository, inventory, technologies, surface)

    assert any(issue.reason is AnalysisIssueReason.SYMLINK for issue in result.issues)
    assert result.operations == []


def test_sensitive_and_excluded_files_are_never_read(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_text(repository / ".env", "SECRET=super-secret\n")
    write_text(repository / "credentials.py", "import os\nos.remove('a')\n")
    write_text(repository / "node_modules" / "pkg" / "index.js", "fs.readFile('a');\n")
    write_text(repository / "main.py", "x = 1\n")

    inventory = manual_inventory(
        repository,
        [".env", "credentials.py", "node_modules/pkg/index.js", "main.py"],
    )
    technologies = manual_technologies(repository, [])
    surface = identify_attack_surface(repository, inventory, technologies)
    real_open = Path.open

    def guarded_open(path: Path, *args: object, **kwargs: object) -> object:
        if path.name in {".env", "credentials.py", "index.js"}:
            raise AssertionError("Sensitive files must not be read")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)

    result = identify_sensitive_operations(repository, inventory, technologies, surface)

    assert result.summary.source_files_inspected == 1
    assert result.operations == []
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
    write_text(repository / "listed.py", "x = 1\n")
    write_text(repository / "unlisted.py", "import os\nos.remove('a')\n")
    inventory = manual_inventory(repository, ["listed.py"])
    technologies = manual_technologies(repository, [])
    surface = identify_attack_surface(repository, inventory, technologies)
    real_open = Path.open

    def guarded_open(path: Path, *args: object, **kwargs: object) -> object:
        if path.name == "unlisted.py":
            raise AssertionError("Unlisted source files must not be read")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)

    result = identify_sensitive_operations(repository, inventory, technologies, surface)

    assert result.summary.source_files_inspected == 1
    assert result.operations == []


def test_empty_repository_and_discovery_incompleteness(repository: Path) -> None:
    empty = analyze(repository)
    assert empty.operations == []
    assert empty.issues == []
    assert empty.summary.source_files_inspected == 0
    assert empty.summary.is_complete is True

    write_text(repository / "app.py", "import os\nos.remove('a')\n")
    inventory = manual_inventory(
        repository,
        ["app.py"],
        is_complete=False,
        truncation_reasons=[DiscoveryTruncationReason.MAX_FILE_COUNT],
    )
    technologies = manual_technologies(repository, [])
    surface = identify_attack_surface(repository, inventory, technologies)

    result = identify_sensitive_operations(repository, inventory, technologies, surface)

    assert result.summary.discovery_is_complete is False
    assert result.summary.discovery_truncation_reasons == [DiscoveryTruncationReason.MAX_FILE_COUNT]
    assert result.summary.is_complete is False
    assert find_operation(result, OperationCategory.FILE_DELETE, "remove")


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

    result = identify_sensitive_operations(repository, inventory, technologies, surface)

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
    with pytest.raises(InvalidSensitiveOperationRootError):
        identify_sensitive_operations(repository, inventory, mismatched_technologies, surface)

    mismatched_surface = surface.model_copy(deep=True)
    mismatched_surface.root = str((tmp_path / "other").resolve())
    with pytest.raises(InvalidSensitiveOperationRootError):
        identify_sensitive_operations(repository, inventory, technologies, mismatched_surface)


def test_root_outside_allowed_roots_is_rejected(
    allowed_root: Path,
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    inventory = manual_inventory(outside, [])
    technologies = manual_technologies(outside, [])
    surface = SimpleNamespace(root=str(outside.resolve()), routes=[])

    with pytest.raises(InvalidSensitiveOperationRootError):
        identify_sensitive_operations(outside, inventory, technologies, surface)


def test_negative_limits_are_rejected(repository: Path) -> None:
    inventory = manual_inventory(repository, [])
    technologies = manual_technologies(repository, [])
    surface = SimpleNamespace(root=str(repository.resolve()), routes=[])

    with pytest.raises(SensitiveOperationAnalysisError):
        identify_sensitive_operations(
            repository,
            inventory,
            technologies,
            surface,
            max_source_file_size_bytes=-1,
        )
    with pytest.raises(SensitiveOperationAnalysisError):
        identify_sensitive_operations(
            repository,
            inventory,
            technologies,
            surface,
            max_source_files=-1,
        )


def test_output_never_contains_runtime_values(repository: Path) -> None:
    write_requirements(repository, "sqlalchemy")
    text = source(
        """
        import subprocess

        from sqlalchemy.orm import Session

        def run():
            session = Session()
            session.execute("SELECT password FROM users WHERE token='super-secret'")
            open("secret.txt")
            subprocess.run(["curl", "http://secret.example/data"])
        """
    )
    write_text(repository / "app.py", text)

    result = analyze(repository)

    dumped = json.dumps(result.model_dump(mode="json"), sort_keys=True)
    assert "super-secret" not in dumped
    assert "SELECT password" not in dumped
    assert "secret.txt" not in dumped
    assert "curl" not in dumped
    assert "secret.example" not in dumped
    assert find_operation(result, OperationCategory.DATABASE_EXECUTE, "execute")
    assert find_operation(result, OperationCategory.FILE_READ, "open")
    assert find_operation(result, OperationCategory.PROCESS_EXECUTION, "run")
