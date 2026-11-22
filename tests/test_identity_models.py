from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, func, inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.core.emails import normalize_email
from app.db.base import Base
from app.db.session import create_db_engine
from app.models.role import Role
from app.models.user import User
from app.models.user_role import UserRole
from app.schemas.enums import RoleName

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def make_user(
    email: str = "Analyst@Example.com",
    password_hash: str = "argon2id-placeholder-hash",
) -> User:
    normalized = normalize_email(email)
    now = datetime.now(UTC)
    return User(
        email=email.strip(),
        email_normalized=normalized,
        password_hash=password_hash,
        created_at=now,
        updated_at=now,
    )


def get_role(session: Session, name: RoleName) -> Role:
    role = session.scalar(select(Role).where(Role.name == name.value))
    assert role is not None
    return role


def test_identity_models_registered_with_base_metadata() -> None:
    assert {"users", "roles", "user_roles"} <= set(Base.metadata.tables)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("User@Example.com", "user@example.com"),
        ("  user@example.com  ", "user@example.com"),
        ("USER@EXAMPLE.COM", "user@example.com"),
        ("Caf\u00e9@Example.com", "caf\u00e9@example.com"),
        ("Cafe\u0301@Example.com", "caf\u00e9@example.com"),
    ],
)
def test_normalize_email_returns_canonical_value(raw: str, expected: str) -> None:
    assert normalize_email(raw) == expected


def test_normalize_email_rejects_invalid_values() -> None:
    with pytest.raises(TypeError):
        normalize_email(123)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        normalize_email("   ")
    with pytest.raises(ValueError):
        normalize_email("a" * 321)


def test_user_defaults_and_timestamp_round_trip(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        user = make_user()
        session.add(user)
        session.commit()
        user_id = user.id

    with session_factory() as session:
        stored = session.get(User, user_id)

    assert stored is not None
    assert stored.id == user_id
    assert stored.is_active is True
    assert stored.is_email_verified is False
    assert stored.created_at.tzinfo is not None
    assert stored.updated_at.tzinfo is not None
    assert stored.updated_at >= stored.created_at
    assert stored.roles == []


def test_duplicate_normalized_email_is_rejected(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        session.add(make_user("User@Example.com"))
        session.commit()

        session.add(make_user("  user@example.COM  "))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

        count = session.scalar(select(func.count()).select_from(User))

    assert count == 1


def test_migration_seeds_canonical_roles_without_assignments(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        names = set(session.scalars(select(Role.name)).all())
        user_count = session.scalar(select(func.count()).select_from(User))
        user_role_count = session.scalar(select(func.count()).select_from(UserRole))
        role_created_at = list(session.scalars(select(Role.created_at)).all())

    assert names == {
        RoleName.ADMIN.value,
        RoleName.SECURITY_ANALYST.value,
        RoleName.VIEWER.value,
    }
    assert user_count == 0
    assert user_role_count == 0
    assert all(value.tzinfo is not None for value in role_created_at)


def test_duplicate_role_assignment_is_rejected(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        user = make_user()
        role = get_role(session, RoleName.VIEWER)
        session.add(user)
        session.flush()
        session.add(UserRole(user_id=user.id, role_id=role.id))
        session.commit()

        session.add(UserRole(user_id=user.id, role_id=role.id))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

        count = session.scalar(select(func.count()).select_from(UserRole))

    assert count == 1


def test_user_deletion_cascades_role_assignments(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        user = make_user()
        role = get_role(session, RoleName.VIEWER)
        session.add(user)
        session.flush()
        session.add(UserRole(user_id=user.id, role_id=role.id))
        session.commit()
        user_id = user.id
        role_id = role.id

    with session_factory() as session:
        session.execute(delete(User).where(User.id == user_id))
        session.commit()

    with session_factory() as session:
        assert session.get(User, user_id) is None
        assert session.scalar(select(func.count()).select_from(UserRole)) == 0
        assert session.get(Role, role_id) is not None


def test_role_deletion_is_restricted_while_assigned(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        user = make_user()
        role = get_role(session, RoleName.VIEWER)
        session.add(user)
        session.flush()
        session.add(UserRole(user_id=user.id, role_id=role.id))
        session.commit()
        role_id = role.id

    with session_factory() as session:
        with pytest.raises(IntegrityError):
            session.execute(delete(Role).where(Role.id == role_id))
            session.commit()
        session.rollback()

    with session_factory() as session:
        assert session.get(Role, role_id) is not None

        session.execute(delete(UserRole).where(UserRole.role_id == role_id))
        session.execute(delete(Role).where(Role.id == role_id))
        session.commit()

    with session_factory() as session:
        assert session.get(Role, role_id) is None


def test_user_roles_relationship_returns_explicit_assignments(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        user = make_user()
        analyst = get_role(session, RoleName.SECURITY_ANALYST)
        viewer = get_role(session, RoleName.VIEWER)
        session.add(user)
        session.flush()
        session.add_all(
            [
                UserRole(user_id=user.id, role_id=analyst.id),
                UserRole(user_id=user.id, role_id=viewer.id),
            ]
        )
        session.commit()
        user_id = user.id

    with session_factory() as session:
        stored = session.get(User, user_id)

    assert stored is not None
    assert [role.name for role in stored.roles] == [
        RoleName.SECURITY_ANALYST.value,
        RoleName.VIEWER.value,
    ]


def test_identity_migration_round_trip(tmp_path: Path) -> None:
    database_path = tmp_path / "migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)

    command.upgrade(config, "head")

    engine = create_db_engine(database_url)
    try:
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
        assert {"users", "roles", "user_roles"} <= tables

        user_columns = {column["name"] for column in inspector.get_columns("users")}
        assert user_columns == {
            "id",
            "email",
            "email_normalized",
            "password_hash",
            "is_active",
            "is_email_verified",
            "created_at",
            "updated_at",
        }

        role_columns = {column["name"] for column in inspector.get_columns("roles")}
        assert role_columns == {"id", "name", "created_at"}

        user_role_columns = {column["name"] for column in inspector.get_columns("user_roles")}
        assert user_role_columns == {"user_id", "role_id", "created_at"}

        user_uniques = inspector.get_unique_constraints("users")
        assert any(
            constraint["column_names"] == ["email_normalized"] for constraint in user_uniques
        )
        role_uniques = inspector.get_unique_constraints("roles")
        assert any(constraint["column_names"] == ["name"] for constraint in role_uniques)

        primary_key = inspector.get_pk_constraint("user_roles")
        assert primary_key["constrained_columns"] == ["user_id", "role_id"]

        foreign_keys = {
            foreign_key["referred_table"]: foreign_key
            for foreign_key in inspector.get_foreign_keys("user_roles")
        }
        assert foreign_keys["users"]["options"].get("ondelete") == "CASCADE"
        assert foreign_keys["roles"]["options"].get("ondelete") == "RESTRICT"

        indexes = inspector.get_indexes("user_roles")
        assert any(
            index["name"] == "ix_user_roles_role_id" and index["column_names"] == ["role_id"]
            for index in indexes
        )

        with engine.connect() as connection:
            role_names = set(connection.execute(text("SELECT name FROM roles")).scalars().all())
        assert role_names == {
            RoleName.ADMIN.value,
            RoleName.SECURITY_ANALYST.value,
            RoleName.VIEWER.value,
        }
    finally:
        engine.dispose()

    command.downgrade(config, "0007")

    engine = create_db_engine(database_url)
    try:
        tables = set(inspect(engine).get_table_names())
        assert not ({"users", "roles", "user_roles"} & tables)
        assert "assessment_jobs" in tables
    finally:
        engine.dispose()

    command.upgrade(config, "head")

    engine = create_db_engine(database_url)
    try:
        assert {"users", "roles", "user_roles"} <= set(inspect(engine).get_table_names())
    finally:
        engine.dispose()
