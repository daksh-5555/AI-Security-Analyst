"""Create (or reuse) a verified Admin demo user so you can sign in immediately.

Run from the project root, with the backend's virtualenv active:

    python scripts/create_demo_user.py

It reads the same .env the app uses, so it writes to the same database.
Credentials:  demo@example.com  /  correct horse battery staple demo
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.emails import normalize_email
from app.core.roles import ROLE_IDS
from app.core.security import hash_password
from app.db.session import engine
from app.models.user import User
from app.models.user_role import UserRole
from app.schemas.enums import RoleName

EMAIL = "demo@example.com"
PASSWORD = "correct horse battery staple demo"


def main() -> None:
    admin_role = next(role for role in RoleName if role.value == "Admin")
    normalized = normalize_email(EMAIL)
    with Session(engine) as session:
        existing = session.scalar(select(User).where(User.email_normalized == normalized))
        if existing is not None:
            print(f"User already exists: {existing.id}")
            return
        now = datetime.now(UTC)
        user = User(
            email=normalized,
            email_normalized=normalized,
            password_hash=hash_password(PASSWORD),
            is_active=True,
            is_email_verified=True,
            created_at=now,
            updated_at=now,
        )
        session.add(user)
        session.flush()
        session.add(UserRole(user_id=user.id, role_id=ROLE_IDS[admin_role]))
        session.commit()
        print(f"Created verified Admin user: {user.id}")
        print(f"  email:    {EMAIL}")
        print(f"  password: {PASSWORD}")


if __name__ == "__main__":
    main()
