"""Local-development identity bootstrap. Run migrations before issuing tokens."""

from __future__ import annotations

import argparse
import sys
from datetime import timedelta

from sqlalchemy.exc import SQLAlchemyError

from .auth import Role
from .db.repositories import TokenRepository
from .db.session import create_database_engine, create_session_factory
from .settings import Settings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="counterseal", description="Counterseal local-development foundation."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser(
        "init-token", help="Issue a local-dev bearer token once; requires alembic upgrade head."
    )
    init.add_argument("--subject", required=True, help="Local user or worker identity")
    init.add_argument("--role", choices=[role.value for role in Role], default="viewer")
    args = parser.parse_args(argv)
    engine = None
    try:
        settings = Settings()
        if settings.environment not in {"development", "test"}:
            print("init-token is a local-development bootstrap only.", file=sys.stderr)
            return 1
        engine = create_database_engine(settings.database_url)
        with create_session_factory(engine).begin() as session:
            issued = TokenRepository(session, hash_secret=settings.token_hash_secret).issue(
                subject=args.subject,
                role=Role(args.role),
                ttl=timedelta(seconds=settings.auth_token_ttl_seconds),
            )
    except (SQLAlchemyError, ValueError, ImportError):
        print(
            "Token issuance failed. Check local settings and run alembic upgrade head.",
            file=sys.stderr,
        )
        return 1
    finally:
        if engine is not None:
            engine.dispose()
    print(
        "Local-development token; shown once. Store securely. Only its hash was persisted.",
        file=sys.stderr,
    )
    print(issued.token)
    return 0
