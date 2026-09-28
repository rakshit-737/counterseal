"""Explicit SQLAlchemy engines and request-scoped sessions."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from fastapi import Request
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool


def create_database_engine(database_url: str) -> Engine:
    url = make_url(database_url)
    if url.get_backend_name() not in {"sqlite", "postgresql"}:
        raise ValueError("only SQLite and PostgreSQL databases are supported")
    kwargs: dict[str, Any] = {"pool_pre_ping": True, "hide_parameters": True}
    if url.get_backend_name() == "sqlite":
        kwargs["connect_args"] = {"check_same_thread": False, "timeout": 10}
        if url.database in (None, "", ":memory:"):
            kwargs["poolclass"] = StaticPool
    engine = create_engine(url, **kwargs)
    if url.get_backend_name() == "sqlite":

        @event.listens_for(engine, "connect")
        def configure_sqlite(connection: Any, _record: Any) -> None:
            # Explicit transactions also cover savepoints and transactional DDL.
            connection.isolation_level = None
            cursor = connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        @event.listens_for(engine, "begin")
        def begin_sqlite(connection: Any) -> None:
            # SQLite's local-dev single writer is serialized before auth reads,
            # avoiding a read-to-write lock upgrade race. PostgreSQL uses row locks.
            connection.exec_driver_sql("BEGIN IMMEDIATE")

    return engine


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


def get_session(request: Request) -> Iterator[Session]:
    """Handlers explicitly commit writes before returning a success response."""

    with request.app.state.session_factory() as session:
        yield session
