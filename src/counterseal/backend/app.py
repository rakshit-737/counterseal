"""FastAPI application factory for the Phase 1 backend slice."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import select, text

from .db import AuditEvent, AuthToken, Case, Job, User
from .db.session import create_database_engine, create_session_factory
from .errors import install_error_handlers
from .observability import RequestLoggingMiddleware, configure_request_logging
from .routes import router
from .settings import Settings, get_settings


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create the local-dev control plane; schema changes are explicit migrations."""

    resolved_settings = settings or get_settings()
    request_logger = configure_request_logging(resolved_settings.log_level)
    engine = create_database_engine(resolved_settings.database_url)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            engine.dispose()

    app = FastAPI(
        title=resolved_settings.app_name,
        version="0.1.0",
        lifespan=lifespan,
        description="Local-development Phase 1 foundation. Security engine not implemented.",
    )
    app.state.settings = resolved_settings
    app.state.engine = engine
    app.state.session_factory = create_session_factory(engine)
    install_error_handlers(app)
    app.add_middleware(RequestLoggingMiddleware, logger=request_logger)
    app.include_router(router)

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    def readyz() -> dict[str, str]:
        # Use the configured SQLAlchemy database and require migrated tables.
        # Failures use the same sanitized 503 envelope as other database errors.
        with app.state.engine.connect() as connection:
            connection.execute(text("SELECT 1"))
            for model in (User, AuthToken, Case, Job, AuditEvent):
                connection.execute(select(model).limit(0))
        return {"status": "ready"}

    return app


app = create_app()


__all__ = ["app", "create_app"]
