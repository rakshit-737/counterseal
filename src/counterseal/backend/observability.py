"""Safe structured request logging and correlation IDs."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from time import perf_counter
from typing import Any
from uuid import UUID, uuid4

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

REQUEST_LOGGER_NAME = "counterseal.request"
CORRELATION_HEADER = "X-Correlation-ID"


class JsonLogFormatter(logging.Formatter):
    """Render only explicit structured fields as one JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": "request.completed",
        }
        fields = getattr(record, "structured", {})
        if isinstance(fields, dict):
            payload.update(fields)
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def configure_request_logging(level: str = "INFO") -> logging.Logger:
    """Configure the dedicated request logger without logging secrets."""

    logger = logging.getLogger(REQUEST_LOGGER_NAME)
    logger.setLevel(level)
    logger.propagate = True
    if not any(isinstance(handler, logging.StreamHandler) for handler in logger.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(JsonLogFormatter())
        logger.addHandler(handler)
    return logger


def _correlation_id(request: Request) -> str:
    candidate = request.headers.get(CORRELATION_HEADER)
    if candidate:
        try:
            return str(UUID(candidate))
        except ValueError:
            pass
    return str(uuid4())


def _safe_route(request: Request) -> str:
    route = request.scope.get("route")
    route_pattern = getattr(route, "path", None)
    if isinstance(route_pattern, str) and route_pattern:
        return route_pattern
    return "<unmatched>"


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log method, route, status, duration, and correlation ID only."""

    def __init__(self, app: Any, *, logger: logging.Logger | None = None) -> None:
        super().__init__(app)
        self.logger = logger or logging.getLogger(REQUEST_LOGGER_NAME)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        correlation_id = _correlation_id(request)
        started = perf_counter()
        response: Response | None = None
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            response.headers[CORRELATION_HEADER] = correlation_id
            return response
        finally:
            self.logger.info(
                "request.completed",
                extra={
                    "structured": {
                        "correlation_id": correlation_id,
                        "method": request.method,
                        "path": _safe_route(request),
                        "status_code": status_code,
                        "duration_ms": round((perf_counter() - started) * 1000, 3),
                    }
                },
            )


__all__ = [
    "CORRELATION_HEADER",
    "JsonLogFormatter",
    "REQUEST_LOGGER_NAME",
    "RequestLoggingMiddleware",
    "configure_request_logging",
]
