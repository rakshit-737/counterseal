"""Bounded local workflow worker for unsupported investigation jobs.

The worker deliberately has no command execution or source-collection path. It
authenticates one persisted worker token, claims at most one database job per
poll, and acknowledges that job as unsupported. This keeps queue transport
testing separate from any future security-engine implementation.
"""

from __future__ import annotations

import logging
import math
import os
import signal
import tempfile
from dataclasses import dataclass
from pathlib import Path
from threading import Event
from typing import Final

from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from .auth import Principal, Role
from .contracts import SECURITY_ENGINE_NOT_IMPLEMENTED
from .db.repositories import ControlPlaneRepository, TokenRepository
from .db.session import create_database_engine, create_session_factory
from .settings import Settings

LOGGER = logging.getLogger("counterseal.worker")
DEFAULT_WORKER_SUBJECT: Final = "local-workflow-worker"
DEFAULT_TOKEN_FILE: Final = "/run/secrets/worker_token"
READY_FILE: Final = Path(tempfile.gettempdir()) / "counterseal-worker.ready"


class WorkerConfigurationError(ValueError):
    """Raised when the worker identity or bounded runtime settings are invalid."""


@dataclass(frozen=True, slots=True)
class WorkerConfig:
    """Validated worker-only settings sourced from the process environment."""

    token_file: Path
    expected_subject: str
    poll_seconds: float = 2.0
    error_backoff_seconds: float = 5.0
    lease_seconds: int = 60
    max_consecutive_errors: int = 5

    def __post_init__(self) -> None:
        if not self.expected_subject.strip():
            raise WorkerConfigurationError("worker identity must be nonblank")
        for value in (self.poll_seconds, self.error_backoff_seconds):
            if not math.isfinite(value) or not 0.1 <= value <= 60:
                raise WorkerConfigurationError("worker wait is outside its permitted bound")
        if not 1 <= self.lease_seconds <= 300 or not 1 <= self.max_consecutive_errors <= 20:
            raise WorkerConfigurationError("worker limits are outside their permitted bound")

    @classmethod
    def from_environment(cls) -> WorkerConfig:
        return cls(
            token_file=Path(os.environ.get("COUNTERSEAL_WORKER_TOKEN_FILE", DEFAULT_TOKEN_FILE)),
            expected_subject=os.environ.get(
                "COUNTERSEAL_WORKER_EXPECTED_SUBJECT", DEFAULT_WORKER_SUBJECT
            ),
            poll_seconds=_bounded_float("COUNTERSEAL_WORKER_POLL_SECONDS", 2.0, 0.1, 60.0),
            error_backoff_seconds=_bounded_float(
                "COUNTERSEAL_WORKER_ERROR_BACKOFF_SECONDS", 5.0, 0.1, 60.0
            ),
            lease_seconds=_bounded_int("COUNTERSEAL_WORKER_LEASE_SECONDS", 60, 1, 300),
            max_consecutive_errors=_bounded_int(
                "COUNTERSEAL_WORKER_MAX_CONSECUTIVE_ERRORS", 5, 1, 20
            ),
        )


def _bounded_float(name: str, default: float, minimum: float, maximum: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise WorkerConfigurationError(f"{name} must be numeric") from exc
    if not math.isfinite(value) or value < minimum or value > maximum:
        raise WorkerConfigurationError(f"{name} is outside its permitted bound")
    return value


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise WorkerConfigurationError(f"{name} must be an integer") from exc
    if value < minimum or value > maximum:
        raise WorkerConfigurationError(f"{name} is outside its permitted bound")
    return value


def read_worker_token(path: Path) -> str:
    """Read one bearer token without ever returning file contents to a logger."""

    if path.is_symlink() or not path.is_file():
        raise WorkerConfigurationError("worker token file is unavailable")
    try:
        with path.open(encoding="utf-8") as stream:
            value = stream.read(515)
        if len(value) > 514:
            raise WorkerConfigurationError("worker token file is too large")
        token = value.strip()
    except (OSError, UnicodeError) as exc:
        raise WorkerConfigurationError("worker token file could not be read") from exc
    if not token or any(character.isspace() for character in token) or len(token) > 512:
        raise WorkerConfigurationError("worker token file does not contain one token")
    return token


def _require_worker(principal: Principal, expected_subject: str) -> None:
    if principal.role is not Role.WORKER:
        raise WorkerConfigurationError("worker token does not have the worker role")
    if not expected_subject.strip() or principal.subject != expected_subject:
        raise WorkerConfigurationError("worker token is not the dedicated worker identity")


def process_once(
    session_factory: sessionmaker[Session],
    settings: Settings,
    token: str,
    *,
    expected_subject: str = DEFAULT_WORKER_SUBJECT,
    lease_seconds: int = 60,
) -> bool:
    """Claim and acknowledge one job, returning whether a job was processed.

    Authentication and claim/complete are in one SQLAlchemy transaction. The
    only completion value accepted here is the repository's explicit
    ``UNSUPPORTED`` outcome; no job payload is interpreted as a command.
    """

    if lease_seconds < 1 or lease_seconds > 300:
        raise WorkerConfigurationError("lease_seconds is outside its permitted bound")
    with session_factory.begin() as session:
        if session.get_bind().dialect.name == "postgresql":
            session.execute(text("SET LOCAL statement_timeout = '10s'"))
            session.execute(text("SET LOCAL lock_timeout = '5s'"))
        principal = TokenRepository(session, hash_secret=settings.token_hash_secret).authenticate(
            token
        )
        _require_worker(principal, expected_subject)
        repository = ControlPlaneRepository(session)
        job = repository.claim(principal=principal, lease_seconds=lease_seconds)
        if job is None:
            return False
        if job.lease_id is None:
            raise WorkerConfigurationError("claimed job did not receive a lease")
        completed = repository.complete(job.job_id, principal=principal, lease_id=job.lease_id)
        if (
            completed.outcome != "UNSUPPORTED"
            or completed.reason != SECURITY_ENGINE_NOT_IMPLEMENTED
        ):
            raise WorkerConfigurationError(
                "repository returned an unsupported job contract violation"
            )
        return True


def _install_stop_handlers(stop: Event) -> None:
    def request_stop(_signum: int, _frame: object) -> None:
        stop.set()

    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(signum, request_stop)
        except (ValueError, OSError):
            # Signal registration is only available from the main thread and
            # varies on Windows; the polling loop remains bounded either way.
            continue


def run(config: WorkerConfig, settings: Settings, stop: Event | None = None) -> int:
    """Run the bounded poll loop until stopped or repeated failures exhaust."""

    READY_FILE.unlink(missing_ok=True)
    token = read_worker_token(config.token_file)
    database_url = make_url(settings.database_url)
    if database_url.get_backend_name() == "postgresql":
        database_url = database_url.update_query_dict({"connect_timeout": "5"})
    engine = create_database_engine(database_url.render_as_string(hide_password=False))
    session_factory = create_session_factory(engine)
    stop_event = stop or Event()
    _install_stop_handlers(stop_event)
    consecutive_errors = 0
    try:
        while not stop_event.is_set():
            try:
                process_once(
                    session_factory,
                    settings,
                    token,
                    expected_subject=config.expected_subject,
                    lease_seconds=config.lease_seconds,
                )
                consecutive_errors = 0
                READY_FILE.touch(mode=0o600)
            except Exception as exc:  # noqa: BLE001 - bounded retry boundary sanitizes all failures
                consecutive_errors += 1
                # Do not include exception text: database drivers can echo
                # connection details, and the token must never reach logs.
                LOGGER.error(
                    "worker iteration failed (%d/%d): %s",
                    consecutive_errors,
                    config.max_consecutive_errors,
                    type(exc).__name__,
                )
                if consecutive_errors >= config.max_consecutive_errors:
                    LOGGER.error("worker stopping after bounded consecutive failures")
                    return 1
                stop_event.wait(config.error_backoff_seconds)
                continue
            stop_event.wait(config.poll_seconds)
    finally:
        READY_FILE.unlink(missing_ok=True)
        engine.dispose()
    return 0


def main() -> int:
    """CLI entry point used by the Compose worker service."""

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    try:
        settings = Settings()
        config = WorkerConfig.from_environment()
        return run(config, settings)
    except Exception as exc:  # noqa: BLE001 - startup boundary sanitizes all failures
        LOGGER.error("worker startup failed: %s", type(exc).__name__)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "DEFAULT_WORKER_SUBJECT",
    "WorkerConfig",
    "WorkerConfigurationError",
    "main",
    "process_once",
    "read_worker_token",
    "run",
]
