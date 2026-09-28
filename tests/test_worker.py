from __future__ import annotations

from datetime import UTC, datetime, timedelta
from threading import Event

import pytest

from counterseal.backend import worker
from counterseal.backend.auth import AuthenticationError, Role
from counterseal.backend.contracts import SECURITY_ENGINE_NOT_IMPLEMENTED
from counterseal.backend.db import AuthToken, Base, Job
from counterseal.backend.db.repositories import ControlPlaneRepository, TokenRepository
from counterseal.backend.db.session import create_database_engine, create_session_factory
from counterseal.backend.settings import Settings
from counterseal.backend.worker import (
    WorkerConfig,
    WorkerConfigurationError,
    process_once,
    read_worker_token,
)


def _fixture(tmp_path):
    engine = create_database_engine(f"sqlite:///{tmp_path / 'worker.db'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    settings = Settings(environment="test", database_url=f"sqlite:///{tmp_path / 'worker.db'}")
    with factory.begin() as session:
        token_repo = TokenRepository(session)
        analyst = token_repo.issue(
            subject="local-operator", role=Role.ANALYST, ttl=timedelta(hours=1)
        )
        worker = token_repo.issue(
            subject="local-workflow-worker", role=Role.WORKER, ttl=timedelta(hours=1)
        )
        repository = ControlPlaneRepository(session)
        case = repository.create_case(
            title="local fixture",
            description="transport test",
            principal=analyst.record.principal(),
        )
        repository.investigate(
            case.case_id,
            principal=analyst.record.principal(),
            idempotency_key="worker-test-1",
        )
    return engine, factory, settings, worker.token


def test_worker_completes_only_as_unsupported(tmp_path):
    engine, factory, settings, token = _fixture(tmp_path)
    try:
        assert process_once(factory, settings, token) is True
        assert process_once(factory, settings, token) is False
        with factory() as session:
            job = session.query(Job).one()
            assert job.status == "COMPLETED"
            assert job.outcome == "UNSUPPORTED"
            assert job.reason == SECURITY_ENGINE_NOT_IMPLEMENTED
    finally:
        engine.dispose()


def test_worker_rejects_non_worker_identity(tmp_path):
    engine, factory, settings, token = _fixture(tmp_path)
    try:
        with pytest.raises(WorkerConfigurationError):
            process_once(factory, settings, token, expected_subject="different-worker")
    finally:
        engine.dispose()


def test_worker_rejects_human_and_revoked_tokens(tmp_path):
    engine, factory, settings, token = _fixture(tmp_path)
    try:
        with factory.begin() as session:
            human = TokenRepository(session).issue(
                subject="local-workflow-worker", role=Role.ADMIN, ttl=timedelta(hours=1)
            )
        with pytest.raises(WorkerConfigurationError):
            process_once(factory, settings, human.token)
        with factory.begin() as session:
            principal = TokenRepository(session).authenticate(token)
            session.get(AuthToken, principal.token_id).revoked_at = datetime.now(UTC)
        with pytest.raises(AuthenticationError):
            process_once(factory, settings, token)
        with factory() as session:
            assert session.query(Job).one().status == "QUEUED"
    finally:
        engine.dispose()


def test_worker_token_file_is_single_line_and_not_empty(tmp_path):
    path = tmp_path / "worker.token"
    path.write_text("opaque-token\n", encoding="utf-8")
    assert read_worker_token(path) == "opaque-token"
    path.write_text("first\nsecond\n", encoding="utf-8")
    with pytest.raises(WorkerConfigurationError):
        read_worker_token(path)


@pytest.mark.parametrize("delay", [0, 61, float("nan"), float("inf")])
def test_worker_delays_are_bounded(tmp_path, delay):
    with pytest.raises(WorkerConfigurationError):
        WorkerConfig(token_file=tmp_path / "token", expected_subject="worker", poll_seconds=delay)


def test_worker_stops_after_bounded_errors_without_logging_secrets(tmp_path, monkeypatch, caplog):
    engine, _factory, settings, token = _fixture(tmp_path)
    token_path = tmp_path / "worker.token"
    token_path.write_text(token, encoding="utf-8")
    attempts = []

    def failing_iteration(*_args, **_kwargs):
        attempts.append(1)
        raise RuntimeError(f"driver detail: {token}")

    monkeypatch.setattr(worker, "process_once", failing_iteration)
    monkeypatch.setattr(worker, "_install_stop_handlers", lambda _event: None)
    monkeypatch.setattr(worker, "READY_FILE", tmp_path / "worker.ready")
    try:
        config = WorkerConfig(
            token_file=token_path,
            expected_subject="local-workflow-worker",
            error_backoff_seconds=0.1,
            max_consecutive_errors=2,
        )
        assert worker.run(config, settings) == 1
        assert len(attempts) == 2
        assert token not in caplog.text
        assert "driver detail" not in caplog.text
        assert not worker.READY_FILE.exists()
    finally:
        engine.dispose()


def test_worker_honors_stop_without_claiming_a_job(tmp_path, monkeypatch):
    engine, factory, settings, token = _fixture(tmp_path)
    token_path = tmp_path / "worker.token"
    token_path.write_text(token, encoding="utf-8")
    stop = Event()
    stop.set()
    monkeypatch.setattr(worker, "_install_stop_handlers", lambda _event: None)
    monkeypatch.setattr(worker, "READY_FILE", tmp_path / "worker.ready")
    try:
        config = WorkerConfig(token_file=token_path, expected_subject="local-workflow-worker")
        assert worker.run(config, settings, stop) == 0
        with factory() as session:
            assert session.query(Job).one().status == "QUEUED"
    finally:
        engine.dispose()
