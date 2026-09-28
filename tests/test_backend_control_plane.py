from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path
from uuid import uuid4

import pytest
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from fastapi.testclient import TestClient
from sqlalchemy import delete, func, inspect, select, text, update
from sqlalchemy.exc import DBAPIError, OperationalError

from alembic import command
from counterseal.backend.app import create_app
from counterseal.backend.auth import Principal, Role, hash_token
from counterseal.backend.cli import main
from counterseal.backend.contracts import SECURITY_ENGINE_NOT_IMPLEMENTED
from counterseal.backend.db import AuditEvent, AuthToken, Base, Case, Job, User
from counterseal.backend.db.repositories import ControlPlaneRepository, TokenRepository
from counterseal.backend.db.session import create_database_engine, create_session_factory
from counterseal.backend.settings import Settings

ROOT = Path(__file__).resolve().parents[1]


def migration_config(connection=None) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.attributes["configure_logger"] = False
    if connection is not None:
        config.attributes["connection"] = connection
    return config


@pytest.fixture
def api(tmp_path):
    app = create_app(Settings(environment="test", database_url=f"sqlite:///{tmp_path / 'api.db'}"))
    with app.state.engine.begin() as connection:
        command.upgrade(migration_config(connection), "head")
    tokens = {}
    with app.state.session_factory.begin() as session:
        repo = TokenRepository(session)
        for role in Role:
            tokens[role.value] = repo.issue(
                subject=f"local-{role.value}", role=role, ttl=timedelta(hours=1)
            ).token
        # Same subject, different token still cannot take over another token's lease.
        tokens["other-worker"] = repo.issue(
            subject="local-worker", role=Role.WORKER, ttl=timedelta(hours=1)
        ).token
    with TestClient(app) as client:
        yield client, app, tokens


def headers(tokens, role="analyst", **extra):
    return {"Authorization": f"Bearer {tokens[role]}", **extra}


def new_case(client, tokens, **body):
    response = client.post(
        "/v1/cases", headers=headers(tokens), json={"title": "Fixture case", **body}
    )
    assert response.status_code == 201, response.text
    return response.json()["case_id"]


def new_job(client, tokens, case_id, key="request-1"):
    response = client.post(
        f"/v1/cases/{case_id}/investigations",
        headers=headers(tokens, **{"Idempotency-Key": key}),
    )
    assert response.status_code == 202, response.text
    return response.json()


def test_auth_requires_only_authorization_bearer_and_me_hides_hashes(api):
    client, app, tokens = api
    for kwargs in (
        {},
        {"headers": {"Authorization": "Bearer invalid-secret"}},
        {"headers": {"Authorization": f"Basic {tokens['admin']}"}},
        {"params": {"access_token": tokens["admin"]}},
        {
            "headers": [
                ("Authorization", f"Bearer {tokens['admin']}"),
                ("Authorization", "Bearer other"),
            ]
        },
    ):
        response = client.get("/v1/me", **kwargs)
        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == "Bearer"
        assert response.json()["error"]["code"] == "UNAUTHENTICATED"
        assert "invalid-secret" not in response.text
    for role in Role:
        response = client.get("/v1/me", headers=headers(tokens, role.value))
        assert response.json() == {"subject": f"local-{role.value}", "role": role.value}
        assert tokens[role.value] not in response.text
    with app.state.session_factory() as session:
        rows = session.scalars(select(AuthToken)).all()
        assert all(row.token_hash not in tokens.values() for row in rows)
        assert {hash_token(token) for token in tokens.values()} == {row.token_hash for row in rows}


@pytest.mark.parametrize("condition", ["expired", "revoked", "disabled"])
def test_expired_revoked_and_disabled_identities_fail_closed(api, condition):
    client, app, tokens = api
    now = datetime.now(UTC)
    with app.state.session_factory.begin() as session:
        if condition == "disabled":
            session.execute(
                update(User).where(User.subject == "local-viewer").values(disabled_at=now)
            )
        elif condition == "revoked":
            session.execute(
                update(AuthToken).where(AuthToken.role == "viewer").values(revoked_at=now)
            )
        else:
            session.execute(
                update(AuthToken)
                .where(AuthToken.role == "viewer")
                .values(
                    issued_at=now - timedelta(hours=2),
                    expires_at=now - timedelta(hours=1),
                )
            )
    assert client.get("/v1/me", headers=headers(tokens, "viewer")).status_code == 401


def test_case_creation_reads_pagination_timeline_and_persistence(api):
    client, app, tokens = api
    case_id = new_case(
        client, tokens, title="  Local question  ", description="No observations collected"
    )
    response = client.get(f"/v1/cases/{case_id}", headers=headers(tokens, "viewer"))
    assert response.status_code == 200
    case = response.json()
    assert case["title"] == "Local question"
    assert case["created_by"] == "local-analyst"
    assert case["state"] == "NEEDS_EVIDENCE"
    assert case["reason"] == SECURITY_ENGINE_NOT_IMPLEMENTED
    assert datetime.fromisoformat(case["created_at"]).utcoffset() == timedelta(0)
    listing = client.get("/v1/cases", headers=headers(tokens, "viewer"), params={"limit": 1}).json()
    assert listing["items"] == [case]
    assert client.get("/v1/cases?offset=1", headers=headers(tokens, "viewer")).json() == {
        "items": []
    }
    timeline = client.get(
        f"/v1/cases/{case_id}/timeline", headers=headers(tokens, "viewer")
    ).json()["items"]
    assert [event["action"] for event in timeline] == ["CASE_CREATED"]
    assert timeline[0]["actor"] == "local-analyst"
    assert client.get(
        f"/v1/cases/{case_id}/timeline?after={timeline[0]['sequence']}", headers=headers(tokens)
    ).json() == {"items": []}
    # Re-open the configured file through a new app/engine, not in-memory state.
    with TestClient(create_app(app.state.settings)) as restarted:
        assert restarted.get(f"/v1/cases/{case_id}", headers=headers(tokens)).json() == case
    assert client.get(f"/v1/cases/{uuid4()}", headers=headers(tokens)).status_code == 404
    assert client.get(f"/v1/cases/{uuid4()}/timeline", headers=headers(tokens)).status_code == 404


def test_human_roles_and_worker_roles_are_separate(api):
    client, _app, tokens = api
    case_id = new_case(client, tokens)
    for role in ("viewer", "worker"):
        assert (
            client.post(
                "/v1/cases", headers=headers(tokens, role), json={"title": "denied"}
            ).status_code
            == 403
        )
        assert (
            client.post(
                f"/v1/cases/{case_id}/investigations",
                headers=headers(tokens, role),
                json={"idempotency_key": "denied"},
            ).status_code
            == 403
        )
    for role in ("viewer", "analyst", "approver", "admin"):
        assert client.get("/v1/cases", headers=headers(tokens, role)).status_code == 200
        assert (
            client.post("/v1/workers/jobs/claim", headers=headers(tokens, role)).status_code == 403
        )
    for role in ("approver", "admin"):
        assert (
            client.post(
                "/v1/cases", headers=headers(tokens, role), json={"title": "authorized"}
            ).status_code
            == 201
        )
    for route in ("/v1/cases", f"/v1/cases/{case_id}", f"/v1/cases/{case_id}/timeline"):
        assert client.get(route, headers=headers(tokens, "worker")).status_code == 403


def test_investigation_idempotency_is_durable_scoped_and_conflicts(api):
    client, app, tokens = api
    case_id = new_case(client, tokens)
    job = new_job(client, tokens, case_id)
    with TestClient(create_app(app.state.settings)) as restarted:
        replay = restarted.post(
            f"/v1/cases/{case_id}/investigations",
            headers=headers(tokens),
            json={"idempotency_key": "request-1"},
        )
    assert replay.status_code == 202
    assert replay.headers["Idempotency-Replayed"] == "true"
    assert replay.json() == job
    assert job["status"] == "QUEUED"
    assert job["reason"] == SECURITY_ENGINE_NOT_IMPLEMENTED
    other_case = new_case(client, tokens)
    conflict = client.post(
        f"/v1/cases/{other_case}/investigations",
        headers=headers(tokens),
        json={"idempotency_key": "request-1"},
    )
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "IDEMPOTENCY_CONFLICT"
    # Different authenticated users have independent key namespaces.
    assert (
        client.post(
            f"/v1/cases/{case_id}/investigations",
            headers=headers(tokens, "admin"),
            json={"idempotency_key": "request-1"},
        ).status_code
        == 202
    )
    assert (
        client.get(f"/v1/cases/{case_id}", headers=headers(tokens)).json()["state"]
        == "NEEDS_EVIDENCE"
    )
    with app.state.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(Job)) == 2
        assert (
            session.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.action == "INVESTIGATION_REQUESTED")
            )
            == 2
        )


@pytest.mark.parametrize(
    "body,extra",
    [
        ({}, {}),
        ({"idempotency_key": "body-key"}, {"Idempotency-Key": "different-key"}),
        ({"idempotency_key": "x" * 129}, {}),
        ({"idempotency_key": "x", "credentials": "do-not-echo-me"}, {}),
        ({}, {"Idempotency-Key": "contains spaces"}),
    ],
)
def test_investigation_rejects_missing_invalid_or_conflicting_keys(api, body, extra):
    client, app, tokens = api
    case_id = new_case(client, tokens)
    response = client.post(
        f"/v1/cases/{case_id}/investigations", headers=headers(tokens, **extra), json=body
    )
    assert response.status_code == 422
    assert "do-not-echo-me" not in response.text
    with app.state.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(Job)) == 0


def test_concurrent_idempotency_and_claim_only_produce_one_job_and_lease(api):
    client, app, tokens = api
    case_id = new_case(client, tokens)

    def submit(_):
        return client.post(
            f"/v1/cases/{case_id}/investigations",
            headers=headers(tokens),
            json={"idempotency_key": "same-key"},
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        submissions = list(pool.map(submit, range(2)))
    assert [r.status_code for r in submissions] == [202, 202]
    assert len({r.json()["job_id"] for r in submissions}) == 1

    def claim(role):
        return client.post("/v1/workers/jobs/claim", headers=headers(tokens, role))

    with ThreadPoolExecutor(max_workers=2) as pool:
        claims = list(pool.map(claim, ["worker", "other-worker"]))
    assert [r.status_code for r in claims] == [200, 200]
    assert sum(r.json()["job"] is not None for r in claims) == 1
    with app.state.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(Job)) == 1
        assert (
            session.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.action == "JOB_CLAIMED")
            )
            == 1
        )


def test_worker_lease_ownership_heartbeat_completion_and_no_false_assurance(api):
    client, _app, tokens = api
    assert client.post("/v1/workers/jobs/claim", headers=headers(tokens, "worker")).json() == {
        "job": None
    }
    case_id = new_case(client, tokens)
    job = new_job(client, tokens, case_id)
    claim = client.post(
        "/v1/workers/jobs/claim", headers=headers(tokens, "worker"), json={"lease_seconds": 30}
    ).json()["job"]
    assert claim["job_id"] == job["job_id"]
    assert claim["attempts"] == 1
    assert claim["status"] == "LEASED"
    base = f"/v1/workers/jobs/{job['job_id']}"
    body = {"lease_id": claim["lease_id"]}
    for action in ("heartbeat", "complete"):
        assert (
            client.post(
                f"{base}/{action}", headers=headers(tokens, "other-worker"), json=body
            ).status_code
            == 403
        )
        assert (
            client.post(
                f"{base}/{action}", headers=headers(tokens, "analyst"), json=body
            ).status_code
            == 403
        )
        assert (
            client.post(
                f"{base}/{action}",
                headers=headers(tokens, "worker"),
                json={"lease_id": str(uuid4())},
            ).status_code
            == 409
        )
    heartbeat = client.post(
        f"{base}/heartbeat", headers=headers(tokens, "worker"), json={**body, "lease_seconds": 120}
    )
    assert heartbeat.status_code == 200
    assert heartbeat.json()["lease_expires_at"] > claim["lease_expires_at"]
    forged = client.post(
        f"{base}/complete",
        headers=headers(tokens, "worker"),
        json={**body, "outcome": "PASS", "state": "LAB_APPROVED"},
    )
    assert forged.status_code == 422
    completed = client.post(f"{base}/complete", headers=headers(tokens, "worker"), json=body)
    assert completed.status_code == 200
    assert completed.json()["status"] == "COMPLETED"
    assert completed.json()["outcome"] == "UNSUPPORTED"
    assert completed.json()["reason"] == SECURITY_ENGINE_NOT_IMPLEMENTED
    replay = client.post(f"{base}/complete", headers=headers(tokens, "worker"), json=body)
    assert replay.json() == completed.json()
    assert (
        client.post(f"{base}/heartbeat", headers=headers(tokens, "worker"), json=body).status_code
        == 409
    )
    assert client.post("/v1/workers/jobs/claim", headers=headers(tokens, "worker")).json() == {
        "job": None
    }
    case = client.get(f"/v1/cases/{case_id}", headers=headers(tokens)).json()
    assert case["state"] == "NEEDS_EVIDENCE"
    assert case["reason"] == SECURITY_ENGINE_NOT_IMPLEMENTED
    events = client.get(f"/v1/cases/{case_id}/timeline", headers=headers(tokens)).json()["items"]
    assert [e["action"] for e in events] == [
        "CASE_CREATED",
        "INVESTIGATION_REQUESTED",
        "JOB_CLAIMED",
        "JOB_HEARTBEAT",
        "JOB_COMPLETED",
    ]
    assert [e["sequence"] for e in events] == sorted(e["sequence"] for e in events)
    assert tokens["worker"] not in str(events)
    assert claim["lease_id"] not in str(events)


def test_expired_lease_is_reclaimable_and_fences_the_same_workers_old_attempt(api):
    client, app, tokens = api
    case_id = new_case(client, tokens)
    job = new_job(client, tokens, case_id)
    first = client.post("/v1/workers/jobs/claim", headers=headers(tokens, "worker")).json()["job"]
    with app.state.session_factory.begin() as session:
        session.execute(
            update(Job)
            .where(Job.job_id == job["job_id"])
            .values(lease_expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
    for action in ("heartbeat", "complete"):
        assert (
            client.post(
                f"/v1/workers/jobs/{job['job_id']}/{action}",
                headers=headers(tokens, "worker"),
                json={"lease_id": first["lease_id"]},
            ).status_code
            == 409
        )
    second = client.post("/v1/workers/jobs/claim", headers=headers(tokens, "worker")).json()["job"]
    assert second["attempts"] == 2
    assert second["lease_id"] != first["lease_id"]
    assert (
        client.post(
            f"/v1/workers/jobs/{job['job_id']}/complete",
            headers=headers(tokens, "worker"),
            json={"lease_id": first["lease_id"]},
        ).status_code
        == 409
    )
    assert (
        client.post(
            f"/v1/workers/jobs/{job['job_id']}/complete",
            headers=headers(tokens, "worker"),
            json={"lease_id": second["lease_id"]},
        ).status_code
        == 200
    )


def test_revoked_worker_cannot_heartbeat_or_complete(api):
    client, app, tokens = api
    job = new_job(client, tokens, new_case(client, tokens))
    lease = client.post("/v1/workers/jobs/claim", headers=headers(tokens, "worker")).json()["job"]
    with app.state.session_factory.begin() as session:
        session.execute(
            update(AuthToken)
            .where(AuthToken.token_hash == hash_token(tokens["worker"]))
            .values(revoked_at=datetime.now(UTC))
        )
    for action in ("heartbeat", "complete"):
        assert (
            client.post(
                f"/v1/workers/jobs/{job['job_id']}/{action}",
                headers=headers(tokens, "worker"),
                json={"lease_id": lease["lease_id"]},
            ).status_code
            == 401
        )


def test_persistence_constraints_prevent_false_case_or_job_outcomes(api):
    client, app, tokens = api
    case_id = new_case(client, tokens)
    job = new_job(client, tokens, case_id)
    for statement in (
        update(Case).where(Case.case_id == case_id).values(state="LAB_APPROVED"),
        update(Job).where(Job.job_id == job["job_id"]).values(status="LEASED"),
        update(Job)
        .where(Job.job_id == job["job_id"])
        .values(
            status="COMPLETED",
            completed_at=datetime.now(UTC),
            outcome=None,
        ),
        update(Job)
        .where(Job.job_id == job["job_id"])
        .values(
            status="COMPLETED",
            completed_at=datetime.now(UTC),
            outcome="PASS",
        ),
    ):
        with pytest.raises(DBAPIError):
            with app.state.session_factory.begin() as session:
                session.execute(statement)


def test_errors_are_consistent_and_never_echo_secrets(api, caplog):
    client, _app, tokens = api
    caplog.set_level(logging.INFO, logger="counterseal.request")
    response = client.post(
        "/v1/cases?password=query-secret",
        headers=headers(tokens),
        json={"title": "", "token": "body-secret"},
    )
    assert response.status_code == 422
    assert response.json() == {
        "error": {"code": "VALIDATION_ERROR", "message": "Request validation failed."}
    }
    assert client.get("/not-a-route").json()["error"]["code"] == "HTTP_404"
    assert (
        client.post("/v1/cases", headers=headers(tokens), content=b'{"title":').status_code == 422
    )
    assert client.get("/v1/cases/not-a-uuid", headers=headers(tokens)).status_code == 422
    assert (
        client.post(
            "/v1/workers/jobs/claim", headers=headers(tokens, "worker"), json={"lease_seconds": 301}
        ).status_code
        == 422
    )
    assert (
        client.post(
            f"/v1/workers/jobs/{uuid4()}/complete",
            headers=headers(tokens, "worker"),
            json={"lease_id": str(uuid4())},
        ).status_code
        == 404
    )
    logged = " ".join(str(r.__dict__) for r in caplog.records if r.name == "counterseal.request")
    assert logged
    for secret in ("query-secret", "body-secret", tokens["analyst"]):
        assert secret not in response.text
        assert secret not in logged


def test_audit_events_reject_orm_and_raw_sql_update_delete(api):
    client, app, tokens = api
    new_case(client, tokens)
    for statement in (
        update(AuditEvent).values(actor="local-admin"),
        delete(AuditEvent),
        text("UPDATE audit_events SET action = 'FORGED'"),
        text("DELETE FROM audit_events"),
    ):
        with pytest.raises(DBAPIError):
            with app.state.session_factory.begin() as session:
                session.execute(statement)
    with app.state.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(AuditEvent)) == 1


def test_case_and_job_audit_writes_are_atomic(api, monkeypatch):
    client, app, tokens = api
    case_id = new_case(client, tokens)

    def fail_audit(*args, **kwargs):
        raise OperationalError("sensitive SQL", {}, Exception("database-password"))

    monkeypatch.setattr(ControlPlaneRepository, "audit", fail_audit)
    failed_case = client.post("/v1/cases", headers=headers(tokens), json={"title": "rolled back"})
    failed_job = client.post(
        f"/v1/cases/{case_id}/investigations",
        headers=headers(tokens),
        json={"idempotency_key": "rolled-back"},
    )
    assert failed_case.status_code == failed_job.status_code == 503
    assert "database-password" not in failed_job.text
    with app.state.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(Case)) == 1
        assert session.scalar(select(func.count()).select_from(Job)) == 0
        assert session.scalar(select(func.count()).select_from(AuditEvent)) == 1


def test_readiness_checks_configured_database_and_hides_connection_failures(api, monkeypatch):
    client, app, _tokens = api
    assert client.get("/readyz").json() == {"status": "ready"}

    def broken_connect():
        raise OperationalError(
            "SELECT secret", {}, Exception("postgresql://user:password@private-host/db")
        )

    monkeypatch.setattr(app.state.engine, "connect", broken_connect)
    failed = client.get("/readyz")
    assert failed.status_code == 503
    assert failed.json() == {
        "error": {"code": "DATABASE_UNAVAILABLE", "message": "Database is unavailable."}
    }
    assert "password" not in failed.text
    assert client.get("/healthz").json() == {"status": "ok"}


def test_readiness_rejects_unmigrated_or_unopenable_database(tmp_path):
    for path in (
        tmp_path / "missing-schema.db",
        tmp_path / "nonexistent-directory" / "unopenable.db",
    ):
        with TestClient(
            create_app(Settings(environment="test", database_url=f"sqlite:///{path}"))
        ) as client:
            assert client.get("/readyz").status_code == 503
            assert client.get("/healthz").status_code == 200


def test_migration_preserves_legacy_tokens_and_matches_models(tmp_path):
    engine = create_database_engine(f"sqlite:///{tmp_path / 'upgrade.db'}")
    now = datetime.now(UTC)
    with engine.begin() as connection:
        cfg = migration_config(connection)
        command.upgrade(cfg, "0001_initial_auth_tokens")
        connection.execute(
            text(
                "INSERT INTO auth_tokens (token_id, token_hash, subject, role, issued_at, expires_at) "
                "VALUES (:id, :hash, :subject, 'operator', :issued, :expires)"
            ),
            {
                "id": str(uuid4()),
                "hash": hash_token("synthetic-legacy-token"),
                "subject": "legacy-local",
                "issued": now.isoformat(" "),
                "expires": (now + timedelta(hours=1)).isoformat(" "),
            },
        )
        command.upgrade(cfg, "head")
        assert {"users", "auth_tokens", "cases", "audit_events", "jobs"} <= set(
            inspect(connection).get_table_names()
        )
        assert compare_metadata(MigrationContext.configure(connection), Base.metadata) == []
    with create_session_factory(engine)() as session:
        assert TokenRepository(session).authenticate("synthetic-legacy-token").role is Role.ANALYST
        assert session.get(User, "legacy-local") is not None
    with engine.begin() as connection:
        command.downgrade(migration_config(connection), "base")
        assert set(inspect(connection).get_table_names()) == {"alembic_version"}
    engine.dispose()


def test_postgresql_migration_compiles_offline(monkeypatch):
    from counterseal.backend.settings import get_settings

    get_settings.cache_clear()
    monkeypatch.setenv("COUNTERSEAL_DATABASE_URL", "postgresql://localhost/counterseal")
    output = StringIO()
    cfg = migration_config()
    cfg.output_buffer = output
    try:
        command.upgrade(cfg, "head", sql=True)
    finally:
        get_settings.cache_clear()
    sql = output.getvalue()
    assert "CREATE TABLE jobs" in sql
    assert "FOREIGN KEY(subject) REFERENCES users" in sql
    assert "BEFORE UPDATE OR DELETE OR TRUNCATE" in sql
    assert "counterseal_audit_append_only" in sql


def test_cli_prints_one_random_token_and_persists_only_its_hash(api, monkeypatch, capsys):
    _client, app, _tokens = api
    monkeypatch.setenv("COUNTERSEAL_ENVIRONMENT", "development")
    monkeypatch.setenv("COUNTERSEAL_DATABASE_URL", app.state.settings.database_url)
    monkeypatch.setenv("COUNTERSEAL_TOKEN_HASH_SECRET", "local-pepper")
    assert main(["init-token", "--subject", "local-cli", "--role", "admin"]) == 0
    captured = capsys.readouterr()
    token = captured.out.strip()
    assert len(token) >= 43
    assert captured.out == token + "\n"
    assert token not in captured.err
    assert "local-development" in captured.err.lower()
    with app.state.session_factory() as session:
        row = session.scalar(select(AuthToken).where(AuthToken.subject == "local-cli"))
        assert row.token_hash == hash_token(token, secret="local-pepper")
        assert token not in repr(row.__dict__)
        assert (
            TokenRepository(session, hash_secret="local-pepper").authenticate(token).role
            is Role.ADMIN
        )
    assert "local-pepper" not in captured.out + captured.err


def test_cli_failure_does_not_print_token_or_database_url(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("COUNTERSEAL_ENVIRONMENT", "development")
    monkeypatch.setenv("COUNTERSEAL_DATABASE_URL", f"sqlite:///{tmp_path / 'not-migrated.db'}")
    assert main(["init-token", "--subject", "local-cli"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "not-migrated.db" not in captured.err
    monkeypatch.setenv("COUNTERSEAL_ENVIRONMENT", "staging")
    assert main(["init-token", "--subject", "local-cli"]) == 1
    assert capsys.readouterr().out == ""


def test_worker_role_has_no_human_authority_and_clear_token_is_not_in_repr(api):
    _client, app, _tokens = api
    assert not Principal(subject="worker", role=Role.WORKER).has_role(Role.VIEWER)
    assert not Principal(subject="admin", role=Role.ADMIN).has_role(Role.WORKER)
    with app.state.session_factory.begin() as session:
        issued = TokenRepository(session).issue(
            subject="repr-test", role=Role.VIEWER, ttl=timedelta(minutes=1)
        )
        assert issued.token not in repr(issued)
