from __future__ import annotations

import logging
from json import loads
from uuid import UUID

from fastapi.testclient import TestClient

from counterseal.backend.app import create_app
from counterseal.backend.db import Base
from counterseal.backend.observability import JsonLogFormatter
from counterseal.backend.settings import Settings


def test_health_and_readiness_endpoints() -> None:
    app = create_app(Settings(environment="test", database_url="sqlite://"))
    Base.metadata.create_all(app.state.engine)
    client = TestClient(app)

    health = client.get("/healthz")
    ready = client.get("/readyz")

    assert health.status_code == 200
    assert health.json() == {"status": "ok"}
    assert ready.status_code == 200
    assert ready.json() == {"status": "ready"}


def test_correlation_id_is_returned_and_request_log_excludes_query_secret(
    caplog,
) -> None:
    client = TestClient(create_app(Settings(environment="test")))
    supplied_id = "2f8c4b3e-92b7-4ff5-9e71-6d8aa37f0e01"

    with caplog.at_level(logging.INFO, logger="counterseal.request"):
        response = client.get(
            "/healthz?access_token=do-not-log-this",
            headers={
                "X-Correlation-ID": supplied_id,
                "Authorization": "Bearer do-not-log-this-either",
            },
        )

    assert response.headers["X-Correlation-ID"] == supplied_id
    records = [record for record in caplog.records if record.name == "counterseal.request"]
    assert records
    payload = loads(JsonLogFormatter().format(records[-1]))
    assert payload["correlation_id"] == supplied_id
    assert payload["path"] == "/healthz"
    assert "do-not-log-this" not in str(payload)
    assert "do-not-log-this-either" not in str(payload)
    assert "authorization" not in str(payload).lower()
    assert "access_token" not in str(payload)


def test_invalid_correlation_id_is_replaced() -> None:
    client = TestClient(create_app(Settings(environment="test")))

    response = client.get("/healthz", headers={"X-Correlation-ID": "not-a-safe-id"})

    UUID(response.headers["X-Correlation-ID"])
