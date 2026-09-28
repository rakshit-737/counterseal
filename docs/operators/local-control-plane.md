# Local control-plane guide

This guide runs the Phase 1 control plane only. It does **not** create a kind
cluster, collect Kubernetes evidence, evaluate RBAC, validate a candidate, or
apply a change. A queued investigation is deliberately completed as
`UNSUPPORTED` with `SECURITY_ENGINE_NOT_IMPLEMENTED`.

## Prerequisites

- Windows, macOS, or Linux development host.
- Python 3.12 and [uv](https://docs.astral.sh/uv/).
- Node.js/npm for the web checks.
- Docker Engine with Docker Compose v2 for the full local stack.

The Phase 1 stack does not require `kubectl` or `kind`. Never point it at a
production, shared, or remote cluster.

## Install and verify locally

From the repository root:

```text
uv sync --extra test
npm ci
uv run --locked --extra test pytest -q
npm test -- --run
npm run typecheck
npm run build
```

These commands use local code and test databases. They do not contact a
Kubernetes cluster.

## Start the disposable Compose stack

Bootstrap creates random local-development database/token material under the
ignored `.local/` directory. It refuses to overwrite an existing generated
secret and never prints secret contents:

```text
python scripts/bootstrap.py
```

The script builds the pinned local images, starts PostgreSQL, applies Alembic
migrations, creates an analyst token and a dedicated worker token, and starts
the API, transport worker, and web services.

Open:

```text
http://127.0.0.1:8080
```

The UI keeps the analyst bearer token in memory only. Read the one-time local
token from `.local/api.token` when signing in; do not paste it into chat,
issues, logs, screenshots, URLs, or source files. The worker token is read by
the worker process from `.local/worker.token` and is not a Kubernetes token.

The API is reachable from the host only through the web proxy by default. The
database is on the internal Compose network; the optional test override may
publish it to loopback port `15432`.

## Phase 1 API smoke path

After signing in, create a case with a title and description. The API stores
only case metadata and starts it in `NEEDS_EVIDENCE`. Requesting an
investigation creates one idempotent transport job. It does not run an
investigator and cannot produce a security result.

Useful routes:

```text
GET  /healthz
GET  /readyz
GET  /v1/me
GET  /v1/cases
POST /v1/cases
GET  /v1/cases/{case_id}
POST /v1/cases/{case_id}/investigations
GET  /v1/cases/{case_id}/timeline
POST /v1/workers/jobs/claim
POST /v1/workers/jobs/{job_id}/heartbeat
POST /v1/workers/jobs/{job_id}/complete
```

`/readyz` requires the migrated configured database. A `503` means the
dependency is unavailable or the schema has not been migrated; it is not a
security or validation result.

## Stop and reset

Stop services without deleting the database volume:

```text
docker compose --env-file .local/compose.env down
```

For a disposable reset, stop the stack and remove `.local/` plus the Compose
volume only after confirming that no local evidence or test data is needed.
Bootstrap intentionally refuses to overwrite existing local secret files, so a
reset is an explicit operator action rather than an automatic rotation.

## Not implemented yet

The following commands intentionally exit with a clear not-implemented
diagnostic until later phases:

```text
make demo
make test-kind
make verify-bundle
make eval-offline
```

Do not replace those diagnostics with canned results. The next safe slice is
the offline deterministic RBAC engine described in
`docs/IMPLEMENTATION_PLAN.md`.
