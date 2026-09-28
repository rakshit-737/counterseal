# Counterseal status

**Checkpoint:** Phase 1 core control-plane slice
**Date:** 2026-09-28
**Overall status:** `in_progress`

This is a development checkpoint, not a release, security certification, or
production-readiness assessment. Counterseal's Kubernetes security engine,
collector, rehearsal runner, evidence bundle verifier, and local applier are
not implemented.

## Implemented in this checkpoint

- Phase 0 domain contracts under `src/counterseal/domain/`:
  - distinct workflow states and public evidence statuses;
  - closed Pydantic schemas for RBAC observations, claims, plans, rehearsal
    records, approvals, receipts, and assurance envelopes;
  - RFC 8785-backed bounded canonicalization and SHA-256 content digests;
  - dedicated namespaced `Role` narrowing grammar only;
  - fail-closed workflow adjacency guards that do not grant authority.
- Phase 0 architecture, threat model, scope ADRs, related-work notes, and
  governance/security documents.
- Phase 1 backend under `src/counterseal/backend/`:
  - FastAPI health/readiness endpoints;
  - hash-only bearer token storage and role checks;
  - SQLAlchemy models and Alembic revisions for users, tokens, cases,
    append-only metadata audit rows, and leased jobs;
  - authenticated case metadata CRUD;
  - idempotent investigation-job enqueueing;
  - worker-only lease claim/heartbeat/complete endpoints;
  - explicit `UNSUPPORTED` / `SECURITY_ENGINE_NOT_IMPLEMENTED` completion.
- Phase 1 web shell under `apps/web/`:
  - in-memory token entry (no browser storage);
  - same-origin API client;
  - case list/create/detail/timeline states;
  - accessible loading, empty, unauthorized, forbidden, error, and dialog
    states;
  - no fabricated evidence or security outcomes.
- Local Compose stack for PostgreSQL, migrations, API, transport worker, and
  Nginx-served web assets. Generated secrets live below ignored `.local/`.

## Verification record

The following checks were run in the local workspace. Results are recorded as
observations about this codebase only:

| Check | Result |
| --- | --- |
| `uv sync --python 3.12 --extra test` | Passed; resolved and installed the locked environment |
| `uv run --locked --extra test pytest -q` | **73 passed**; 28 non-failing dependency/config deprecation warnings |
| `uv run --locked --extra test ruff check src tests scripts` | **Passed** after lead quality fixes |
| `uv run --locked --extra test ruff format --check src tests scripts` | **Passed** after formatting the Python tree |
| `uv run --locked --extra test mypy` | **Passed**; no issues in 23 source files |
| `npm test -- --run` | **15 passed** across 3 files |
| `npm run typecheck` | Passed |
| `npm run build` | Passed; Vite production bundle generated |
| `npm run e2e` | **2 passed**; route-mocked UI-only tests, not backend integration |
| `docker compose --env-file .local/compose.env config --quiet` | Passed after local bootstrap |
| Windows `python scripts/bootstrap.py` | Passed; built images, migrated PostgreSQL, created ignored local secrets, and started services |
| Live HTTP/PostgreSQL/worker smoke | Passed: `/healthz` 200, `/readyz` 200, analyst `/v1/me`, case create, unsupported job enqueue, worker timeline completion |
| `uv run --locked --extra test pip-audit --skip-editable` | Passed; no known vulnerabilities reported; local editable package skipped |
| GitHub Actions CI for `d42dd57` | **Passed**: Python quality/tests, web quality/tests, and dependency audit; runner emitted only action-runtime/Ubuntu migration warnings |
| kind/RBAC integration | Not run; no Counterseal collector or engine exists |
| Benchmark/evaluation | Not run |
| Independent security audit | Not performed |

The warning-producing tests still passed. They do not establish production
safety, database availability, workload preservation, or Kubernetes behavior.

## Current blockers and limitations

1. The live Compose/PostgreSQL path requires Docker and generated local secrets;
   it has not yet been independently re-run as the lead checkpoint.
2. No Kubernetes client, audit collector, RBAC analyzer, deterministic
   candidate engine, real rehearsal, evidence bundle, approval consumer, or
   local applier exists.
3. Phase 1's SQLite path is a test accelerator only. PostgreSQL is the
   deployment database and requires a migration run before readiness succeeds.
4. Token bootstrap is a local-development identity foundation, not an external
   identity provider or Kubernetes credential.
5. Audit append-only triggers are database-boundary controls. A privileged
   database owner can bypass or replace the database and remains a trust
   assumption.
6. No claim of `FIXTURE_VALIDATED` is produced by the current Phase 1 API or
   UI. That public status is reserved for the later evidence-backed fixture
   path and must display **NOT PRODUCTION ASSURANCE**.

## Next smallest safe slice

Implement Phase 2's deterministic offline engine against synthetic RBAC
fixtures: normalize metadata-only audit events, build a snapshot-scoped
permission graph, verify typed claims, compile only the three allowed
namespaced-Role narrowing transformations, and emit explicit unsupported or
inconclusive results when visibility is incomplete. Add tests before any live
kind or model integration.
