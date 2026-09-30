# Counterseal status

**Checkpoint:** Phase 2 deterministic offline engine slice
**Date:** 2026-09-30
**Overall status:** `in_progress`

This is a development checkpoint, not a release, security certification, or
production-readiness assessment. The engine implemented here is offline and
fixture-driven; the Kubernetes collector, rehearsal runner, evidence bundle
verifier, approval consumer, and local applier are not implemented.

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
- Phase 2 offline engine under `src/counterseal/engine/`:
  - metadata-only, body-free Kubernetes audit normalization with bounded
    projection, stage deduplication, deterministic grouping, and contract
    violation detection;
  - additive, snapshot-scoped RBAC analysis for core `Secret`/`ConfigMap`
    read permissions, including direct subjects, Kubernetes ServiceAccount
    groups, RoleBinding-to-ClusterRole relationships, cross-namespace subject
    bindings, alternative grants, and evidence-linked graph records;
  - typed-claim verification bound to the supplied snapshot, source, evidence
    IDs, and metadata object digests; scalar facts without a source object are
    rejected;
  - fail-closed handling for incomplete/unknown snapshots, wildcard and
    aggregated rules, unsupported subresources, and ambiguous grants;
  - a closed policy gate and typed compiler for only the three namespaced
    `Role` narrowing transformations, with deterministic RFC 8785 digests;
  - a synthetic `CANDIDATE_ONLY` smoke demo at `make phase2-offline`.
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
| `uv run --locked --extra test pytest -q` | **127 passed**; 28 non-failing dependency/config deprecation warnings |
| `uv run --locked --extra test pytest tests/engine -q` | **54 passed**; offline Phase 2 unit, adversarial, and property coverage |
| `uv run --locked --extra test ruff check src tests scripts` | **Passed** |
| `uv run --locked --extra test ruff format --check src tests scripts` | **Passed**; 45 Python files checked |
| `uv run --locked --extra test mypy` | **Passed**; no issues in 29 source files |
| `uv run --locked --extra test python scripts/phase2_offline.py` | **Passed**; deterministic A/B/C output, all `CANDIDATE_ONLY` |
| `npm test -- --run` | **15 passed** across 3 files |
| `npm run typecheck` | Passed |
| `npm run build` | Passed; Vite production bundle generated |
| `npm run e2e` | **2 passed**; route-mocked UI-only tests, not backend integration |
| `docker compose --env-file .local/compose.env config --quiet` | Passed after local bootstrap |
| Windows `python scripts/bootstrap.py` | Passed; built images, migrated PostgreSQL, created ignored local secrets, and started services |
| Live HTTP/PostgreSQL/worker smoke | Passed: `/healthz` 200, `/readyz` 200, analyst `/v1/me`, case create, unsupported job enqueue, worker timeline completion |
| `uv run --locked --extra test pip-audit --skip-editable` | Passed; no known vulnerabilities reported; local editable package skipped |
| GitHub Actions CI for `d42dd57` | **Passed**: Python quality/tests, web quality/tests, and dependency audit; runner emitted only action-runtime/Ubuntu migration warnings |
| kind/RBAC integration | Not run; no collector or rehearsal runner exists; Phase 2 engine remains offline |
| Benchmark/evaluation | Not run |
| Independent security audit | Not performed |

The warning-producing tests still passed. They do not establish production
safety, database availability, workload preservation, or Kubernetes behavior.

## Current blockers and limitations

1. The live Compose/PostgreSQL path requires Docker and generated local secrets;
   it was verified once on this Windows host, but repeatability across hosts
   and operating systems remains unverified.
2. No Kubernetes client, audit collector, real rehearsal, evidence bundle,
   approval consumer, or local applier exists. The Phase 2 RBAC engine accepts
   only bounded caller-supplied fixtures and does not authenticate their source.
3. Phase 1's SQLite path is a test accelerator only. PostgreSQL is the
   deployment database and requires a migration run before readiness succeeds.
4. Token bootstrap is a local-development identity foundation, not an external
   identity provider or Kubernetes credential.
5. Audit append-only triggers are database-boundary controls. A privileged
   database owner can bypass or replace the database and remains a trust
   assumption.
6. No claim of `FIXTURE_VALIDATED` is produced by the current API, UI, or
   offline engine. That public status is reserved for the later
   evidence-backed fixture path and must display **NOT PRODUCTION ASSURANCE**.

## Next smallest safe slice

Implement Phase 3's read-only host collector and separate rehearsal runner for
an explicitly selected, developer-owned local kind fixture. Preserve the
Phase 2 offline boundary: wrong context, incomplete evidence, unsupported RBAC
shapes, stale identities, and failed probes must remain explicit abstentions or
unsupported outcomes. Add no applier or production/remote-cluster path.
