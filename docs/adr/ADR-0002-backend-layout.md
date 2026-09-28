# ADR-0002: Compact Phase 1 backend layout

- **Status:** Accepted
- **Date:** 2026-09-28
- **Decision owners:** Counterseal maintainers
- **Related phase:** Phase 1 core

## Context

The Phase 1 control plane needs a small, reviewable HTTP and persistence
surface. A parallel application layout and a second migration tree would make
it unclear which code and schema are authoritative. SQLite is convenient for
isolated tests, while deployment requires PostgreSQL behavior and migrations.

The job transport also needs to exist before the security engine. A queue that
pretended to perform investigation would create a security claim without an
engine or evidence.

## Decision

1. Backend application code lives under `src/counterseal/backend`.
2. Database migrations live under `alembic`.
3. The repository will not add placeholder `apps/api` or `migrations`
   directories. New backend modules belong in the existing package structure;
   new schema revisions belong in `alembic/versions`.
4. PostgreSQL is the deployment database. SQLite is supported only as a test
   accelerator for isolated repository/app tests. A SQLite deployment is not a
   supported production or shared-environment topology.
5. Phase 1 exposes HTTP bearer authentication, local role checks, case metadata
   persistence, and a durable job transport. Investigation jobs are typed and
   idempotent, but they intentionally complete as:

   ```text
   outcome: UNSUPPORTED
   reason: SECURITY_ENGINE_NOT_IMPLEMENTED
   ```

   This is an explicit unsupported result, not a fake security engine.
6. The React case surface consumes the case contract. It may create and review
   case metadata, but it does not become a Kubernetes client or an application
   authority.

## Consequences

### Positive

- There is one discoverable backend package and one migration source of truth.
- PostgreSQL behavior is the deployment contract while tests can remain fast
  and isolated.
- Queue mechanics can be tested without overstating investigation capability.
- Case creation can be integrated before later evidence and engine phases.

### Negative

- SQLite-specific behavior must not be mistaken for PostgreSQL deployment
  verification.
- The queue can persist work but cannot produce validation until a later engine
  is implemented.
- The compact layout does not itself provide identity assurance, secret
  management, or production readiness.

## Phase 1 acceptance

The layout decision is satisfied when the implementation and tests demonstrate:

- bearer tokens are stored only as hashes and role checks protect routes;
- Alembic revisions create the supported PostgreSQL schema;
- case creation and reads are durable and auditable as metadata;
- idempotent job requests cannot create duplicate logical work;
- lease ownership and expiry prevent an arbitrary worker from completing a job;
- investigation completion remains typed `UNSUPPORTED`; and
- no absent engine is implied by API, UI, or documentation language.

The acceptance list is a gate, not a claim that a check was run. Actual results
belong in `docs/STATUS.md`.
