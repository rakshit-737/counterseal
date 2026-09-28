# Counterseal coding protocol

This file is repository-local guidance for human and AI-assisted development.
Counterseal is a research prototype for evidence-bound, fixture-scoped
Kubernetes RBAC remediation validation. It is not containment, production
safety, autonomous remediation, or an authorization replacement.

## Start with the boundary

1. Read `README.md`, `docs/STATUS.md`, and the relevant section of
   `docs/IMPLEMENTATION_PLAN.md` before changing behavior.
2. Inspect the implementation and tests that support the proposed claim. Treat
   unmentioned files and local edits as potentially intentional.
3. Identify the active phase and the smallest change that satisfies its
   acceptance criteria. Do not implement a later phase because a future
   interface is already described.
4. Separate observed behavior, design decisions, assumptions, and planned
   work in code and documentation.
5. If a precondition is missing or a result cannot be reproduced, fail closed
   with an explicit unsupported, stale, inconclusive, abstained, or failed
   outcome.

## Active phase boundary

The current implementation work stops at Phase 0/Phase 1:

- HTTP bearer authentication and role checks;
- SQLAlchemy persistence and Alembic migrations;
- PostgreSQL deployment support, with SQLite only as a test accelerator;
- durable idempotent job transport with leases and explicit unsupported
  completion; and
- React case creation against the case contract.

The security engine, host collector, rehearsal runner, evidence bundle path,
and human local applier are later boundaries. Do not simulate them with a
status label, a model field, a queued job, or a placeholder command.

## Design constraints

- V1 is limited to an explicitly selected developer-owned local kind cluster.
- Collection is host-side and read-only; it must preserve target/context
  identity and must not use an ambient or remote context by default.
- The only intended editable object is a dedicated namespaced `Role`.
- Intended candidate edits are removing secret access, removing `list`/`watch`,
  and restricting a named `get` using `resourceNames`.
- Never change bindings, widen permissions, edit cluster-scoped roles, or accept
  arbitrary manifests in the V1 remediation path.
- The rehearsal runner is a separate trusted host process and is not the
  applier. Any later application is human-initiated and local.
- Models, AI output, digests, approvals, and public status values do not grant
  authority. Authority comes from an explicit human action and the separately
  enforced local boundary.
- Use RFC 8785 canonicalization for evidence-bound digest material. Explain
  what is covered and do not present a digest as authenticity or authorization.
- Keep workflow state distinct from report status. `FIXTURE_VALIDATED` always
  carries the phrase `NOT PRODUCTION ASSURANCE` in user-facing reporting.

## Persistence and transport

- Keep backend code under `src/counterseal/backend` and migrations under
  `alembic`; do not create parallel `apps/api` or `migrations` layouts.
- PostgreSQL is the deployment database. SQLite is allowed only for isolated
  test acceleration and must not be described as the deployment path.
- Database-backed jobs are transport. Until the engine exists, investigation
  jobs must remain typed `UNSUPPORTED` with
  `SECURITY_ENGINE_NOT_IMPLEMENTED`.
- Preserve idempotency, lease ownership, expiry, and append-only metadata
  invariants when changing repositories or migrations.

## Safety and evidence

- Never use production, shared, or remote clusters for development examples or
  tests. Use synthetic data or an explicitly owned local fixture.
- Never request, copy, persist, or publish bearer tokens, kubeconfigs, private
  keys, credentials, or personal data. Logs must not contain secrets.
- Do not add a mutation-capable Kubernetes client to a collector or rehearsal
  runner. A field named `dry_run`, `approval`, `rollback`, or `reversible` is
  not enforcement by itself.
- Remember that RBAC grants are additive. Removing one Role rule cannot prove
  that another binding grants no access; preserve uncertainty.
- Treat a passing fixture check as a bounded observation. It is not proof of
  production safety, containment, compliance, or correctness of workload
  behavior.

## Verification and documentation

- Run the narrowest meaningful checks for each code change, then record the
  actual command and result in `docs/STATUS.md` through the project’s status
  owner. Never infer a passing result from a command that was not run.
- Update docs when routes, schemas, persistence, phase boundaries, or status
  vocabulary change. Link claims to the exact supporting file.
- Use exact dates for retrieved references and verification records.
- Keep diagrams explicit about current versus planned components.
- Do not add benchmark, first-in-field, production-readiness, or security
  review claims without evidence and an approved record.

## Change review checklist

Before handing off a change:

- identify the active phase and acceptance criterion;
- list changed files and any migration or API compatibility effect;
- inspect for accidental target widening, binding changes, or secret logging;
- verify unsupported paths remain unsupported;
- run and report applicable checks, or state `not run`;
- re-read affected docs for stale paths and claims; and
- note blockers instead of working around them silently.
