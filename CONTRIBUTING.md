# Contributing to Counterseal

Counterseal welcomes focused contributions that improve evidence-bound,
fixture-scoped Kubernetes RBAC remediation validation. The project is a
research prototype. Read [`README.md`](README.md), [`CLAUDE.md`](CLAUDE.md),
the [implementation plan](docs/IMPLEMENTATION_PLAN.md), and the
[threat model](docs/threat-model/THREAT_MODEL.md) before coding.

## Before opening a change

1. Identify the phase and acceptance criterion in
   `docs/IMPLEMENTATION_PLAN.md`.
2. Read the relevant ADR and inspect the code/tests that support the change.
3. Describe the intended scope, assumptions, and failure outcome.
4. Use synthetic data or an explicitly owned local fixture. Never include
   credentials, kubeconfigs, tokens, private keys, or personal data.

## Scope rules

- The active work is the offline portion of Phase 2: HTTP auth and persistence,
  metadata-only audit normalization, snapshot-scoped RBAC analysis, typed
  claims, and deterministic Role-only candidate compilation. The control-plane
  investigation job remains an unsupported transport boundary.
- SQLite is a test accelerator only; PostgreSQL is the deployment database.
- The Kubernetes collector, rehearsal runner, AI assistance, bundles, and
  human applier belong to later phases and must not be implied by a placeholder.
- The planned V1 candidate scope is a dedicated namespaced Role: remove secret
  access, remove `list`/`watch`, or restrict a named `get`. Do not change
  bindings, widen permissions, or accept generic manifests.
- Models, UI state, approvals, and digests do not grant authority.

## Code and documentation changes

- Keep backend code under `src/counterseal/backend` and migrations under
  `alembic`.
- Preserve API, database, lease, idempotency, and append-only invariants.
- Use RFC 8785 canonicalization for evidence-bound engine material, and do not
  present its digest as authenticity or authority.
- Mark planned behavior as planned and unsupported behavior as unsupported.
- Keep public report status separate from workflow state; display
  `FIXTURE_VALIDATED` with `NOT PRODUCTION ASSURANCE`.
- Update the threat model, ADRs, and operator documentation when a boundary
  changes.

## Verification

Run the narrowest relevant checks for the change, including migration and API
tests where applicable. Record the exact commands and actual results; do not
claim a check that was not run. Integration checks must use a disposable,
developer-owned local fixture and must state their prerequisites. Do not make
benchmark, priority, production-readiness, or security-review claims without
an evidence-backed record.

## Review expectations

Reviewers should check phase alignment, target scoping, secret handling,
unsupported paths, migration compatibility, and stale documentation. Changes
that introduce remote/production access, autonomous mutation, binding edits,
permission widening, or generic manifest handling require an explicit scope
decision and are outside the current V1 boundary.

By contributing, you agree to follow the project [Code of Conduct](CODE_OF_CONDUCT.md)
and the reporting guidance in [`SECURITY.md`](SECURITY.md).
