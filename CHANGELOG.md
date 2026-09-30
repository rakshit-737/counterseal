# Changelog

All notable project changes are recorded here. This file describes repository
history; it does not certify a release or a security property.

## Unreleased

### Added

- Phase 0 architecture documentation for evidence-bound, fixture-scoped local
  kind RBAC remediation validation.
- Phase 1 control-plane documentation for HTTP authentication, SQLAlchemy and
  Alembic persistence, PostgreSQL deployment, SQLite test acceleration, durable
  job transport, and React case creation.
- Phase 2 offline engine for metadata-only audit normalization, additive
  snapshot-scoped RBAC analysis, typed-claim verification, and the bounded
  namespaced-`Role` candidate compiler.
- ADR-0002 for the compact `src/counterseal/backend` and `alembic` layout.
- ADR-0003 for the offline deterministic engine boundary.
- Primary-source related-work notes covering Kubernetes RBAC, authorization,
  audit, `kubectl auth can-i`, kind, and RFC 8785.
- Security, contribution, conduct, governance, and attribution guidance.

### Explicit limitations

- The deterministic engine is offline and fixture-driven; it is not connected
  to a Kubernetes collector, rehearsal runner, or control-plane job.
- Investigation jobs remain `UNSUPPORTED` with
  `SECURITY_ENGINE_NOT_IMPLEMENTED`.
- No host collector, real rehearsal runner, AI authority, evidence bundle, or
  local applier is available in the Phase 0–2 boundary.
- `FIXTURE_VALIDATED` means bounded fixture evidence and is **NOT PRODUCTION
  ASSURANCE**.

Verification results belong in [`docs/STATUS.md`](docs/STATUS.md), not in this
summary.
