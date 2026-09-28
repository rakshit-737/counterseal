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
- ADR-0002 for the compact `src/counterseal/backend` and `alembic` layout.
- Primary-source related-work notes covering Kubernetes RBAC, authorization,
  audit, `kubectl auth can-i`, kind, and RFC 8785.
- Security, contribution, conduct, governance, and attribution guidance.

### Explicit limitations

- The deterministic security engine is not implemented.
- Investigation jobs remain `UNSUPPORTED` with
  `SECURITY_ENGINE_NOT_IMPLEMENTED`.
- No host collector, real rehearsal runner, AI authority, or local applier is
  available in the Phase 0/1 boundary.
- `FIXTURE_VALIDATED` means bounded fixture evidence and is **NOT PRODUCTION
  ASSURANCE**.

Verification results belong in [`docs/STATUS.md`](docs/STATUS.md), not in this
summary.
