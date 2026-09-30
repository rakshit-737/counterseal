# Security policy

Counterseal is an early research prototype for evidence-bound, fixture-scoped
Kubernetes RBAC remediation validation. It is not a production security
control, containment system, autonomous remediator, or authorization service.

## Scope

The supported design boundary is an explicitly owned local kind fixture, a
host-side read-only collector, a separate trusted rehearsal runner, and a
human local applier for a narrow dedicated namespaced Role diff. The current
Phase 0–2 implementation includes only an offline deterministic engine over
bounded caller-supplied fixtures; it has no collector, rehearsal runner,
evidence bundle verifier, or applier. Investigation jobs are intentionally
`UNSUPPORTED` with `SECURITY_ENGINE_NOT_IMPLEMENTED`.

Do not test this project against production, shared, remote, or managed
clusters. Do not submit real credentials, kubeconfigs, tokens, private keys, or
personal data in issues, pull requests, logs, fixtures, or reports.

## Reporting a vulnerability

Do not disclose sensitive details in a public issue. Report privately to the
project maintainers through the repository hosting service or the private
security channel provided by the maintainers. Include:

- a concise description and impact;
- affected commit, component, or migration;
- reproducible steps using synthetic data or an owned local fixture;
- whether credentials or personal data may be exposed; and
- a minimal safe proof of concept, if one is necessary.

If no private channel is available, ask maintainers for one without including
the vulnerability details in a public thread. Do not probe systems that you do
not own or have explicit permission to test.

## Disclosure and fixes

Maintainers will acknowledge receipt when practical, assess scope and
reproducibility, and coordinate a fix or mitigation before public disclosure
when the issue affects users. A security review or production-readiness claim
must not be inferred from a fix or from a fixture result.

## Security expectations for contributors

- Preserve fail-closed behavior and explicit unsupported outcomes.
- Keep tokens hash-only and out of logs.
- Keep the collector read-only and the runner separate from any applier.
- Do not widen the local-kind, Role-only V1 scope without an ADR and threat
  model update.
- Treat models, status labels, approvals, and digests as non-authoritative
  data.
