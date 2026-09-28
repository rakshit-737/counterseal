# Governance

Counterseal is maintained as a research prototype. Governance exists to keep
scope, evidence, and safety claims reviewable; it does not grant the project
authority over any Kubernetes cluster.

## Maintainers

Maintainers are the people listed by the repository hosting service or named in
the current project records. They review changes, maintain the roadmap and
security policy, and make release decisions. No individual is implied by this
document until the project records name them.

## Decision process

1. Changes that alter scope, trust boundaries, public status, persistence
   semantics, or application behavior require an ADR or an update to the
   relevant ADR.
2. The implementation plan identifies phase ownership and acceptance criteria.
3. Reviewers require evidence for implementation and verification claims.
4. Uncertainty is recorded as unsupported, stale, inconclusive, abstained, or
   failed; it is not silently resolved by a model or a convenience default.
5. Maintainers seek review from at least one other contributor for security,
   target-selection, migration, and application-boundary changes when practical.

## Scope decisions

The V1 boundary is an explicitly owned local kind fixture, a host read-only
collector, a separate trusted rehearsal runner, and a human local applier for
a narrow dedicated namespaced Role diff. Binding changes, permission widening,
generic manifests, remote/managed clusters, containment, production safety,
and autonomous remediation require a new decision and are not implied by
existing code.

## Releases

Maintainers release only after the roadmap gates, security disposition,
documentation, migration compatibility, licensing, and reproducibility have
been reviewed. A release may still be a research release and must carry the
`NOT PRODUCTION ASSURANCE` qualifier where fixture validation is discussed.

## Conflicts and conduct

Participants should disclose material conflicts that affect a scope or release
decision. Conduct concerns and vulnerabilities use the private reporting paths
in [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) and [`SECURITY.md`](SECURITY.md).
