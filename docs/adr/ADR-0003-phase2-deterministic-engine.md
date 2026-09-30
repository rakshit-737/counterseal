# ADR-0003: Offline deterministic Phase 2 engine

- **Status:** Accepted for the Phase 2 offline slice
- **Date:** 2026-09-30
- **Decision owners:** Counterseal maintainers
- **Related phases:** Phase 2 deterministic engine, Phase 3 real rehearsal

## Context

The Phase 1 control plane deliberately transports investigation jobs without
claiming that a Kubernetes object was observed. The next safe slice needs to
exercise the RBAC question without acquiring cluster credentials, reading
Secret bodies, or making a mutation path appear to exist.

Kubernetes RBAC is additive. A namespaced `Role` rule cannot be evaluated in
isolation when another binding, group, or cross-namespace ServiceAccount
subject may grant the same access. Audit input also contains fields that must
not enter a retained artifact, including request/response bodies and
credentials.

## Decision

1. Phase 2 is a pure offline library. It accepts bounded, already-decoded
   metadata and typed fixture records. It has no Kubernetes client, network,
   subprocess, model, approval consumer, or applier.
2. Audit normalization retains only the selected identity, operation, object
   reference, timestamps, response code, and explicit status/reason. Known
   irrelevant metadata is bounded and discarded; body-bearing or unknown
   fields fail closed without echoing their values. Repeated stages are
   deduplicated only when their retained projections are identical.
3. RBAC analysis computes additive read-only permissions from one snapshot.
   A `RoleBinding` namespace is the permission namespace, independent of the
   namespace of its ServiceAccount subject. Cluster-wide binding results use an
   explicit target namespace or the analyzed account namespace. Incomplete,
   unknown, wildcard, aggregated, unsupported, and ambiguous shapes cannot
   produce a definitive request denial or grant.
4. Typed claims are checked against the supplied snapshot, source, evidence
   IDs, and metadata object digests. A narrative string, a bare boolean fact,
   or a fabricated evidence identifier is not sufficient. This is provenance
   binding, not independent source authentication or authorization.
5. Candidate compilation accepts only a dedicated namespaced `Role` snapshot
   and emits typed rule deltas for exactly these transformations:
   removing all Secret access, removing `list`/`watch`, or restricting a named
   `get`. Binding edits, widening, arbitrary manifests, wildcard rules, and
   incomplete alternative-grant visibility are rejected or inconclusive.
   Every eligible result is `CANDIDATE_ONLY` and has
   `approval_eligible=False`.
6. RFC 8785 canonicalization and SHA-256 digests cover the typed artifact
   representation. Digests provide repeatability and change detection only;
   they are not signatures, freshness proofs, or authority.

## Consequences

- Synthetic tests can cover deterministic parsing, graph closure, claims, and
  candidate grammar without a cluster or credentials.
- The engine can expose potential wildcard access while returning
  `UNSUPPORTED`, avoiding a false definitive denial.
- A future collector and rehearsal runner must establish source authenticity,
  target locality, and actual Kubernetes behavior before any fixture result is
  presented as validation. The Phase 2 engine cannot produce
  `FIXTURE_VALIDATED` by itself.
- Cross-namespace and alternative grants may make a candidate inconclusive;
  this is intentional fail-closed behavior rather than an optimization to
  force a candidate.

## Rejected alternatives

- Parsing arbitrary YAML, JSON manifests, or shell commands: rejected because
  it widens the mutation surface and makes input bounds and authority unclear.
- Treating a model output, approval-shaped field, or digest as authorization:
  rejected by the domain and compiler boundaries.
- Treating an omitted binding or an unsupported wildcard as proof of denial:
  rejected because RBAC is additive and the snapshot may be incomplete.
