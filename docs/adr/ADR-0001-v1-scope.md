# ADR-0001: V1 fixture-scoped Kubernetes RBAC validation

- **Status:** Accepted scope decision; the offline Phase 2 engine is implemented
  and the cluster/rehearsal path remains planned.
- **Date:** 2026-09-28
- **Decision owners:** Counterseal maintainers
- **Related phases:** Phase 2 deterministic engine, Phase 3 real rehearsal,
  Phase 6 local application/export

## Context

Counterseal could become a general Kubernetes automation product, but that
would mix target selection, authorization, mutation, and evidence before the
research prototype has established a bounded validation path. Kubernetes RBAC
is additive, and a permission removed from one Role may still be granted by a
different binding. A validation result therefore needs an explicit subject,
namespace, resource, verb, target, and evidence boundary.

The intended experiment is narrower: validate a candidate remediation against a
developer-owned local kind cluster, with a read-only host collector, a separate
trusted rehearsal runner, and a human local applier. This is not containment,
production safety, or autonomous remediation.

## Decision

V1 will support only **fixture-scoped RBAC remediation validation for one
explicitly selected, developer-owned local kind cluster**.

### Target and collection

1. The caller must name the kind cluster and context. The validator must prove
   the selected context is local and owned for the run; it must not silently use
   an ambient current context or a remote/managed endpoint.
2. Collection is host-side and read-only. It may inspect the bounded RBAC
   observations needed for the declared question, including the relevant
   namespaced `Role`, binding relationships, and subject identity.
3. Evidence retains target/context identity, namespace, subject, API group,
   resource/subresource, verb, resource name where relevant, capture time, and
   content digest.
4. Authentication, discovery, locality checks, unsupported shapes, API errors,
   incomplete observations, or target mismatch produce `abstained` or `failed`,
   never an inferred pass.

### Candidate and rehearsal

1. The only editable object is a **dedicated namespaced `Role`**.
2. The only intended transformations are:
   - remove access to `secrets`;
   - remove `list` and `watch`; and
   - restrict a named `get` with `resourceNames`.
3. The validation path must not modify `RoleBinding`, `ClusterRoleBinding`,
   `ClusterRole`, `ServiceAccount`, or any unrelated resource. It must not
   widen permissions or accept a generic manifest.
4. A separate trusted host rehearsal runner compares bounded baseline and
   candidate permission probes. The runner is not an applier and has no
   autonomous mutation path.
5. A later human local applier, if implemented, must re-check the exact target,
   Role identity, resource version, and candidate digest before a local change.

RBAC's additive semantics are part of the result. Removing a rule from the
dedicated Role does not establish that every effective grant is gone when
other bindings exist. A result that cannot bound that possibility must remain
inconclusive or abstained.

## Non-goals

V1 does not include:

- production, shared, remote, managed, hosted, or cloud Kubernetes clusters;
- EKS, GKE, AKS, cloud IAM, workload identity, admission policy, network
  policy, Pod Security, service mesh, or non-RBAC authorization;
- credential discovery, token minting, impersonation, privilege escalation,
  break-glass access, or bypass of an authorization decision;
- autonomous remediation, containment, rollback guarantees, or production
  safety assurance;
- changes to bindings or cluster-scoped roles;
- permission widening, generic manifests, arbitrary resource mutation, or
  multi-cluster scans; or
- a claim that RBAC validation proves workload safety, data safety, or approval.

## Consequences

### Positive

- Target and operation scope are explicit and small.
- Read-only observation and rehearsal remain separate from application.
- Candidate behavior is deterministic and reviewable on fixtures.
- An abstention caused by additive grants or uncertain locality is visible
  rather than converted to a pass.

### Negative

- V1 cannot answer questions for production or remote clusters.
- A Role-only diff cannot remove access granted elsewhere.
- The host and trusted runner remain important operational assumptions.
- Local validation does not establish application correctness or safety.

## Acceptance criteria for future implementation

This ADR must not be marked implemented until the implementation has, at a
minimum:

- explicit target/context input and a positive local-kind check;
- a read-only collector boundary with no mutation-capable method exposed;
- deterministic fixtures for secret access, list/watch, named-get, binding
  ambiguity, and unsupported shapes;
- RFC 8785 canonical evidence and candidate digest checks;
- a separate rehearsal runner with pass/fail/abstain evidence;
- rejection tests for remote/wrong contexts, target drift, permission widening,
  binding edits, and generic manifests; and
- a human local applier whose accepted input is limited to the exact candidate
  digest and dedicated namespaced Role.

These are future acceptance criteria, not current test or integration results.
