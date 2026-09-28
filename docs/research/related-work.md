# Initial related-work review

**Retrieved:** 2026-09-28  
**Method:** concise reading of primary project/specification documentation using
the project web fetch tool. This is a design input, not a survey, benchmark, or
claim of priority.

## Kubernetes RBAC and authorization

The Kubernetes RBAC reference describes `Role`, `ClusterRole`, `RoleBinding`,
and `ClusterRoleBinding`. Role permissions are additive; there are no deny
rules. A namespaced `RoleBinding` can bind a Role in its namespace or a
ClusterRole into that namespace, while a ClusterRoleBinding grants cluster-wide
scope. The reference also documents `resourceNames` for named-object
restriction and cautions that `list`/`watch` requests need a matching field
selector when resource names are used. Kubernetes authorization evaluates
request attributes including user, groups, API group, resource, subresource,
namespace, verb, and resource name; authorization happens before admission.

These semantics motivate Counterseal's narrow candidate grammar: edit only a
dedicated namespaced Role, remove secret access or `list`/`watch`, and restrict
a named `get`; do not alter bindings or widen permissions. They also require
Counterseal to treat a Role diff as insufficient evidence when another binding
may grant the same permission.

Sources:

- Kubernetes, **Using RBAC Authorization**:
  <https://kubernetes.io/docs/reference/access-authn-authz/rbac/> (retrieved
  2026-09-28).
- Kubernetes, **Authorization**:
  <https://kubernetes.io/docs/reference/access-authn-authz/authorization/>
  (retrieved 2026-09-28).

## Audit records

Kubernetes auditing is a chronological record of API activity. The official
documentation identifies request stages (`RequestReceived`, `ResponseStarted`,
`ResponseComplete`, and `Panic`) and policy levels including `Metadata`,
`Request`, and `RequestResponse`. A policy controls what is recorded and the
backend persists it; omitting an audit policy means events are not logged.

Counterseal therefore treats Kubernetes audit material as an input to a future
evidence path rather than as an automatic truth or safety signal. Audit records
must retain their source, policy context, capture time, and digest, and should
not be confused with Counterseal's local metadata audit rows.

Source:

- Kubernetes, **Auditing**:
  <https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/> (retrieved
  2026-09-28).

## Authorization probes and kind

The official `kubectl auth can-i` reference describes authorization checks using
the Kubernetes verb, type, namespace, and optional name. It also documents
impersonation flags, which require permission themselves. Counterseal can use a
bounded equivalent as future rehearsal evidence, but a `can-i` answer is an
observation for a declared identity and target; it is not permission for
Counterseal to apply a change.

The kind quick-start guide documents local cluster creation, named clusters,
their generated contexts, and interaction through kubectl. It also notes that
kind can use Docker, Podman, or nerdctl and that kubeconfig handling affects the
selected context. Counterseal's future collector must make the cluster/context
selection explicit and prove local ownership rather than inherit an ambient
context.

Sources:

- Kubernetes, **kubectl auth can-i**:
  <https://kubernetes.io/docs/reference/kubectl/generated/kubectl_auth/kubectl_auth_can-i/>
  (retrieved 2026-09-28).
- Kubernetes SIGs, **kind Quick Start**:
  <https://kind.sigs.k8s.io/docs/user/quick-start/> (retrieved 2026-09-28).

## Canonical evidence representation

RFC 8785 defines the JSON Canonicalization Scheme for repeatable JSON
serialization: no insignificant whitespace, deterministic recursive property
ordering, constrained JSON data, and UTF-8 output. It is a representation
scheme for hashing or signing, not a signature or identity system. Counterseal
requires RFC 8785 for Phase 2 evidence/candidate material so that digest
comparisons are reproducible, while keeping trust, freshness, and authorization
as separate controls.

Source:

- IETF, **RFC 8785: JSON Canonicalization Scheme**:
  <https://www.rfc-editor.org/rfc/rfc8785> (retrieved 2026-09-28).

## Design consequence for Counterseal

The primary sources support a layered boundary rather than a generic operator:
read-only host collection from an explicit local kind fixture, deterministic
Role-only candidate derivation, a separate trusted rehearsal runner, and a
human local applier. Current Phase 0/1 code stops before collection and engine
work; its queue records unsupported work instead of fabricating a validation
result.
