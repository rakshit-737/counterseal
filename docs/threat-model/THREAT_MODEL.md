# Counterseal threat model

**Status:** `in_progress` research baseline
**Date:** 2026-09-28
**Scope:** Phase 0 architecture and Phase 1 core control plane, plus the
explicitly bounded future V1 local-kind/RBAC validation path.

This model treats unimplemented components as absent controls. A type, field,
status, digest, diagram, or planned phase does not enforce a security property.
Counterseal is not containment, production safety, autonomous remediation, or a
replacement for Kubernetes authorization and audit controls.

## Security objectives

1. Keep every validation question bound to an explicitly identified local
   fixture, namespace, subject, resource, and verb scope.
2. Preserve provenance and integrity of observations, candidate diffs, reports,
   decisions, and receipts.
3. Prevent unsupported, stale, ambiguous, or unapproved material from becoming
   a Kubernetes change.
4. Keep collection read-only, rehearsal separate, and any later application
   human-initiated and local.
5. Make uncertainty and abstention visible instead of converting them to pass.
6. Avoid collecting, logging, or exporting credentials and sensitive evidence.

## Assets and trust boundaries

| Asset | Current representation | Required property | Boundary/status |
| --- | --- | --- | --- |
| Principal and bearer token | `backend/auth.py`, `AuthToken` | Authentication without clear-token persistence | Implemented Phase 1 hash-only path; local identity is not Kubernetes identity |
| Case metadata | `Case` and HTTP contracts | Durable ownership and explicit state | Implemented Phase 1; no evidence claim |
| Job transport state | `Job` and lease routes | Idempotency, ownership, expiry, replay-safe completion | Implemented transport; no engine result |
| Metadata audit rows | `AuditEvent`, Alembic triggers | Append-only record at DB boundary | Implemented where configured; DB owner remains trusted |
| RBAC observations | Planned evidence records | Provenance, target binding, canonical bytes | Planned Phase 3; no collector now |
| Candidate Role diff | Planned deterministic engine output | Exact scope, no widening, stable digest | Planned Phase 2; no engine now |
| Rehearsal verdict | Planned runner output | Read-only, repeatable, explicit reason | Planned Phase 3; no runner now |
| Approval/decision | Planned human record | Exact candidate binding, identity, expiry, separation | Planned; no approval authority now |
| Local application receipt | Planned export | Human action, target/version/digest binding | Planned Phase 6; no applier now |
| Credentials and sensitive data | Future adapters | Minimized, redacted, confidential | No live collector or secret boundary now |

Trust boundaries are explicit:

1. **HTTP client → control plane.** Requests may be malformed, replayed, or
   unauthenticated. Bearer authentication and role checks protect Phase 1
   routes, but local role identity does not authorize Kubernetes access.
2. **Control plane → database.** SQLAlchemy and migrations define schema and
   transactions. The database owner, host, and backups are trusted assumptions.
3. **Queue → worker.** A leased job is transport state. A worker cannot invent
   a validation result; the current contract is unsupported.
4. **Host → local kind target.** The future collector must prove explicit local
   context and read-only capability. Ambient kubeconfig context is not a safe
   target selector.
5. **Observation → derivation.** The future engine must preserve the difference
   between observed RBAC data and a derived candidate/determination.
6. **Engine → rehearsal runner.** The runner is a separate trusted host
   process. It consumes evidence and probes; it is not an applier.
7. **Human decision → local applier.** A later applier must require a human
   action tied to the exact candidate digest and current local target/version.
8. **Export → reviewer.** Bundles and reports can disclose sensitive content or
   be modified if transport/storage controls are weak.

## Implemented versus planned controls

| ID | Threat | Implemented in Phase 0/1 | Planned control | Residual risk |
| --- | --- | --- | --- | --- |
| T-01 | Unauthenticated or malformed HTTP request reaches a protected route | `HTTPBearer`, single authorization-header check, Pydantic closed contracts, role dependencies | External identity integration and deployment-specific policy review | Local token bootstrap and host remain trusted; no production identity claim |
| T-02 | Clear bearer token leaks through persistence or logs | Token repository persists a hash and metadata; request logger excludes request headers/body | Secret rotation, deployment secret policy, log access review | A token can still be exposed by a caller or host; no independent secret manager |
| T-03 | Duplicate job request creates contradictory work | Request fingerprint and `(requested_by, idempotency_key_hash)` uniqueness | Recovery/reconciliation and operational queue monitoring | DB owner can modify state; only investigation transport exists |
| T-04 | Arbitrary worker claims or completes another worker's job | Worker role, token identity, lease owner, lease ID, expiry predicates | Runner-specific credential boundary and worker isolation | Host/process compromise can bypass application assumptions |
| T-05 | Metadata audit history is changed or deleted | Database triggers reject update/delete/truncate for audit rows where installed | Independent append-only store, retention, access review, export verification | Privileged DB owner can disable/bypass controls, delete storage, or withhold history |
| T-06 | Unknown fields or inconsistent record shapes smuggle data into domain objects | Pydantic `extra="forbid"`, bounded fields, validators, explicit enums | End-to-end schema versioning and adversarial fixture coverage | Valid structure can carry false meaning; no source truth verification |
| T-07 | Changed evidence or candidate is accepted as unchanged | Domain digest helpers and explicit digest fields exist; queue fingerprints hash request material | RFC 8785 canonicalization for engine material, trusted digest references, stale rejection | Bare SHA-256 is not a signature, freshness proof, identity proof, or authorization |
| T-08 | A hash chain is treated as tamper-proof audit | No cryptographic hash chain is claimed in Phase 1; metadata append-only is separate | Chain exact event bytes with a trusted anchor and verify exports | A chain detects changes only relative to a trusted anchor; it cannot prevent deletion, replay, omission, key compromise, or DB-owner attacks |
| T-09 | Case creation or queue state is presented as RBAC validation | Case starts `NEEDS_EVIDENCE`; job result is typed `UNSUPPORTED` with `SECURITY_ENGINE_NOT_IMPLEMENTED` | Deterministic engine and evidence-backed report | UI/users may still misread labels; documentation must repeat the boundary |
| T-10 | Collector reaches the wrong or remote cluster | No collector exists, so no hidden cluster access is present | Explicit context input, positive local-kind check, read-only client, target identity evidence | Host kubeconfig, Docker/runtime, and locality detection remain trust assumptions |
| T-11 | RBAC candidate widens access or changes bindings | No candidate/applier exists | Role-only allow-list: remove secret access, remove list/watch, restrict named get; reject bindings/widening/generic manifests | RBAC is additive; other bindings may preserve access and require abstention |
| T-12 | `list`/`watch` or secret access exposes sensitive data | No Kubernetes collector or credentials are present | Read-only, least-privilege probes; avoid secret bodies; explicit redaction and resource-name constraints | Kubernetes authorization semantics and workload behavior remain outside this tool |
| T-13 | Rehearsal labelled dry-run mutates a fixture | No runner exists | Separate trusted host runner with read-only API capability and mutation-negative tests | Host/admin credentials and runtime integrity are not proven by Counterseal |
| T-14 | Stale approval authorizes changed target/diff | No approval path exists | Human approval binds exact RFC 8785 candidate digest, target/context, Role UID/version, expiry, and actor | Approval system and local host can still be compromised; no automatic revocation now |
| T-15 | Model output becomes operational authority | No model integration exists | Models receive no Kubernetes credentials/tools; outputs are suggestions with evidence links and cannot set status or applier input | A human may over-trust fluent text; UI must label model provenance |
| T-16 | Large/adversarial input exhausts resources | Scalar validation and bounded HTTP pagination exist | Collection, bundle, canonicalization, queue, and model budgets plus fuzz/property tests | Full resource budget and availability design are future work |
| T-17 | Sensitive evidence leaks through bundles, UI, or logs | Request logging is limited to route metadata; no collector/bundle exists | Redaction policy, secret-body exclusion, access controls, retention, export review | Future integrations may encounter sensitive data; no confidentiality guarantee now |
| T-18 | Dependency or host compromise changes behavior | Dependencies are declared and migrations are explicit | Provenance review, reproducible builds, security review, sandboxing of runner | No independent security review or production hardening is claimed |

## Approval assumptions

Approval is a future human decision, not an API role that automatically
authorizes a change. A valid future approval must be bound to the exact
canonical candidate digest, target/context identity, dedicated Role identity and
resource version, rehearsal evidence, actor identity, and expiry. The approval
service must verify those bindings at use time and reject stale or reused
decisions.

The current `approver` role and domain approval-shaped records must not be read
as an implemented approval gate. No Phase 1 endpoint applies a candidate, and
no approval can promote `SECURITY_ENGINE_NOT_IMPLEMENTED` to a validation
result.

## Trusted runner assumptions

The future rehearsal runner is intentionally separate from the control plane
and applier. The design assumes the host process, its executable, its local
fixture, and its read-only Kubernetes credentials are controlled by the human
operator. Counterseal does not currently attest the host, prevent a privileged
operator from replacing the runner, or establish that a local kind endpoint is
isolated from other host resources. Those are residual risks requiring explicit
review and evidence before a runner result is used.

## Hash chain limits

A chained metadata record can include the digest of the previous event and the
canonical digest of the current event. This can reveal an alteration or reorder
when a reviewer has a trusted starting anchor and the complete sequence. It does
not provide:

- authenticity without a trusted signing key or authenticated anchor;
- proof that an event was not omitted, replayed, or backdated;
- protection from a database owner who can rewrite the chain and anchor;
- availability, independent time, key custody, or confidentiality; or
- authorization to perform a Kubernetes action.

Phase 1's append-only metadata triggers and the domain's optional digest fields
are separate from a future signed audit-chain design.

## Public status decision rule

`FIXTURE_VALIDATED` may be reported only by a future evidence-backed fixture
path that meets its declared acceptance criteria. It must be shown with
**NOT PRODUCTION ASSURANCE**. `UNSUPPORTED`, `STALE`, `INCONCLUSIVE`,
`abstained`, or `failed` is the correct outcome when scope, identity, evidence,
integrity, or safety preconditions are missing.
