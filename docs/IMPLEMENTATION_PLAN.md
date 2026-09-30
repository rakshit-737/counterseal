# Counterseal implementation plan

**Plan status:** Phase 0, Phase 1, and the offline portion of Phase 2 are the
active implementation scope. Cluster collection and later phases remain
planned. This plan is a research roadmap, not a production capability
statement.

Counterseal validates a narrow, evidence-bound question around an explicitly
owned local kind fixture. It does not provide containment, production safety,
autonomous remediation, or a general Kubernetes manifest workflow.

## Non-negotiable vocabulary

- **Public report status** says what the evidence supports. The intended public
  result is `FIXTURE_VALIDATED` with the prominent qualifier **NOT PRODUCTION
  ASSURANCE**.
- **Workflow state** says where a case is in its process. It is not a report
  result and must not be used as one.
- **Unsupported** is a valid result. In Phase 1, every investigation job is
  transport-only and completes `UNSUPPORTED` with
  `SECURITY_ENGINE_NOT_IMPLEMENTED`.
- **A model is not an authority.** Pydantic records, AI output, digests,
  approvals, and UI state cannot grant a Kubernetes permission or initiate an
  application.

## Phase roadmap

### Phase 0 — Architecture

**Objective.** Establish the narrow V1 boundary, current/planned architecture,
status vocabulary, threat model, related-work record, and decision records.

**Files and surfaces.** `README.md`, `CLAUDE.md`, this plan,
`docs/architecture.md`, `docs/adr/ADR-0001-v1-scope.md`,
`docs/adr/ADR-0002-backend-layout.md`, `docs/threat-model/THREAT_MODEL.md`,
`docs/research/related-work.md`, and project governance/security documents.

**Dependencies.** Repository inspection; primary Kubernetes RBAC,
authorization, audit, `kubectl auth can-i`, kind, and RFC 8785 documentation.

**Acceptance.** The docs distinguish implemented and planned components; name
the local-kind/read-only-collector/trusted-runner/human-applier boundaries;
describe the Role-only candidate scope; state the public status qualifier; and
make no test, benchmark, integration, or production claim without a record.

**Stop boundary.** No cluster client, engine, rehearsal, AI, applier, or
production operation is introduced by architecture documentation.

### Phase 1 — Core *(implemented)*

**Objective.** Provide the local control-plane foundation: HTTP authentication,
case persistence, migration discipline, durable job transport, and React case
creation.

**Files and surfaces.** `src/counterseal/backend/**`, `alembic/**`, the Phase 1
tests, `pyproject.toml`, and the connected case UI under `apps/web/**`.

**Dependencies.** FastAPI, Pydantic, SQLAlchemy, PostgreSQL, Alembic, and the
React/Vite toolchain. PostgreSQL is the deployment database. SQLite is only a
test accelerator and is not a deployment recommendation.

**Acceptance.** Bearer tokens are verified without storing clear tokens; role
checks protect routes; Alembic can create the supported schema; case creation
and reads persist metadata; jobs have idempotency and lease ownership; audit
metadata is append-only at the database boundary; and investigation jobs
return typed `UNSUPPORTED` with `SECURITY_ENGINE_NOT_IMPLEMENTED`.

**Stop boundary.** No Phase 1 route may claim an evidence observation, RBAC
verdict, rehearsal result, candidate plan, or application receipt. The engine
is not implemented in this phase.

### Phase 2 — Deterministic engine *(active; offline slice implemented)*

**Objective.** Implement an offline, fixture-driven engine that canonicalizes
evidence and candidate material with RFC 8785, computes explicit digests, and
derives only the allowed namespaced-Role transformations.

**Files and surfaces.** Implemented `src/counterseal/engine/**` and focused
domain types under `src/counterseal/domain/**`; the synthetic offline smoke
entry point is `scripts/phase2_offline.py` and focused tests live under
`tests/engine/**`.

**Dependencies.** Phase 1 case/evidence contracts; Kubernetes RBAC semantics;
RFC 8785; fixture schemas and expected digests.

**Acceptance.** Repeated runs on the same fixture produce the same canonical
bytes, digests, diff ordering, and decision; secret access, list/watch removal,
and named-get restriction are the only candidate transformations; binding
changes, widening, generic manifests, unsupported shapes, and ambiguous
effective grants abstain or fail closed. The current implementation meets
this acceptance only for bounded caller-supplied offline records; it does not
authenticate their source or establish cluster behavior.

**Stop boundary.** The engine remains offline. It does not connect to a
cluster, rehearse a change, call a model, or apply a manifest.

### Phase 3 — Real rehearsal

**Objective.** Add the host read-only collector and the separate trusted host
rehearsal runner for an explicitly selected, developer-owned local kind cluster.

**Files and surfaces.** Planned `src/counterseal/collector/**`,
`src/counterseal/rehearsal/**`, `tools/rehearsal/**`, local-fixture
definitions, and integration tests that require an explicitly provisioned
disposable kind cluster.

**Dependencies.** Phase 2 deterministic engine; kind and kubectl tool
contracts; explicit context/locality checks; a documented host trust model.

**Acceptance.** The collector is read-only and records target/context identity,
RBAC observations, timestamps, and evidence digests. The runner is a separate
process with no applier path; it compares bounded baseline/candidate
permission probes and emits pass/fail/abstain with reasons. Wrong context,
remote context, API errors, unsupported RBAC shapes, or missing evidence do not
pass.

**Stop boundary.** No autonomous mutation, remote/managed cluster support, or
production claim. Rehearsal is evidence, not authorization.

### Phase 4 — Bundles and UI

**Objective.** Package evidence and reports for review, and make the case UI
show provenance, workflow state, public status, and the explicit disclaimer.

**Files and surfaces.** Planned `src/counterseal/bundles/**`,
`src/counterseal/export/**`, report schemas and API read models, plus
`apps/web/**` review views.

**Dependencies.** Phase 1 persistence; Phase 2 digests; Phase 3 collector and
rehearsal records.

**Acceptance.** Bundles have explicit entry membership and digests; imports
reject stale or mismatched material; UI labels `FIXTURE_VALIDATED` separately
from workflow state and displays **NOT PRODUCTION ASSURANCE**; secrets and
unredacted credentials are excluded.

**Stop boundary.** The UI cannot approve, apply, or widen a candidate. It is a
review surface, not an authority.

### Phase 5 — AI assistance

**Objective.** Offer optional model assistance for summarization, hypothesis
wording, and review prompts while preserving evidence links and human control.

**Files and surfaces.** Planned `src/counterseal/ai/**`, prompt/output schemas,
model policy documentation, and tests with deterministic stubs.

**Dependencies.** Phase 2 evidence graph and Phase 4 bundle/report contracts.

**Acceptance.** Every model output is labelled as a suggestion or derived
text, retains its evidence references, and cannot change target scope, status,
approval, queue ownership, rehearsal verdict, or applier input. Unsupported or
unavailable models degrade to an explicit non-AI path.

**Stop boundary.** Models have no Kubernetes credentials, no direct cluster
tools, no applier access, and no authority to turn uncertainty into pass.

### Phase 6 — Local application and export

**Objective.** Provide an explicit human local applier and exportable receipt
for a previously validated, digest-bound candidate.

**Files and surfaces.** Planned `src/counterseal/applier/**`,
`src/counterseal/export/**`, preflight/receipt schemas, a local applier CLI,
and `docs/operators/local-control-plane.md`.

**Dependencies.** Phase 3 rehearsal; Phase 4 bundles/UI; a human decision tied
to the exact candidate digest; target/context and Role identity checks.

**Acceptance.** Only a dedicated namespaced `Role` may be edited, and only by
the permitted transformations: remove secret access, remove `list`/`watch`,
or restrict a named `get`. Bindings are immutable to this path; widening,
cluster-scoped roles, generic manifests, unrelated resources, target drift,
and ambiguous grants are rejected. Application is human-initiated on the local
fixture, and the receipt includes the exact digest and result.

**Stop boundary.** No autonomous application, remote or production target,
containment promise, or generic Kubernetes executor.

### Phase 7 — Evaluation

**Objective.** Evaluate the bounded workflow on a declared fixture matrix,
including pass, fail, abstain, stale, unsupported, and target-mismatch cases.

**Files and surfaces.** Planned `evaluation/**`, fixture manifests/data,
reproducible evaluation scripts, and an evidence-backed evaluation report.

**Dependencies.** Completed Phase 2–6 paths and a declared evaluation
methodology.

**Acceptance.** Each result has inputs, tool versions, expected outcome, actual
outcome, and limitations. Claims are limited to the declared fixtures and
method; no “first” or benchmark claim is made without an approved methodology
and recorded run.

**Stop boundary.** Fixture evaluation cannot be represented as production
assurance or general Kubernetes safety.

### Phase 8 — Hardening

**Objective.** Review authentication, authorization, persistence, dependency
provenance, failure handling, resource limits, secret handling, and evidence
redaction.

**Files and surfaces.** Security review records, focused tests under
`tests/security/**`, dependency configuration, threat-model updates, and
hardening notes.

**Dependencies.** Evaluation findings and an updated threat model.

**Acceptance.** Known threats have owners and dispositions; failures remain
fail closed; tokens and credentials are minimized; migration and queue
recovery behavior is tested; and an independent review decision is recorded.

**Stop boundary.** Hardening does not create a production guarantee by itself.

### Phase 9 — Documentation

**Objective.** Align user, operator, developer, security, governance, and
research documentation with the verified implementation.

**Files and surfaces.** `README.md`, `CLAUDE.md`, `docs/**`, operator guide,
security/governance documents, changelog, and notices.

**Dependencies.** Implemented behavior and verified results from prior phases.

**Acceptance.** Every quickstart is executable or clearly marked as future;
current/planned behavior is separated; public status and workflow remain
distinct; links resolve; and no stale generic-operation language remains.

**Stop boundary.** Documentation cannot upgrade a planned feature to
implemented or a fixture result to production assurance.

### Phase 10 — Release

**Objective.** Make a deliberate release decision with reproducible packaging,
license/notice files, versioned migrations, security disposition, and release
notes.

**Files and surfaces.** Packaging and lock metadata, `LICENSE`, `NOTICE`,
`CHANGELOG.md`, release checklist, and signed/recorded artifacts as decided by
maintainers.

**Dependencies.** Phase 8 review, Phase 9 documentation, and a maintainer
release decision. The Apache-2.0 license file is a lead/maintainer-owned
release task.

**Acceptance.** The release contains only supported claims, has a reproducible
installation path, documents database/migration compatibility, includes the
license and attribution required by the chosen distribution terms, and records
known limitations and verification results.

**Stop boundary.** No release is a production-safety certification or an
authorization to operate outside the explicitly documented local boundary.

## Cross-phase gates

Every phase must pass these gates before its output is used by a later phase:

1. **Scope gate:** target, namespace, subject, API group, resource/subresource,
   verb, and allowed transformation are explicit.
2. **Evidence gate:** observations and derived claims retain provenance; parsing
   does not upgrade trust.
3. **Integrity gate:** RFC 8785 canonical material and digest references match;
   stale or mismatched inputs abstain.
4. **Authority gate:** no model, status, record, digest, or UI event grants
   Kubernetes permission.
5. **Runner gate:** any rehearsal uses a separate trusted host runner with a
   read-only collector and explicit local target.
6. **Human gate:** any local application requires a human action tied to the
   exact candidate digest.
7. **Documentation gate:** implementation, verification, and plan remain
   separate.

## Current stop point

The current session stops after the offline Phase 2 slice. The control plane
may authenticate, persist case metadata, create a durable unsupported job, and
present case creation. The offline engine may normalize bounded metadata,
derive a snapshot-scoped permission inventory, verify typed claims against
supplied source-bound facts, and compile a `CANDIDATE_ONLY` Role diff. It may
not claim that a cluster was collected, that a rehearsal passed, that a
workload was preserved, or that anything was applied. Those claims require the
later phases and their recorded acceptance evidence.
