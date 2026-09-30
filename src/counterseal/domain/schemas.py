"""Bounded offline records. Validation checks structure, never truth or authority.

References, dedicated-role declarations, completeness and runner trust require a
future independent verifier. Nothing here collects, approves or executes work.
"""

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Annotated, Any, Literal, Self

from pydantic import (
    AfterValidator,
    AliasChoices,
    AwareDatetime,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)

from .digest import canonical_digest, verify_digest
from .enums import (
    ApprovalDecision,
    AuditStage,
    ClaimPredicate,
    CountersealState,
    CountersealStatus,
    EvidenceKind,
    ExecutionOutcome,
    GraphEdgeType,
    GraphNodeType,
    ProbeKind,
    ProbePhase,
    ProbeStatus,
    RbacResourceKind,
    RbacSubjectKind,
    RehearsalDecision,
    RunnerTrust,
    SourceKind,
    TransformationType,
)


def _unique(values: tuple[Any, ...]) -> tuple[Any, ...]:
    if len(set(values)) != len(values):
        raise ValueError("entries must be unique")
    return values


def _timestamp(value: Any) -> Any:
    if not isinstance(value, (datetime, str)):
        raise ValueError("timestamps require an explicit timezone, not an epoch number")
    return value


type Items[T] = Annotated[tuple[T, ...], Field(max_length=256), AfterValidator(_unique)]
type RequiredItems[T] = Annotated[Items[T], Field(min_length=1)]
Identifier = Annotated[
    str, StringConstraints(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
]
Name = Annotated[
    str,
    StringConstraints(min_length=1, max_length=253, pattern=r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$"),
]
Namespace = Annotated[Name, Field(max_length=63, pattern=r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")]
Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2048)]
Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
Timestamp = Annotated[
    AwareDatetime, BeforeValidator(_timestamp), AfterValidator(lambda v: v.astimezone(UTC))
]
ReadVerb = Literal["get", "list", "watch"]
ResponseCode = Annotated[int, Field(strict=True, ge=100, le=599)]


class DomainModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_default=True,
        revalidate_instances="always",
        allow_inf_nan=False,
    )
    schema_version: Literal["1"] = "1"

    def canonical_digest(self) -> str:
        return canonical_digest(self)

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        """Revalidate copies too; Pydantic's default update skips validation."""
        return type(self).model_validate({**self.model_dump(mode="python"), **(update or {})})


class RbacSubject(DomainModel):
    kind: RbacSubjectKind
    name: Identifier
    namespace: Namespace | None = None

    @model_validator(mode="after")
    def namespace_matches_kind(self) -> Self:
        if (self.kind == RbacSubjectKind.SERVICE_ACCOUNT) != (self.namespace is not None):
            raise ValueError("only ServiceAccount subjects require a namespace")
        return self


class RbacObjectIdentity(DomainModel):
    kind: RbacResourceKind
    namespace: Namespace | None = None
    name: Name

    @model_validator(mode="after")
    def scope_matches_kind(self) -> Self:
        namespaced = self.kind in {
            RbacResourceKind.ROLE,
            RbacResourceKind.ROLE_BINDING,
            RbacResourceKind.SERVICE_ACCOUNT,
        }
        if namespaced != (self.namespace is not None):
            raise ValueError("object namespace does not match kind")
        return self


class TargetObjectIdentity(DomainModel):
    api_group: Literal["rbac.authorization.k8s.io"] = "rbac.authorization.k8s.io"
    kind: Literal["Role"] = "Role"
    namespace: Namespace
    name: Name
    dedicated: Literal[True]
    dedicated_to: RbacSubject = Field(validation_alias=AliasChoices("dedicated_to", "subject"))

    @model_validator(mode="after")
    def dedicated_subject_is_in_scope(self) -> Self:
        if (
            self.dedicated_to.kind == RbacSubjectKind.SERVICE_ACCOUNT
            and self.dedicated_to.namespace != self.namespace
        ):
            raise ValueError("a dedicated ServiceAccount must share the Role namespace")
        return self


class RbacSourceScope(DomainModel):
    namespaces: RequiredItems[Namespace]
    resource_kinds: RequiredItems[RbacResourceKind]


class RbacPermission(DomainModel):
    api_group: Literal[""] = ""
    resource: Literal["secrets", "configmaps"] = "secrets"
    verb: ReadVerb
    namespace: Namespace
    resource_name: Name | None = None


class TrustedTestProfile(DomainModel):
    profile_id: Identifier
    version: Identifier
    digest: Digest


class SourceEnrollment(DomainModel):
    case_id: Identifier
    source_id: Identifier
    source_kind: SourceKind
    cluster_name: Identifier
    context_name: Identifier
    rbac_scope: RbacSourceScope
    fixture_id: Identifier
    fixture_version: Identifier
    enrolled_at: Timestamp
    enrolled_by: Identifier


class AuditMetadataEvent(DomainModel):
    audit_id: Identifier
    stage: AuditStage
    source: Identifier = Field(validation_alias=AliasChoices("source", "source_id"))
    subject: RbacSubject
    verb: ReadVerb
    namespace: Namespace | None = None
    api_group: Name | Literal[""]
    resource: Name
    subresource: Name | None = None
    resource_name: Name | None = Field(
        default=None, validation_alias=AliasChoices("resource_name", "name")
    )
    groups: Items[Identifier] = ()
    response_code: ResponseCode | None = None
    occurred_at: Timestamp
    request_received_at: Timestamp | None = None
    level: Literal["Metadata"] = "Metadata"


class EvidenceRecord(DomainModel):
    evidence_id: Identifier
    kind: EvidenceKind
    source_id: Identifier
    captured_at: Timestamp
    captured_by: Identifier
    content_digest: Digest
    size_bytes: Annotated[int, Field(strict=True, ge=0, le=8 * 1024 * 1024)]


class RbacSnapshotObject(DomainModel):
    identity: RbacObjectIdentity
    uid: Identifier
    resource_version: Identifier
    object_digest: Digest


class SnapshotManifest(DomainModel):
    case_id: Identifier
    snapshot_id: Identifier
    source_id: Identifier
    cluster_name: Identifier
    context_name: Identifier
    rbac_scope: RbacSourceScope
    created_at: Timestamp
    created_by: Identifier
    objects: Items[RbacSnapshotObject] = ()
    evidence_ids: Items[Identifier] = ()
    root_digest: Digest = Field(validation_alias=AliasChoices("root_digest", "snapshot_digest"))
    complete: Annotated[bool, Field(strict=True)] = False
    missing_resources: Items[RbacResourceKind] = tuple(RbacResourceKind)

    @model_validator(mode="after")
    def scope_is_consistent(self) -> Self:
        if "missing_resources" not in self.model_fields_set:
            object.__setattr__(self, "missing_resources", self.rbac_scope.resource_kinds)
        if set(self.missing_resources) - set(self.rbac_scope.resource_kinds):
            raise ValueError("missing resources must belong to the declared scope")
        if self.complete and self.missing_resources:
            raise ValueError("a complete snapshot cannot have missing resources")
        identities = [obj.identity for obj in self.objects]
        if len(set(identities)) != len(identities):
            raise ValueError("snapshot contains duplicate object identities")
        for obj in identities:
            if obj.kind not in self.rbac_scope.resource_kinds or (
                obj.namespace is not None and obj.namespace not in self.rbac_scope.namespaces
            ):
                raise ValueError("snapshot object is outside the declared RBAC scope")
        return self


class GraphNode(DomainModel):
    node_id: Identifier
    node_type: GraphNodeType
    snapshot_id: Identifier
    evidence_ids: RequiredItems[Identifier]
    object_ref: Identifier


class GraphEdge(DomainModel):
    edge_id: Identifier
    edge_type: GraphEdgeType
    snapshot_id: Identifier
    from_node_id: Identifier
    to_node_id: Identifier
    evidence_ids: RequiredItems[Identifier]

    @model_validator(mode="after")
    def no_self_edge(self) -> Self:
        if self.from_node_id == self.to_node_id:
            raise ValueError("graph edges cannot point to the same node")
        return self


class WorkloadContract(DomainModel):
    contract_id: Identifier
    version: Identifier
    owner: Identifier
    approved_by: Identifier
    reviewed_at: Timestamp
    expires_at: Timestamp
    subject: RbacSubject
    namespace: Namespace
    required_operations: RequiredItems[RbacPermission]
    trusted_test_profile: TrustedTestProfile
    digest: Digest

    @model_validator(mode="after")
    def contract_is_bound(self) -> Self:
        if self.expires_at <= self.reviewed_at:
            raise ValueError("contract expiry must follow review")
        if (
            self.subject.kind == RbacSubjectKind.SERVICE_ACCOUNT
            and self.subject.namespace != self.namespace
        ):
            raise ValueError("the contract subject must share its declared namespace")
        if any(op.namespace != self.namespace for op in self.required_operations):
            raise ValueError("required operations must stay in the contract namespace")
        if not verify_digest(self.model_dump(mode="python", exclude={"digest"}), self.digest):
            raise ValueError("contract digest does not match its content")
        return self


class Hypothesis(DomainModel):
    hypothesis_id: Identifier
    snapshot_id: Identifier
    statement: Text
    evidence_ids: RequiredItems[Identifier]
    claim_ids: Items[Identifier]
    falsifier_probe_ids: RequiredItems[Identifier]
    created_at: Timestamp


class TypedClaim(DomainModel):
    """Arguments are ordered, bounded evidence/object references, never expressions."""

    claim_id: Identifier
    snapshot_id: Identifier
    predicate: ClaimPredicate
    arguments: RequiredItems[Identifier]
    evidence_ids: RequiredItems[Identifier]
    created_at: Timestamp

    @model_validator(mode="after")
    def predicate_arity(self) -> Self:
        # audit; binding/role; role/rule; result; contract/test-result;
        # snapshot/scope; source/object/object-digest.
        arities = dict(zip(ClaimPredicate, (1, 2, 2, 1, 2, 2, 3), strict=True))
        if len(self.arguments) != arities[self.predicate]:
            raise ValueError("claim arguments do not match predicate arity")
        return self


class RbacRule(DomainModel):
    api_group: Literal[""] = ""
    resource: Literal["secrets"] = "secrets"
    verbs: RequiredItems[ReadVerb]
    resource_names: Items[Name] = ()


class PlanOperation(DomainModel):
    """A secret-only rule delta. No arbitrary paths, bindings or mutation verbs."""

    operation_id: Identifier
    rule_index: Annotated[int, Field(strict=True, ge=0, le=255)]
    transformation: TransformationType
    before: RbacRule
    after: RbacRule | None

    @model_validator(mode="after")
    def narrowing_grammar(self) -> Self:
        if self.transformation == TransformationType.REMOVE_SECRET_ACCESS:
            valid = self.after is None
        elif self.transformation == TransformationType.REMOVE_SECRET_LIST_WATCH:
            remaining = tuple(v for v in self.before.verbs if v not in ("list", "watch"))
            expected = self.before.model_copy(update={"verbs": remaining}) if remaining else None
            valid = remaining != self.before.verbs and self.after == expected
        else:
            before_verbs = set(self.before.verbs)
            after_verbs = set(self.after.verbs) if self.after else set()
            if not self.after:
                # Candidate C may remove a separate list/watch-only rule while
                # the named-get rule is narrowed in another operation.
                valid = bool(before_verbs) and before_verbs <= {"list", "watch"}
            else:
                old_names = set(self.before.resource_names)
                new_names = set(self.after.resource_names)
                valid = bool(
                    "get" in before_verbs
                    and after_verbs == {"get"}
                    and new_names
                    and (not old_names or new_names < old_names)
                )
        if not valid:
            raise ValueError(
                "operation must strictly narrow secret access using the selected transform"
            )
        return self


class CanonicalCompiledDiff(DomainModel):
    operations: RequiredItems[PlanOperation]

    @model_validator(mode="after")
    def distinct_rules(self) -> Self:
        if len({op.rule_index for op in self.operations}) != len(self.operations):
            raise ValueError("a diff may change each source rule only once")
        return self


class AssuranceEnvelope(DomainModel):
    envelope_id: Identifier
    environment: Literal["offline_fixture", "local_kind"]
    source: Identifier = Field(validation_alias=AliasChoices("source", "source_id"))
    snapshot: Identifier = Field(validation_alias=AliasChoices("snapshot", "snapshot_id"))
    snapshot_digest: Digest = Field(
        validation_alias=AliasChoices("snapshot_digest", "source_snapshot_digest")
    )
    fixture: Identifier = Field(validation_alias=AliasChoices("fixture", "fixture_id"))
    fixture_version: Identifier
    kubernetes_version: Identifier
    image_digests: RequiredItems[Digest]
    rbac_scope: RbacSourceScope
    contract_digest: Digest
    contract_expires_at: Timestamp = Field(
        validation_alias=AliasChoices("contract_expires_at", "contract_expiry", "expires_at")
    )
    authorizer_assumptions: RequiredItems[Text]
    admission_assumptions: RequiredItems[Text]
    network_assumptions: RequiredItems[Text]
    probe_set_digest: Digest
    differences: Items[Text]
    unknowns: Items[Text]
    runner_id: Identifier
    runner_trust: RunnerTrust
    policy_version: Identifier


class ProbeDefinition(DomainModel):
    probe_id: Identifier
    version: Identifier
    kind: ProbeKind
    phase: ProbePhase
    subject: RbacSubject
    operation: RbacPermission
    trusted_test_profile: TrustedTestProfile
    test_id: Identifier
    expected_response_code: Literal[200, 403]
    timeout_seconds: Annotated[int, Field(strict=True, ge=1, le=120)] = 30


class RbacTransformation(DomainModel):
    transformation_type: TransformationType
    target_object_identity: TargetObjectIdentity = Field(
        validation_alias=AliasChoices("target_object_identity", "target")
    )
    rule_index: Annotated[int, Field(strict=True, ge=0, le=255)]
    before: RbacRule
    after: RbacRule | None

    @model_validator(mode="after")
    def narrowing_grammar(self) -> Self:
        operation = PlanOperation(
            operation_id="transformation",
            rule_index=self.rule_index,
            transformation=self.transformation_type,
            before=self.before,
            after=self.after,
        )
        if operation.transformation != self.transformation_type:
            raise ValueError("transformation type mismatch")
        return self


class CandidatePlan(DomainModel):
    plan_id: Identifier
    case_id: Identifier
    source_id: Identifier
    source_snapshot_digest: Digest
    workload_contract_version: Identifier
    fixture_profile_version: Identifier
    policy_version: Identifier
    source_snapshot: SnapshotManifest
    workload_contract: WorkloadContract
    target_object_identity: TargetObjectIdentity
    target_uid: Identifier
    target_resource_version: Identifier
    typed_transformation: RbacTransformation
    canonical_compiled_diff: CanonicalCompiledDiff
    supporting_claim_ids: RequiredItems[Identifier]
    applicable_probe_set: RequiredItems[ProbeDefinition]
    assurance_envelope: AssuranceEnvelope
    limitations: Items[Text]
    rationale: Text
    created_at: Timestamp
    created_by: Identifier
    status: Literal[CountersealStatus.CANDIDATE_ONLY] = CountersealStatus.CANDIDATE_ONLY
    canonical_artifact_digest: Digest | None = None

    def canonical_artifact_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="python", exclude={"canonical_artifact_digest"})

    def expected_canonical_artifact_digest(self) -> str:
        return canonical_digest(self.canonical_artifact_payload())

    @model_validator(mode="after")
    def bind_artifact(self) -> Self:
        snap, contract, env, target = (
            self.source_snapshot,
            self.workload_contract,
            self.assurance_envelope,
            self.target_object_identity,
        )
        if not snap.complete or snap.missing_resources or not snap.objects or not snap.evidence_ids:
            raise ValueError("candidates require a nonempty complete snapshot with evidence")
        if (
            self.case_id,
            self.source_id,
            self.source_snapshot_digest,
            env.source,
            env.snapshot,
            env.snapshot_digest,
            env.rbac_scope,
        ) != (
            snap.case_id,
            snap.source_id,
            snap.root_digest,
            snap.source_id,
            snap.snapshot_id,
            snap.root_digest,
            snap.rbac_scope,
        ):
            raise ValueError("candidate assurance does not match snapshot scope")
        if (
            self.workload_contract_version,
            target.namespace,
            target.dedicated_to,
            env.contract_digest,
            env.contract_expires_at,
        ) != (
            contract.version,
            contract.namespace,
            contract.subject,
            contract.digest,
            contract.expires_at,
        ):
            raise ValueError("target and assurance must match the workload contract")
        if (
            self.fixture_profile_version != contract.trusted_test_profile.version
            or self.fixture_profile_version != env.fixture_version
            or self.policy_version != env.policy_version
        ):
            raise ValueError(
                "candidate provenance does not match the contract profile and fixture policy"
            )
        if not contract.reviewed_at <= self.created_at < contract.expires_at:
            raise ValueError("candidate creation must fall within the contract review window")
        if not any(
            (
                obj.identity.kind,
                obj.identity.namespace,
                obj.identity.name,
                obj.uid,
                obj.resource_version,
            )
            == (
                "Role",
                target.namespace,
                target.name,
                self.target_uid,
                self.target_resource_version,
            )
            for obj in snap.objects
        ):
            raise ValueError("target UID/version must be present in the source snapshot")
        matching_operation = any(
            op.rule_index == self.typed_transformation.rule_index
            and op.transformation == self.typed_transformation.transformation_type
            and op.before == self.typed_transformation.before
            and op.after == self.typed_transformation.after
            for op in self.canonical_compiled_diff.operations
        )
        if (
            self.typed_transformation.target_object_identity != target
            or any(
                op.transformation != self.typed_transformation.transformation_type
                for op in self.canonical_compiled_diff.operations
            )
            or not matching_operation
        ):
            raise ValueError("compiled diff must use the declared transformation")
        if any(
            p.subject != contract.subject
            or p.operation.namespace != contract.namespace
            or p.trusted_test_profile != contract.trusted_test_profile
            for p in self.applicable_probe_set
        ):
            raise ValueError("probes must match the workload subject, scope and trusted profile")
        if env.probe_set_digest != canonical_digest(self.applicable_probe_set):
            raise ValueError("probe-set digest does not match candidate probes")
        expected = self.expected_canonical_artifact_digest()
        if (
            self.canonical_artifact_digest is not None
            and self.canonical_artifact_digest != expected
        ):
            raise ValueError("canonical_artifact_digest does not match the complete artifact")
        object.__setattr__(self, "canonical_artifact_digest", expected)
        return self


class RehearsalJob(DomainModel):
    rehearsal_id: Identifier
    plan_id: Identifier
    plan_digest: Digest
    assurance_envelope: AssuranceEnvelope
    probe_ids: RequiredItems[Identifier]
    created_at: Timestamp
    created_by: Identifier


class ProbeResult(DomainModel):
    result_id: Identifier
    probe_id: Identifier
    probe_version: Identifier
    snapshot_id: Identifier
    phase: ProbePhase
    status: ProbeStatus
    response_code: ResponseCode | None
    evidence_ids: RequiredItems[Identifier]
    runner_id: Identifier
    observed_at: Timestamp
    detail: Text


class RehearsalVerdict(DomainModel):
    verdict_id: Identifier
    rehearsal_id: Identifier
    plan_id: Identifier
    plan_digest: Digest
    assurance_envelope: AssuranceEnvelope
    decision: RehearsalDecision
    status: Literal[
        CountersealStatus.FIXTURE_VALIDATED,
        CountersealStatus.INCONCLUSIVE,
        CountersealStatus.UNSUPPORTED,
        CountersealStatus.STALE,
    ]
    baseline_result_ids: Items[Identifier]
    control_result_ids: Items[Identifier]
    test_result_ids: Items[Identifier]
    issued_at: Timestamp
    issued_by: Identifier
    rationale: Text

    @model_validator(mode="after")
    def explicit_validation_references(self) -> Self:
        passing = self.decision == RehearsalDecision.PASS
        if passing != (self.status == CountersealStatus.FIXTURE_VALIDATED):
            raise ValueError("explicit status must agree with the declared decision")
        if passing and not (
            self.baseline_result_ids and self.control_result_ids and self.test_result_ids
        ):
            raise ValueError(
                "fixture validation requires baseline, control and nonempty test results"
            )
        return self


class Approval(DomainModel):
    approval_id: Identifier
    plan_id: Identifier
    plan_digest: Digest
    rehearsal_verdict_id: Identifier
    assurance_envelope: AssuranceEnvelope
    decision: ApprovalDecision
    status: Literal[
        CountersealStatus.LAB_APPROVED, CountersealStatus.INCONCLUSIVE, CountersealStatus.STALE
    ]
    approver: Identifier
    decided_at: Timestamp
    expires_at: Timestamp
    rationale: Text

    @model_validator(mode="after")
    def explicit_time_bounded_decision(self) -> Self:
        expected = {
            ApprovalDecision.APPROVED: CountersealStatus.LAB_APPROVED,
            ApprovalDecision.REJECTED: CountersealStatus.INCONCLUSIVE,
            ApprovalDecision.EXPIRED: CountersealStatus.STALE,
        }
        if (
            self.status != expected[self.decision]
            or not self.decided_at < self.expires_at <= self.assurance_envelope.contract_expires_at
        ):
            raise ValueError("approval requires coherent status and a contract-bounded expiry")
        return self


class ExecutionReceipt(DomainModel):
    receipt_id: Identifier
    plan_id: Identifier
    plan_digest: Digest
    approval_id: Identifier
    rehearsal_verdict_id: Identifier
    assurance_envelope: AssuranceEnvelope
    target_object_identity: TargetObjectIdentity
    before_object_digest: Digest
    after_object_digest: Digest | None
    outcome: ExecutionOutcome
    status: Literal[CountersealStatus.APPLIED_LOCAL, CountersealStatus.INCONCLUSIVE]
    postcheck_result_ids: Items[Identifier]
    evidence_ids: RequiredItems[Identifier]
    started_at: Timestamp
    finished_at: Timestamp
    executor: Identifier
    detail: Text

    @model_validator(mode="after")
    def explicit_outcome(self) -> Self:
        success = self.outcome == ExecutionOutcome.SUCCEEDED
        if self.finished_at < self.started_at or success != (
            self.status == CountersealStatus.APPLIED_LOCAL
        ):
            raise ValueError("receipt times/status are inconsistent")
        if success and not (self.after_object_digest and self.postcheck_result_ids):
            raise ValueError("applied-local receipts require after-state and postcheck references")
        return self


class CaseReport(DomainModel):
    report_id: Identifier
    case_id: Identifier
    assurance_envelope: AssuranceEnvelope
    generated_at: Timestamp
    generated_by: Identifier
    summary: Text
    status: CountersealStatus
    final_state: CountersealState
    evidence_ids: RequiredItems[Identifier]
    claim_ids: Items[Identifier]
    plan_id: Identifier | None = None
    baseline_result_id: Identifier | None = None
    rehearsal_verdict_id: Identifier | None = None
    approval_id: Identifier | None = None
    execution_receipt_id: Identifier | None = None

    @model_validator(mode="after")
    def references_match_status(self) -> Self:
        required = {
            CountersealStatus.BASELINE_REPRODUCED: self.baseline_result_id,
            CountersealStatus.FIXTURE_VALIDATED: self.rehearsal_verdict_id,
            CountersealStatus.CANDIDATE_ONLY: self.plan_id,
            CountersealStatus.LAB_APPROVED: self.approval_id,
            CountersealStatus.APPLIED_LOCAL: self.execution_receipt_id,
        }
        if self.status in required and not required[self.status]:
            raise ValueError("public status requires its supporting artifact reference")
        if (
            (self.execution_receipt_id and not self.approval_id)
            or (self.approval_id and not self.rehearsal_verdict_id)
            or (self.rehearsal_verdict_id and not self.plan_id)
        ):
            raise ValueError("report references must include the prerequisite artifacts")
        if (
            self.final_state == CountersealState.MITIGATED_SCOPED
            and self.status != CountersealStatus.APPLIED_LOCAL
        ):
            raise ValueError("mitigated-scoped reports require applied-local evidence")
        return self


class EvidenceBundleManifest(DomainModel):
    bundle_id: Identifier
    case_id: Identifier
    created_at: Timestamp
    evidence_ids: RequiredItems[Identifier]
    entry_digests: RequiredItems[Digest]
    bundle_digest: Digest

    @model_validator(mode="after")
    def aligned_entries(self) -> Self:
        if len(self.evidence_ids) != len(self.entry_digests):
            raise ValueError("each evidence entry requires a digest")
        return self


class PersistedState(DomainModel):
    case_id: Identifier
    state: CountersealState
    revision: Annotated[int, Field(strict=True, ge=1, le=2**31 - 1)] = 1
    updated_at: Timestamp
    updated_by: Identifier
    transition_id: Identifier
    reason: Text
    previous_state: CountersealState | None = None

    @model_validator(mode="after")
    def revision_history_shape(self) -> Self:
        if (self.revision == 1) != (
            self.previous_state is None
        ) or self.previous_state == self.state:
            raise ValueError("revision and previous state are inconsistent")
        return self


__all__ = [
    "Approval",
    "AssuranceEnvelope",
    "AuditMetadataEvent",
    "CandidatePlan",
    "CanonicalCompiledDiff",
    "CaseReport",
    "DomainModel",
    "EvidenceBundleManifest",
    "EvidenceRecord",
    "ExecutionReceipt",
    "GraphEdge",
    "GraphNode",
    "Hypothesis",
    "PersistedState",
    "PlanOperation",
    "ProbeDefinition",
    "ProbeResult",
    "RbacObjectIdentity",
    "RbacPermission",
    "RbacRule",
    "RbacSnapshotObject",
    "RbacSourceScope",
    "RbacSubject",
    "RbacTransformation",
    "RehearsalJob",
    "RehearsalVerdict",
    "SnapshotManifest",
    "SourceEnrollment",
    "TargetObjectIdentity",
    "TrustedTestProfile",
    "TypedClaim",
    "WorkloadContract",
]
