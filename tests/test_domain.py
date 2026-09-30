from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from counterseal.domain import (
    ALLOWED_TRANSITIONS,
    Approval,
    ApprovalDecision,
    AssuranceEnvelope,
    AuditMetadataEvent,
    AuditStage,
    CandidatePlan,
    CanonicalCompiledDiff,
    CaseReport,
    ClaimPredicate,
    CountersealState,
    CountersealStatus,
    EvidenceBundleManifest,
    EvidenceKind,
    EvidenceRecord,
    ExecutionOutcome,
    ExecutionReceipt,
    GraphEdge,
    GraphEdgeType,
    GraphNode,
    GraphNodeType,
    Hypothesis,
    PersistedState,
    PlanOperation,
    ProbeDefinition,
    ProbeKind,
    ProbePhase,
    ProbeResult,
    ProbeStatus,
    RbacObjectIdentity,
    RbacPermission,
    RbacResourceKind,
    RbacRule,
    RbacSnapshotObject,
    RbacSourceScope,
    RbacSubject,
    RbacSubjectKind,
    RbacTransformation,
    RehearsalDecision,
    RehearsalJob,
    RehearsalVerdict,
    RunnerTrust,
    SnapshotManifest,
    SourceEnrollment,
    SourceKind,
    TargetObjectIdentity,
    TransformationType,
    TrustedTestProfile,
    TypedClaim,
    WorkloadContract,
    can_transition,
    canonical_digest,
    canonical_json,
    transition,
    verify_digest,
)

NOW = datetime(2026, 1, 1, 12, tzinfo=UTC)
DIGEST = "sha256:" + "a" * 64
OBJECT_DIGEST = "sha256:" + "b" * 64
SNAPSHOT_DIGEST = "sha256:" + "c" * 64
IMAGE_DIGEST = "sha256:" + "d" * 64


def subject() -> RbacSubject:
    return RbacSubject(kind=RbacSubjectKind.SERVICE_ACCOUNT, name="worker", namespace="workloads")


def scope() -> RbacSourceScope:
    return RbacSourceScope(namespaces=("workloads",), resource_kinds=(RbacResourceKind.ROLE,))


def profile() -> TrustedTestProfile:
    return TrustedTestProfile(profile_id="secret-tests", version="1", digest=DIGEST)


def permission() -> RbacPermission:
    return RbacPermission(namespace="workloads", verb="get")


def contract() -> WorkloadContract:
    values = {
        "contract_id": "contract-1",
        "version": "1",
        "owner": "owner-1",
        "approved_by": "reviewer-1",
        "reviewed_at": NOW,
        "expires_at": NOW + timedelta(hours=1),
        "subject": subject(),
        "namespace": "workloads",
        "required_operations": (permission(),),
        "trusted_test_profile": profile(),
    }
    unsigned = WorkloadContract.model_construct(digest=DIGEST, **values)
    return WorkloadContract(
        digest=canonical_digest(unsigned.model_dump(mode="python", exclude={"digest"})), **values
    )


def snapshot(*, complete: bool = True) -> SnapshotManifest:
    values = {
        "case_id": "case-1",
        "snapshot_id": "snapshot-1",
        "source_id": "source-1",
        "cluster_name": "kind-counterseal",
        "context_name": "kind-counterseal",
        "rbac_scope": scope(),
        "created_at": NOW,
        "created_by": "collector-1",
        "objects": (
            RbacSnapshotObject(
                identity=RbacObjectIdentity(
                    kind=RbacResourceKind.ROLE, namespace="workloads", name="worker-role"
                ),
                uid="uid-1",
                resource_version="rv-1",
                object_digest=OBJECT_DIGEST,
            ),
        )
        if complete
        else (),
        "evidence_ids": ("evidence-snapshot",) if complete else (),
        "root_digest": SNAPSHOT_DIGEST,
        "complete": complete,
        "missing_resources": () if complete else (RbacResourceKind.ROLE,),
    }
    return SnapshotManifest(**values)


def target() -> TargetObjectIdentity:
    return TargetObjectIdentity(
        namespace="workloads",
        name="worker-role",
        dedicated=True,
        dedicated_to=subject(),
    )


def rules() -> tuple[RbacRule, RbacRule]:
    before = RbacRule(verbs=("get", "list", "watch"))
    after = RbacRule(verbs=("get",))
    return before, after


def transformation() -> RbacTransformation:
    before, after = rules()
    return RbacTransformation(
        transformation_type=TransformationType.REMOVE_SECRET_LIST_WATCH,
        target_object_identity=target(),
        rule_index=0,
        before=before,
        after=after,
    )


def probe() -> ProbeDefinition:
    return ProbeDefinition(
        probe_id="probe-1",
        version="1",
        kind=ProbeKind.SECRET_ACCESS,
        phase=ProbePhase.CANDIDATE,
        subject=subject(),
        operation=permission(),
        trusted_test_profile=profile(),
        test_id="secret-forbidden",
        expected_response_code=403,
    )


def envelope() -> AssuranceEnvelope:
    candidate_probe = probe()
    return AssuranceEnvelope(
        environment="offline_fixture",
        source="source-1",
        snapshot="snapshot-1",
        snapshot_digest=SNAPSHOT_DIGEST,
        fixture="counterseal-rbac",
        fixture_version="1",
        kubernetes_version="v1.30.0",
        image_digests=(IMAGE_DIGEST,),
        rbac_scope=scope(),
        contract_digest=contract().digest,
        contract_expires_at=NOW + timedelta(hours=1),
        authorizer_assumptions=("fixture authorizer is selected",),
        admission_assumptions=("no mutating admission is in scope",),
        network_assumptions=("fixture network is isolated",),
        probe_set_digest=canonical_digest((candidate_probe,)),
        differences=(),
        unknowns=("live cluster behavior is unknown",),
        runner_id="runner-1",
        runner_trust=RunnerTrust.ATTESTED_LOCAL,
        policy_version="policy-1",
        envelope_id="envelope-1",
    )


def candidate(
    *, snapshot_value: SnapshotManifest | None = None, **overrides: object
) -> CandidatePlan:
    snap = snapshot_value or snapshot()
    workload = contract()
    assurance = envelope()
    values: dict[str, object] = {
        "plan_id": "plan-1",
        "case_id": "case-1",
        "source_id": snap.source_id,
        "source_snapshot_digest": snap.root_digest,
        "workload_contract_version": workload.version,
        "fixture_profile_version": workload.trusted_test_profile.version,
        "policy_version": assurance.policy_version,
        "source_snapshot": snap,
        "workload_contract": workload,
        "target_object_identity": target(),
        "target_uid": "uid-1",
        "target_resource_version": "rv-1",
        "typed_transformation": transformation(),
        "canonical_compiled_diff": CanonicalCompiledDiff(
            operations=(
                PlanOperation(
                    operation_id="operation-1",
                    rule_index=0,
                    transformation=TransformationType.REMOVE_SECRET_LIST_WATCH,
                    before=rules()[0],
                    after=rules()[1],
                ),
            )
        ),
        "supporting_claim_ids": ("claim-1",),
        "applicable_probe_set": (probe(),),
        "assurance_envelope": assurance,
        "limitations": ("fixture only",),
        "rationale": "Remove list/watch from a dedicated secret rule.",
        "created_at": NOW,
        "created_by": "planner-1",
    }
    values.update(overrides)
    return CandidatePlan(**values)


def test_artifacts_are_closed_frozen_and_reference_explicit_evidence() -> None:
    source = SourceEnrollment(
        case_id="case-1",
        source_id="source-1",
        source_kind=SourceKind.LOCAL_KIND,
        cluster_name="kind-counterseal",
        context_name="kind-counterseal",
        rbac_scope=scope(),
        fixture_id="counterseal-rbac",
        fixture_version="1",
        enrolled_at=NOW,
        enrolled_by="operator-1",
    )
    event = AuditMetadataEvent(
        audit_id="audit-1",
        stage=AuditStage.RESPONSE_COMPLETE,
        source=source.source_id,
        subject=subject(),
        verb="get",
        namespace="workloads",
        api_group="",
        resource="secrets",
        response_code=403,
        occurred_at=NOW,
    )
    evidence = EvidenceRecord(
        evidence_id="evidence-1",
        kind=EvidenceKind.AUDIT_METADATA,
        source_id=source.source_id,
        captured_at=NOW,
        captured_by="operator-1",
        content_digest=DIGEST,
        size_bytes=128,
    )
    snap = snapshot()
    node = GraphNode(
        node_id="node-1",
        node_type=GraphNodeType.ROLE,
        snapshot_id=snap.snapshot_id,
        evidence_ids=(evidence.evidence_id,),
        object_ref="worker-role",
    )
    edge = GraphEdge(
        edge_id="edge-1",
        edge_type=GraphEdgeType.OBSERVED_ACCESS,
        snapshot_id=snap.snapshot_id,
        from_node_id=node.node_id,
        to_node_id="node-2",
        evidence_ids=(evidence.evidence_id,),
    )
    hypothesis = Hypothesis(
        hypothesis_id="hypothesis-1",
        snapshot_id=snap.snapshot_id,
        statement="The role grants unnecessary list/watch access.",
        evidence_ids=(evidence.evidence_id,),
        claim_ids=("claim-1",),
        falsifier_probe_ids=("probe-1",),
        created_at=NOW,
    )
    claim = TypedClaim(
        claim_id="claim-1",
        snapshot_id=snap.snapshot_id,
        predicate=ClaimPredicate.PROBE_RETURNED_FORBIDDEN,
        arguments=("probe-1",),
        evidence_ids=(evidence.evidence_id,),
        created_at=NOW,
    )
    plan = candidate()
    rehearsal = RehearsalJob(
        rehearsal_id="rehearsal-1",
        plan_id=plan.plan_id,
        plan_digest=plan.canonical_artifact_digest,
        assurance_envelope=plan.assurance_envelope,
        probe_ids=("probe-1",),
        created_at=NOW,
        created_by="runner-1",
    )
    result = ProbeResult(
        result_id="result-1",
        probe_id="probe-1",
        probe_version="1",
        snapshot_id=snap.snapshot_id,
        phase=ProbePhase.CANDIDATE,
        status=ProbeStatus.PASS,
        response_code=403,
        evidence_ids=(evidence.evidence_id,),
        runner_id="runner-1",
        observed_at=NOW,
        detail="The candidate probe returned the expected forbidden response.",
    )
    verdict = RehearsalVerdict(
        verdict_id="verdict-1",
        rehearsal_id=rehearsal.rehearsal_id,
        plan_id=plan.plan_id,
        plan_digest=plan.canonical_artifact_digest,
        assurance_envelope=plan.assurance_envelope,
        decision=RehearsalDecision.PASS,
        status=CountersealStatus.FIXTURE_VALIDATED,
        baseline_result_ids=("baseline-1",),
        control_result_ids=("control-1",),
        test_result_ids=(result.result_id,),
        issued_at=NOW,
        issued_by="runner-1",
        rationale="Control, baseline and candidate test references are present.",
    )
    approval = Approval(
        approval_id="approval-1",
        plan_id=plan.plan_id,
        plan_digest=plan.canonical_artifact_digest,
        rehearsal_verdict_id=verdict.verdict_id,
        assurance_envelope=plan.assurance_envelope,
        decision=ApprovalDecision.APPROVED,
        status=CountersealStatus.LAB_APPROVED,
        approver="reviewer-1",
        decided_at=NOW,
        expires_at=NOW + timedelta(minutes=30),
        rationale="The exact candidate was reviewed.",
    )
    receipt = ExecutionReceipt(
        receipt_id="receipt-1",
        plan_id=plan.plan_id,
        plan_digest=plan.canonical_artifact_digest,
        approval_id=approval.approval_id,
        rehearsal_verdict_id=verdict.verdict_id,
        assurance_envelope=plan.assurance_envelope,
        target_object_identity=plan.target_object_identity,
        before_object_digest=OBJECT_DIGEST,
        after_object_digest=DIGEST,
        outcome=ExecutionOutcome.SUCCEEDED,
        status=CountersealStatus.APPLIED_LOCAL,
        postcheck_result_ids=("postcheck-1",),
        evidence_ids=(evidence.evidence_id,),
        started_at=NOW,
        finished_at=NOW,
        executor="executor-1",
        detail="Local fixture receipt only.",
    )
    report = CaseReport(
        report_id="report-1",
        case_id="case-1",
        assurance_envelope=plan.assurance_envelope,
        generated_at=NOW,
        generated_by="reporter-1",
        summary="The local fixture record set is complete.",
        status=CountersealStatus.APPLIED_LOCAL,
        final_state=CountersealState.MITIGATED_SCOPED,
        evidence_ids=(evidence.evidence_id,),
        claim_ids=(claim.claim_id,),
        plan_id=plan.plan_id,
        rehearsal_verdict_id=verdict.verdict_id,
        approval_id=approval.approval_id,
        execution_receipt_id=receipt.receipt_id,
    )
    bundle = EvidenceBundleManifest(
        bundle_id="bundle-1",
        case_id="case-1",
        created_at=NOW,
        evidence_ids=(evidence.evidence_id,),
        entry_digests=(evidence.content_digest,),
        bundle_digest=DIGEST,
    )
    state = PersistedState(
        case_id="case-1",
        state=CountersealState.NEW,
        updated_at=NOW,
        updated_by="operator-1",
        transition_id="transition-1",
        reason="case opened",
    )
    records = (
        source,
        event,
        evidence,
        snap,
        node,
        edge,
        hypothesis,
        claim,
        plan,
        rehearsal,
        result,
        verdict,
        approval,
        receipt,
        report,
        bundle,
        state,
    )
    assert all(record.schema_version == "1" for record in records)
    with pytest.raises(ValidationError):
        plan.rationale = "changed"
    with pytest.raises(ValidationError):
        EvidenceRecord(
            evidence_id="evidence-2",
            kind=EvidenceKind.AUDIT_METADATA,
            source_id="source-1",
            captured_at=NOW,
            captured_by="operator-1",
            content_digest=DIGEST,
            size_bytes=1,
            request_body="never accepted",
        )


def test_public_status_is_separate_from_the_workflow_state() -> None:
    assert CountersealState is not CountersealStatus
    assert [item.value for item in CountersealState] == [
        "NEW",
        "INVESTIGATING",
        "NEEDS_EVIDENCE",
        "UNSUPPORTED",
        "BASELINING",
        "EVALUATING",
        "NO_SAFE_CANDIDATE",
        "AWAITING_APPROVAL",
        "APPLYING",
        "POSTCHECK",
        "MITIGATED_SCOPED",
        "ESCALATED",
        "INCONCLUSIVE",
        "STALE",
        "FAILED",
        "CANCELLED",
    ]
    assert [item.value for item in CountersealStatus] == [
        "OBSERVED",
        "DERIVED",
        "BASELINE_REPRODUCED",
        "FIXTURE_VALIDATED",
        "CANDIDATE_ONLY",
        "LAB_APPROVED",
        "APPLIED_LOCAL",
        "INCONCLUSIVE",
        "STALE",
        "UNSUPPORTED",
    ]
    assert not hasattr(CountersealState, "CANDIDATE_ONLY")
    assert not hasattr(TransformationType, "ADD_BINDING_SUBJECT")


@pytest.mark.parametrize(
    ("source", "target", "allowed"),
    [
        (CountersealState.NEW, CountersealState.INVESTIGATING, True),
        (CountersealState.INVESTIGATING, CountersealState.BASELINING, True),
        (CountersealState.EVALUATING, CountersealState.AWAITING_APPROVAL, True),
        (CountersealState.AWAITING_APPROVAL, CountersealState.APPLYING, True),
        (CountersealState.POSTCHECK, CountersealState.MITIGATED_SCOPED, True),
        (CountersealState.NEW, CountersealState.APPLYING, False),
        (CountersealState.EVALUATING, CountersealState.APPLYING, False),
        (CountersealState.APPLYING, CountersealState.AWAITING_APPROVAL, False),
        (CountersealState.CANCELLED, CountersealState.INVESTIGATING, False),
    ],
)
def test_state_matrix_is_explicit(
    source: CountersealState, target: CountersealState, allowed: bool
) -> None:
    assert can_transition(source, target) is allowed
    assert (target in ALLOWED_TRANSITIONS[source]) is allowed


def test_transition_is_immutable_and_has_no_authority_side_effect() -> None:
    initial = PersistedState(
        case_id="case-1",
        state=CountersealState.NEW,
        updated_at=NOW,
        updated_by="operator-1",
        transition_id="t-1",
        reason="opened",
    )
    next_state = transition(
        initial,
        CountersealState.INVESTIGATING,
        updated_at=NOW,
        updated_by="operator-1",
        transition_id="t-2",
        reason="review started",
    )
    assert initial.state == CountersealState.NEW
    assert next_state.state == CountersealState.INVESTIGATING
    assert next_state.revision == 2
    assert not can_transition(CountersealState.NEW, CountersealState.AWAITING_APPROVAL)
    with pytest.raises(ValueError):
        transition(
            initial,
            CountersealState.APPLYING,
            updated_at=NOW,
            updated_by="operator-1",
            transition_id="t-3",
            reason="skip gates",
        )


def test_snapshot_scope_and_executable_gate() -> None:
    incomplete = snapshot(complete=False)
    assert incomplete.complete is False
    assert incomplete.missing_resources == (RbacResourceKind.ROLE,)
    assert (
        SnapshotManifest(
            case_id="case-2",
            snapshot_id="empty",
            source_id="source-1",
            cluster_name="kind",
            context_name="ctx",
            rbac_scope=scope(),
            created_at=NOW,
            created_by="collector",
            root_digest=DIGEST,
        ).complete
        is False
    )
    with pytest.raises(ValidationError):
        candidate(snapshot_value=incomplete)
    with pytest.raises(ValidationError):
        SnapshotManifest(
            case_id="case-1",
            snapshot_id="bad",
            source_id="source-1",
            cluster_name="kind",
            context_name="ctx",
            rbac_scope=scope(),
            created_at=NOW,
            created_by="collector",
            root_digest=DIGEST,
            complete=True,
            missing_resources=(RbacResourceKind.ROLE,),
        )


def test_required_contract_and_assurance_fields_cannot_be_omitted() -> None:
    contract_values = contract().model_dump(mode="python")
    contract_values.pop("approved_by")
    with pytest.raises(ValidationError):
        WorkloadContract(**contract_values)
    envelope_values = envelope().model_dump(mode="python")
    envelope_values.pop("network_assumptions")
    with pytest.raises(ValidationError):
        AssuranceEnvelope(**envelope_values)


@pytest.mark.parametrize("transform", list(TransformationType))
def test_supported_transforms_are_strictly_narrowing(transform: TransformationType) -> None:
    before = RbacRule(verbs=("get", "list", "watch"), resource_names=())
    if transform is TransformationType.REMOVE_SECRET_ACCESS:
        after = None
    elif transform is TransformationType.REMOVE_SECRET_LIST_WATCH:
        after = RbacRule(verbs=("get",))
    else:
        after = RbacRule(verbs=("get",), resource_names=("named-secret",))
    operation = PlanOperation(
        operation_id="op", rule_index=0, transformation=transform, before=before, after=after
    )
    assert operation.transformation is transform
    with pytest.raises(ValidationError):
        PlanOperation(
            operation_id="bad",
            rule_index=0,
            transformation=transform,
            before=before,
            after=RbacRule(verbs=("get", "list", "watch")),
        )


def test_target_and_claim_grammars_reject_scope_expansion_and_free_form_predicates() -> None:
    with pytest.raises(ValidationError):
        TargetObjectIdentity(
            namespace="workloads",
            name="worker-binding",
            dedicated=True,
            dedicated_to=subject(),
            kind="RoleBinding",
        )
    with pytest.raises(ValidationError):
        TargetObjectIdentity(
            namespace="workloads", name="worker-role", dedicated=False, dedicated_to=subject()
        )
    with pytest.raises(ValidationError):
        TypedClaim(
            claim_id="claim",
            snapshot_id="snapshot-1",
            predicate="run_any_query",
            arguments=("x",),
            evidence_ids=("evidence-1",),
            created_at=NOW,
        )
    with pytest.raises(ValidationError):
        TypedClaim(
            claim_id="claim",
            snapshot_id="snapshot-1",
            predicate=ClaimPredicate.SOURCE_OBJECT_MATCHES,
            arguments=("one", "two"),
            evidence_ids=("evidence-1",),
            created_at=NOW,
        )
    with pytest.raises(ValidationError):
        TypedClaim(
            claim_id="claim",
            snapshot_id="snapshot-1",
            predicate=ClaimPredicate.OBSERVED_API_SUCCESS,
            arguments=("probe",),
            evidence_ids=("evidence-1",),
            created_at=NOW,
            confidence=0.9,
        )


def test_audit_metadata_has_no_bodies_and_timestamps_are_aware() -> None:
    event = AuditMetadataEvent(
        audit_id="audit-2",
        stage=AuditStage.REQUEST_RECEIVED,
        source="source-1",
        subject=subject(),
        verb="get",
        namespace="workloads",
        api_group="",
        resource="secrets",
        response_code=200,
        occurred_at=NOW,
    )
    assert event.level == "Metadata"
    assert event.occurred_at.tzinfo is not None
    with pytest.raises(ValidationError):
        AuditMetadataEvent(
            audit_id="audit-3",
            stage=AuditStage.RESPONSE_COMPLETE,
            source="source-1",
            subject=subject(),
            verb="get",
            namespace="workloads",
            api_group="",
            resource="secrets",
            response_code=200,
            occurred_at=datetime(2026, 1, 1),
            response_body={"secret": "x"},
        )
    with pytest.raises(ValidationError):
        SourceEnrollment(
            case_id="case-1",
            source_id="source-1",
            source_kind=SourceKind.LOCAL_KIND,
            cluster_name="kind",
            context_name="ctx",
            rbac_scope=scope(),
            fixture_id="fixture",
            fixture_version="1",
            enrolled_at=datetime(2026, 1, 1),
            enrolled_by="operator",
        )


def test_candidate_digest_is_computed_and_tampering_is_rejected() -> None:
    plan = candidate()
    assert plan.canonical_artifact_digest == plan.expected_canonical_artifact_digest()
    assert verify_digest(plan.canonical_artifact_payload(), plan.canonical_artifact_digest)
    with pytest.raises(ValidationError):
        candidate(canonical_artifact_digest=DIGEST)
    with pytest.raises(ValidationError):
        plan.model_copy(update={"rationale": "tampered"})
    changed = candidate(rationale="A different narrow rationale.")
    assert changed.canonical_artifact_digest != plan.canonical_artifact_digest


def test_candidate_direct_fields_are_digest_bound() -> None:
    plan = candidate()
    changed_payload = plan.canonical_artifact_payload()
    changed_payload["policy_version"] = "policy-2"
    assert canonical_digest(changed_payload) != plan.canonical_artifact_digest
    with pytest.raises(ValidationError):
        plan.model_copy(update={"policy_version": "policy-2"})


def test_candidate_direct_and_nested_provenance_must_match() -> None:
    with pytest.raises(ValidationError):
        candidate(source_id="source-2")


def test_rfc8785_numeric_equivalence_and_rejection_of_unsafe_values() -> None:
    assert canonical_json({"value": 1}) == canonical_json({"value": 1.0})
    assert canonical_digest({"value": 1}) == canonical_digest({"value": 1.0})
    with pytest.raises(ValueError):
        canonical_json({"value": float("nan")})
    with pytest.raises(ValueError):
        canonical_json({"value": {1, 2}})
