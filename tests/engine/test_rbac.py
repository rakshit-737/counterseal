from dataclasses import replace
from datetime import UTC, datetime

import pytest

from counterseal.domain import ClaimPredicate, TypedClaim
from counterseal.engine.rbac import (
    AnalysisStatus,
    ApiSuccessFact,
    BindingReferenceFact,
    BusinessInvariantFact,
    ClaimContext,
    ClusterRoleBindingRecord,
    ClusterRoleRecord,
    Completeness,
    EvidenceRef,
    ForbiddenProbeFact,
    PermissionRequest,
    RbacAnalyzer,
    RbacRuleRecord,
    RbacSnapshotRecord,
    ReasonCode,
    RoleBindingRecord,
    RoleRecord,
    RoleRuleFact,
    ServiceAccountRef,
    SnapshotObjectRecord,
    SnapshotScopeFact,
    SourceObjectFact,
    SubjectRecord,
    verify_claim,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def rule(
    *,
    verbs: tuple[str, ...] = ("get",),
    resource_names: tuple[str, ...] = (),
    resources: tuple[str, ...] = ("secrets",),
    api_groups: tuple[str, ...] = ("",),
    rule_id: str | None = None,
) -> RbacRuleRecord:
    return RbacRuleRecord(
        api_groups=api_groups,
        resources=resources,
        verbs=verbs,
        resource_names=resource_names,
        rule_id=rule_id,
    )


def sa_subject(name: str = "worker", namespace: str = "workloads") -> SubjectRecord:
    return SubjectRecord(kind="ServiceAccount", name=name, namespace=namespace)


def base_snapshot(
    *,
    roles: tuple[RoleRecord, ...] = (),
    cluster_roles: tuple[ClusterRoleRecord, ...] = (),
    role_bindings: tuple[RoleBindingRecord, ...] = (),
    cluster_role_bindings: tuple[ClusterRoleBindingRecord, ...] = (),
    complete: bool = True,
    missing_resources: tuple[str, ...] = (),
    unknown_kinds: tuple[str, ...] = (),
    snapshot_id: str = "snapshot-1",
) -> RbacSnapshotRecord:
    return RbacSnapshotRecord(
        snapshot_id=snapshot_id,
        roles=roles,
        cluster_roles=cluster_roles,
        role_bindings=role_bindings,
        cluster_role_bindings=cluster_role_bindings,
        complete=complete,
        missing_resources=missing_resources,
        evidence_ids=("evidence-1",),
        unknown_kinds=unknown_kinds,
    )


def direct_binding_snapshot() -> RbacSnapshotRecord:
    role = RoleRecord(
        name="worker-role",
        namespace="workloads",
        rules=(rule(verbs=("get", "list"), rule_id="rule-1"),),
        evidence_ids=("evidence-1",),
    )
    binding = RoleBindingRecord(
        name="worker-binding",
        namespace="workloads",
        role_ref_kind="Role",
        role_ref_name="worker-role",
        subjects=(sa_subject(),),
        evidence_ids=("evidence-1",),
    )
    return base_snapshot(roles=(role,), role_bindings=(binding,))


def analyze(
    snapshot: RbacSnapshotRecord,
    *,
    namespace: str = "workloads",
    name: str = "worker",
    resource: str = "secrets",
    verb: str | None = None,
    resource_name: str | None = None,
    target_namespace: str | None = None,
):
    return RbacAnalyzer().analyze(
        snapshot,
        ServiceAccountRef(name=name, namespace=namespace),
        resource=resource,
        target_namespace=target_namespace,
        verb=verb,
        resource_name=resource_name,
    )


def test_direct_role_binding_returns_deterministic_secret_permissions() -> None:
    result = analyze(direct_binding_snapshot())

    assert result.status is AnalysisStatus.GRANTED
    assert result.completeness is Completeness.COMPLETE
    assert [(item.verb, item.resource_name) for item in result.effective_permissions] == [
        ("get", None),
        ("list", None),
    ]
    assert len(result.matching_grants) == 2
    assert {node.snapshot_id for node in result.graph_nodes} == {"snapshot-1"}
    assert {edge.snapshot_id for edge in result.graph_edges} == {"snapshot-1"}


def test_role_binding_to_cluster_role_is_scoped_to_binding_namespace() -> None:
    cluster_role = ClusterRoleRecord(
        name="secret-reader",
        rules=(rule(verbs=("get",)),),
        evidence_ids=("evidence-1",),
    )
    binding = RoleBindingRecord(
        name="workload-binding",
        namespace="workloads",
        role_ref_kind="ClusterRole",
        role_ref_name="secret-reader",
        subjects=(sa_subject(),),
        evidence_ids=("evidence-1",),
    )
    result = analyze(base_snapshot(cluster_roles=(cluster_role,), role_bindings=(binding,)))
    other_namespace = analyze(
        base_snapshot(cluster_roles=(cluster_role,), role_bindings=(binding,)),
        namespace="other",
    )

    assert result.status is AnalysisStatus.GRANTED
    assert result.effective_permissions[0].namespace == "workloads"
    assert other_namespace.status is AnalysisStatus.DENIED


def test_cluster_role_binding_applies_cluster_role_in_any_namespace() -> None:
    cluster_role = ClusterRoleRecord(
        name="cluster-secret-reader",
        rules=(rule(verbs=("get",)),),
        evidence_ids=("evidence-1",),
    )
    binding = ClusterRoleBindingRecord(
        name="cluster-binding",
        role_ref_kind="ClusterRole",
        role_ref_name="cluster-secret-reader",
        subjects=(SubjectRecord(kind="Group", name="system:serviceaccounts"),),
        evidence_ids=("evidence-1",),
    )
    result = analyze(
        base_snapshot(cluster_roles=(cluster_role,), cluster_role_bindings=(binding,)),
        namespace="other",
    )

    assert result.status is AnalysisStatus.GRANTED
    assert result.effective_permissions[0].namespace == "other"


def test_service_account_groups_are_all_applicable() -> None:
    role = RoleRecord(
        name="group-role",
        namespace="workloads",
        rules=(rule(),),
        evidence_ids=("evidence-1",),
    )
    bindings = tuple(
        RoleBindingRecord(
            name=f"binding-{index}",
            namespace="workloads",
            role_ref_kind="Role",
            role_ref_name="group-role",
            subjects=(SubjectRecord(kind="Group", name=group),),
            evidence_ids=("evidence-1",),
        )
        for index, group in enumerate(
            ("system:serviceaccounts", "system:serviceaccounts:workloads", "system:authenticated")
        )
    )
    result = analyze(base_snapshot(roles=(role,), role_bindings=bindings))

    assert result.status is AnalysisStatus.GRANTED
    assert len(result.matching_grants) == 3
    assert result.reason_codes.count(ReasonCode.ADDITIVE_GRANT) == 1


def test_alternative_bindings_are_reported_without_deduplicating_grants() -> None:
    role_a = RoleRecord("role-a", "workloads", (rule(),), evidence_ids=("evidence-1",))
    role_b = RoleRecord("role-b", "workloads", (rule(),), evidence_ids=("evidence-1",))
    bindings = tuple(
        RoleBindingRecord(
            name=f"binding-{role.name}",
            namespace="workloads",
            role_ref_kind="Role",
            role_ref_name=role.name,
            subjects=(sa_subject(),),
            evidence_ids=("evidence-1",),
        )
        for role in (role_a, role_b)
    )
    result = analyze(base_snapshot(roles=(role_a, role_b), role_bindings=bindings))

    assert len(result.effective_permissions) == 1
    assert len(result.matching_grants) == 2
    assert len(result.alternative_paths) == 1
    assert len(result.alternative_paths[0].grants) == 2


def test_role_binding_subject_namespace_is_independent_from_grant_namespace() -> None:
    role = RoleRecord("role", "other", (rule(),), evidence_ids=("evidence-1",))
    binding = RoleBindingRecord(
        "binding",
        "other",
        "Role",
        "role",
        (sa_subject(),),
        evidence_ids=("evidence-1",),
    )
    result = analyze(base_snapshot(roles=(role,), role_bindings=(binding,)))

    assert result.status is AnalysisStatus.GRANTED
    assert result.effective_permissions[0].namespace == "other"
    scoped = analyze(
        base_snapshot(roles=(role,), role_bindings=(binding,)),
        target_namespace="workloads",
    )
    assert scoped.status is AnalysisStatus.DENIED
    assert scoped.effective_permissions == ()
    cross_namespace_request = RbacAnalyzer().analyze(
        base_snapshot(roles=(role,), role_bindings=(binding,)),
        ServiceAccountRef("worker", "workloads"),
        request=PermissionRequest(
            resource="secrets",
            verb="get",
            resource_name="cross-namespace-secret",
            namespace="other",
        ),
    )
    assert cross_namespace_request.status is AnalysisStatus.GRANTED


def test_resource_names_are_preserved_and_match_only_named_requests() -> None:
    role = RoleRecord(
        "named-role",
        "workloads",
        (rule(resource_names=("allowed-secret",)),),
        evidence_ids=("evidence-1",),
    )
    binding = RoleBindingRecord(
        "named-binding",
        "workloads",
        "Role",
        "named-role",
        (sa_subject(),),
        evidence_ids=("evidence-1",),
    )
    snapshot = base_snapshot(roles=(role,), role_bindings=(binding,))

    assert (
        analyze(snapshot, name="worker").effective_permissions[0].resource_name == "allowed-secret"
    )
    assert (
        analyze(snapshot, verb="get", resource_name="allowed-secret").status
        is AnalysisStatus.GRANTED
    )
    assert (
        analyze(snapshot, verb="get", resource_name="other-secret").status is AnalysisStatus.DENIED
    )


def test_inventory_is_separate_from_named_request_decisions() -> None:
    role = RoleRecord(
        "named-role",
        "workloads",
        (rule(verbs=("get", "list"), resource_names=("allowed-secret",)),),
        evidence_ids=("evidence-1",),
    )
    binding = RoleBindingRecord(
        "named-binding",
        "workloads",
        "Role",
        "named-role",
        (sa_subject(),),
        evidence_ids=("evidence-1",),
    )
    snapshot = base_snapshot(roles=(role,), role_bindings=(binding,))

    unfiltered_get = analyze(snapshot, verb="get")
    unfiltered_list = analyze(snapshot, verb="list")
    named_get = analyze(snapshot, verb="get", resource_name="allowed-secret")

    assert unfiltered_get.status is AnalysisStatus.UNSUPPORTED
    assert ReasonCode.NAMED_GET_REQUIRES_RESOURCE_NAME in unfiltered_get.reason_codes
    assert unfiltered_get.effective_permissions
    assert unfiltered_list.status is AnalysisStatus.UNSUPPORTED
    assert ReasonCode.NAMED_LIST_WATCH_REQUIRES_FIELD_SELECTOR in unfiltered_list.reason_codes
    assert named_get.status is AnalysisStatus.GRANTED

    field_selected = RbacAnalyzer().analyze(
        snapshot,
        ServiceAccountRef("worker", "workloads"),
        request=PermissionRequest(
            resource="secrets",
            verb="list",
            field_selector_resource_name="allowed-secret",
        ),
    )
    assert field_selected.status is AnalysisStatus.GRANTED


def test_unrestricted_and_named_grants_are_overlapping_alternative_paths() -> None:
    unrestricted = RoleRecord(
        "open",
        "workloads",
        (rule(verbs=("get",)),),
        evidence_ids=("evidence-1",),
    )
    named = RoleRecord(
        "named",
        "workloads",
        (rule(verbs=("get",), resource_names=("one",)),),
        evidence_ids=("evidence-1",),
    )
    bindings = tuple(
        RoleBindingRecord(
            name=f"binding-{role.name}",
            namespace="workloads",
            role_ref_kind="Role",
            role_ref_name=role.name,
            subjects=(sa_subject(),),
            evidence_ids=("evidence-1",),
        )
        for role in (unrestricted, named)
    )
    result = analyze(base_snapshot(roles=(unrestricted, named), role_bindings=bindings))

    assert len(result.alternative_paths) == 1
    assert {grant.permission.resource_name for grant in result.alternative_paths[0].grants} == {
        None,
        "one",
    }


def test_configmaps_are_supported_in_the_same_read_only_subset() -> None:
    role = RoleRecord(
        "config-reader",
        "workloads",
        (rule(resources=("configmaps",), verbs=("get",)),),
        evidence_ids=("evidence-1",),
    )
    binding = RoleBindingRecord(
        "config-binding",
        "workloads",
        "Role",
        "config-reader",
        (sa_subject(),),
        evidence_ids=("evidence-1",),
    )
    snapshot = base_snapshot(roles=(role,), role_bindings=(binding,))
    result = analyze(snapshot, resource="configmaps")
    request = analyze(snapshot, resource="configmaps", verb="get", resource_name="settings")

    assert result.status is AnalysisStatus.GRANTED
    assert result.effective_permissions[0].resource == "configmaps"
    assert request.status is AnalysisStatus.GRANTED


def test_full_service_account_user_identity_and_ambiguous_subjects_fail_closed() -> None:
    role = RoleRecord("reader", "workloads", (rule(),), evidence_ids=("evidence-1",))
    exact_user = RoleBindingRecord(
        "user-binding",
        "workloads",
        "Role",
        "reader",
        (SubjectRecord(kind="User", name="system:serviceaccount:workloads:worker"),),
        evidence_ids=("evidence-1",),
    )
    missing_namespace = RoleBindingRecord(
        "missing-namespace",
        "workloads",
        "Role",
        "reader",
        (SubjectRecord(kind="ServiceAccount", name="worker"),),
        evidence_ids=("evidence-1",),
    )
    unknown_kind = RoleBindingRecord(
        "unknown-subject",
        "workloads",
        "Role",
        "reader",
        (SubjectRecord(kind="Robot", name="worker"),),
        evidence_ids=("evidence-1",),
    )
    exact = analyze(base_snapshot(roles=(role,), role_bindings=(exact_user,)))
    ambiguous = analyze(
        base_snapshot(
            roles=(role,),
            role_bindings=(missing_namespace, unknown_kind),
        )
    )

    assert exact.status is AnalysisStatus.GRANTED
    assert ambiguous.status is AnalysisStatus.UNSUPPORTED
    assert ReasonCode.MISSING_SUBJECT_NAMESPACE in ambiguous.reason_codes
    assert ReasonCode.UNKNOWN_KIND in ambiguous.reason_codes


def test_wildcard_aggregated_unknown_subresource_and_incomplete_inputs_abstain() -> None:
    cases = (
        (RoleRecord("wild", "workloads", (rule(resources=("*",)),)), ()),
        (RoleRecord("aggregated", "workloads", (rule(),), aggregation_rule={"selectors": ()}), ()),
        (RoleRecord("subresource", "workloads", (rule(resources=("secrets/status",)),)), ()),
    )
    for role, _ in cases:
        binding = RoleBindingRecord(
            f"binding-{role.name}",
            "workloads",
            "Role",
            role.name,
            (sa_subject(),),
        )
        result = analyze(base_snapshot(roles=(role,), role_bindings=(binding,)))
        assert result.status in {AnalysisStatus.UNSUPPORTED, AnalysisStatus.ABSTAIN}
    unknown_binding = RoleBindingRecord(
        "unknown-binding",
        "workloads",
        "Widget",
        "role",
        (sa_subject(),),
    )
    unknown = analyze(base_snapshot(role_bindings=(unknown_binding,), unknown_kinds=("Widget",)))
    unknown_with_grant = analyze(
        base_snapshot(
            roles=direct_binding_snapshot().roles,
            role_bindings=direct_binding_snapshot().role_bindings,
            unknown_kinds=("Widget",),
        )
    )
    incomplete = analyze(base_snapshot(complete=False, missing_resources=("ClusterRoleBinding",)))
    assert ReasonCode.UNKNOWN_KIND in unknown.reason_codes
    assert unknown.status is AnalysisStatus.UNSUPPORTED
    assert unknown_with_grant.status is AnalysisStatus.UNSUPPORTED
    assert incomplete.status is AnalysisStatus.ABSTAIN
    assert incomplete.completeness is Completeness.INCOMPLETE


def test_unresolved_wildcard_never_becomes_request_denied() -> None:
    role = RoleRecord("wild", "workloads", (rule(resources=("*",)),), evidence_ids=("evidence-1",))
    binding = RoleBindingRecord(
        "wild-binding",
        "workloads",
        "Role",
        "wild",
        (sa_subject(),),
        evidence_ids=("evidence-1",),
    )
    result = RbacAnalyzer().analyze(
        base_snapshot(roles=(role,), role_bindings=(binding,)),
        ServiceAccountRef("worker", "workloads"),
        request=PermissionRequest(resource="secrets", verb="get", resource_name="payroll-canary"),
    )

    assert result.status is AnalysisStatus.UNSUPPORTED
    assert result.request_status is AnalysisStatus.UNSUPPORTED
    assert result.effective_permissions
    assert result.effective_permissions[0].resource == "*"


def test_field_selector_metadata_name_is_parsed_and_conflicts_fail_closed() -> None:
    request = PermissionRequest(
        resource="secrets",
        verb="list",
        field_selector="metadata.name=report-api-token",
    )
    assert request.field_selector_resource_name == "report-api-token"
    with pytest.raises(ValueError):
        PermissionRequest(
            resource="secrets",
            verb="list",
            field_selector="metadata.name=report-api-token",
            field_selector_resource_name="payroll-canary",
        )


def test_snapshot_ids_are_not_mixed_in_graph_or_permissions() -> None:
    first = direct_binding_snapshot()
    second = RbacSnapshotRecord(
        snapshot_id="snapshot-2",
        roles=tuple(replace(item, snapshot_id=None) for item in first.roles),
        role_bindings=tuple(replace(item, snapshot_id=None) for item in first.role_bindings),
        evidence_ids=("evidence-2",),
    )
    first_result = analyze(first)
    second_result = analyze(second)

    assert first_result.snapshot_id != second_result.snapshot_id
    assert all(node.snapshot_id == first_result.snapshot_id for node in first_result.graph_nodes)
    assert all(edge.snapshot_id == second_result.snapshot_id for edge in second_result.graph_edges)
    assert first_result.graph_nodes != second_result.graph_nodes


def test_typed_claim_verifier_uses_facts_and_rejects_fabricated_evidence() -> None:
    snapshot = direct_binding_snapshot()
    role = snapshot.roles[0]
    binding = snapshot.role_bindings[0]
    role_object_digest = "sha256:" + "1" * 64
    binding_object_digest = "sha256:" + "2" * 64
    object_record = SnapshotObjectRecord(
        object_id="role-object",
        kind="Role",
        name=role.name,
        namespace=role.namespace,
        object_digest=role_object_digest,
        snapshot_id=snapshot.snapshot_id,
        evidence_ids=("evidence-1",),
        source_id="source-1",
    )
    binding_object = SnapshotObjectRecord(
        object_id="binding-object",
        kind="RoleBinding",
        name=binding.name,
        namespace=binding.namespace,
        object_digest=binding_object_digest,
        snapshot_id=snapshot.snapshot_id,
        evidence_ids=("evidence-1",),
        source_id="source-1",
    )
    audit_object = SnapshotObjectRecord(
        object_id="audit-object",
        kind="AuditMetadata",
        name="audit-1",
        namespace=None,
        object_digest="sha256:" + "3" * 64,
        snapshot_id=snapshot.snapshot_id,
        evidence_ids=("evidence-1",),
        source_id="source-1",
    )
    probe_object = SnapshotObjectRecord(
        object_id="probe-object",
        kind="ProbeResult",
        name="probe-1",
        namespace=None,
        object_digest="sha256:" + "4" * 64,
        snapshot_id=snapshot.snapshot_id,
        evidence_ids=("evidence-1",),
        source_id="source-1",
    )
    result_object = SnapshotObjectRecord(
        object_id="result-object",
        kind="BusinessInvariantResult",
        name="result-1",
        namespace=None,
        object_digest="sha256:" + "5" * 64,
        snapshot_id=snapshot.snapshot_id,
        evidence_ids=("evidence-1",),
        source_id="source-1",
    )
    scope_object = SnapshotObjectRecord(
        object_id="scope-object",
        kind="SnapshotScope",
        name="scope-1",
        namespace=None,
        object_digest="sha256:" + "6" * 64,
        snapshot_id=snapshot.snapshot_id,
        evidence_ids=("evidence-1",),
        source_id="source-1",
    )
    context = ClaimContext(
        snapshot=RbacSnapshotRecord(
            snapshot_id=snapshot.snapshot_id,
            roles=snapshot.roles,
            role_bindings=snapshot.role_bindings,
            evidence_ids=snapshot.evidence_ids,
            complete=True,
            objects=(
                object_record,
                binding_object,
                audit_object,
                probe_object,
                result_object,
                scope_object,
            ),
            source_id="source-1",
            scope_id="scope-1",
        ),
        evidence=(EvidenceRef("evidence-1", snapshot.snapshot_id, source_id="source-1"),),
        api_success=(
            ApiSuccessFact(
                "audit-1",
                snapshot.snapshot_id,
                200,
                ("evidence-1",),
                "source-1",
                "audit-object",
                audit_object.object_digest,
            ),
        ),
        binding_references=(
            BindingReferenceFact(
                binding.binding_id,
                role.role_id,
                snapshot.snapshot_id,
                ("evidence-1",),
                "source-1",
                "binding-object",
                binding_object_digest,
            ),
        ),
        role_rules=(
            RoleRuleFact(
                role.role_id,
                "rule-1",
                snapshot.snapshot_id,
                ("evidence-1",),
                "source-1",
                "role-object",
                role_object_digest,
            ),
        ),
        forbidden_probes=(
            ForbiddenProbeFact(
                "probe-1",
                snapshot.snapshot_id,
                403,
                ("evidence-1",),
                "source-1",
                "probe-object",
                probe_object.object_digest,
            ),
        ),
        business_invariants=(
            BusinessInvariantFact(
                "contract-1",
                "result-1",
                snapshot.snapshot_id,
                True,
                ("evidence-1",),
                "source-1",
                "result-object",
                result_object.object_digest,
            ),
        ),
        snapshot_scopes=(
            SnapshotScopeFact(
                snapshot.snapshot_id,
                "scope-1",
                True,
                ("evidence-1",),
                "source-1",
                "scope-object",
                scope_object.object_digest,
            ),
        ),
        source_objects=(
            SourceObjectFact(
                "source-1",
                "role-object",
                role_object_digest,
                snapshot.snapshot_id,
                ("evidence-1",),
            ),
        ),
    )
    claims = tuple(
        TypedClaim(
            claim_id=f"claim-{index}",
            snapshot_id=snapshot.snapshot_id,
            predicate=predicate,
            arguments=arguments,
            evidence_ids=("evidence-1",),
            created_at=NOW,
        )
        for index, (predicate, arguments) in enumerate(
            (
                (ClaimPredicate.OBSERVED_API_SUCCESS, ("audit-1",)),
                (ClaimPredicate.BINDING_REFERENCES_ROLE, (binding.binding_id, role.role_id)),
                (ClaimPredicate.ROLE_CONTAINS_RULE, (role.role_id, "rule-1")),
                (ClaimPredicate.PROBE_RETURNED_FORBIDDEN, ("probe-1",)),
                (ClaimPredicate.BUSINESS_INVARIANT_PASSED, ("contract-1", "result-1")),
                (ClaimPredicate.SNAPSHOT_COMPLETE_FOR_SCOPE, (snapshot.snapshot_id, "scope-1")),
                (
                    ClaimPredicate.SOURCE_OBJECT_MATCHES,
                    ("source-1", "role-object", role_object_digest),
                ),
            )
        )
    )

    assert all(verify_claim(claim, context).verified for claim in claims)
    fabricated = TypedClaim(
        claim_id="c-fabricated",
        snapshot_id=snapshot.snapshot_id,
        predicate=ClaimPredicate.OBSERVED_API_SUCCESS,
        arguments=("audit-1",),
        evidence_ids=("fake-evidence",),
        created_at=NOW,
    )
    narrative_only = TypedClaim(
        claim_id="c-narrative",
        snapshot_id=snapshot.snapshot_id,
        predicate=ClaimPredicate.PROBE_RETURNED_FORBIDDEN,
        arguments=("the-probe-was-forbidden",),
        evidence_ids=("evidence-1",),
        created_at=NOW,
    )
    assert not verify_claim(fabricated, context).verified
    assert not verify_claim(narrative_only, context).verified
    unbound_api = replace(context.api_success[0], object_id=None, object_digest=None)
    unbound_context = replace(context, api_success=(unbound_api,))
    assert not verify_claim(claims[0], unbound_context).verified
    wrong_object_api = replace(
        context.api_success[0],
        object_id="role-object",
        object_digest=role_object_digest,
    )
    assert not verify_claim(claims[0], replace(context, api_success=(wrong_object_api,))).verified
    unscoped_context = replace(
        context,
        snapshot=replace(context.snapshot, scope_id=None),
    )
    assert not verify_claim(claims[5], unscoped_context).verified
