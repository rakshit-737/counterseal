from __future__ import annotations

import pytest
from pydantic import ValidationError

from counterseal.domain import RbacSubject, RbacSubjectKind, TransformationType
from counterseal.engine.compiler import (
    CandidateStatus,
    CompiledCandidate,
    compile_candidate,
)
from counterseal.engine.policy import (
    BindingObservation,
    CompileRequest,
    PolicyDecision,
    ReasonCode,
    RoleRuleObservation,
    RoleSnapshot,
)


def subject() -> RbacSubject:
    return RbacSubject(kind=RbacSubjectKind.SERVICE_ACCOUNT, name="worker", namespace="workloads")


def binding(
    *, role_name: str = "worker-role", subject_value: RbacSubject | None = None, **overrides: object
) -> BindingObservation:
    values: dict[str, object] = {
        "kind": "RoleBinding",
        "name": "worker-binding",
        "role_kind": "Role",
        "role_name": role_name,
        "namespace": "workloads",
        "subject": subject() if subject_value is None else subject_value,
        "known": True,
    }
    values.update(overrides)
    return BindingObservation(**values)


def snapshot(*rules: RoleRuleObservation, **overrides: object) -> RoleSnapshot:
    values: dict[str, object] = {
        "name": "worker-role",
        "namespace": "workloads",
        "uid": "uid-1",
        "resource_version": "rv-1",
        "dedicated": True,
        "dedicated_to": subject(),
        "rules": rules,
        "complete": True,
        "visibility_complete": True,
        "bindings_complete": True,
        "bindings": (binding(),),
    }
    values.update(overrides)
    return RoleSnapshot(**values)


def request(
    snap: RoleSnapshot,
    transformation: TransformationType,
    **overrides: object,
) -> CompileRequest:
    values: dict[str, object] = {
        "snapshot": snap,
        "transformation": transformation,
        "expected_uid": snap.uid,
        "expected_resource_version": snap.resource_version,
        "supporting_claim_ids": ("claim-role-1",),
    }
    values.update(overrides)
    return CompileRequest(**values)


def test_a_removes_secret_rules_and_preserves_supported_configmap_rules() -> None:
    result = compile_candidate(
        request(
            snapshot(
                RoleRuleObservation(rule_index=0, verbs=("get", "list", "watch")),
                RoleRuleObservation(rule_index=1, resource="configmaps", verbs=("get", "list")),
            ),
            TransformationType.REMOVE_SECRET_ACCESS,
        )
    )

    assert isinstance(result, CompiledCandidate)
    assert result.decision is PolicyDecision.ELIGIBLE
    assert result.approval_eligible is False
    assert result.status is CandidateStatus.CANDIDATE_ONLY
    assert tuple(delta.rule_index for delta in result.deltas) == (0,)
    assert result.operations[0].after is None
    assert tuple(rule.rule_index for rule in result.preserved_rules) == (1,)
    assert result.preserved_rules[0].resource == "configmaps"


def test_b_removes_list_watch_and_preserves_get() -> None:
    result = compile_candidate(
        request(
            snapshot(RoleRuleObservation(rule_index=0, verbs=("watch", "get", "list"))),
            TransformationType.REMOVE_SECRET_LIST_WATCH,
        )
    )

    assert isinstance(result, CompiledCandidate)
    assert result.operations[0].after is not None
    assert result.operations[0].after.verbs == ("get",)
    assert result.operations[0].after.resource_names == ()


def test_b_removes_a_list_watch_only_rule() -> None:
    result = compile_candidate(
        request(
            snapshot(RoleRuleObservation(rule_index=0, verbs=("list", "watch"))),
            TransformationType.REMOVE_SECRET_LIST_WATCH,
        )
    )

    assert isinstance(result, CompiledCandidate)
    assert result.operations[0].after is None


def test_c_restricts_get_and_removes_list_watch_to_the_approved_secret() -> None:
    result = compile_candidate(
        request(
            snapshot(
                RoleRuleObservation(
                    rule_index=0,
                    verbs=("get", "list", "watch"),
                    resource_names=("other", "report-api-token"),
                )
            ),
            TransformationType.RESTRICT_NAMED_SECRET_ACCESS,
            approved_secret_name="report-api-token",
        )
    )

    assert isinstance(result, CompiledCandidate)
    assert result.decision is PolicyDecision.ELIGIBLE
    assert len(result.operations) == 1
    assert result.operations[0].after is not None
    assert result.operations[0].after.verbs == ("get",)
    assert result.operations[0].after.resource_names == ("report-api-token",)


def test_c_removes_separate_list_watch_only_rule() -> None:
    result = compile_candidate(
        request(
            snapshot(
                RoleRuleObservation(rule_index=0, verbs=("get",)),
                RoleRuleObservation(rule_index=1, verbs=("list", "watch")),
            ),
            TransformationType.RESTRICT_NAMED_SECRET_ACCESS,
            approved_secret_name="report-api-token",
        )
    )

    assert isinstance(result, CompiledCandidate)
    assert tuple(delta.rule_index for delta in result.deltas) == (0, 1)
    assert result.operations[1].after is None


def test_c_restricts_named_subset_and_rejects_named_widening_or_no_op() -> None:
    narrowed = compile_candidate(
        request(
            snapshot(
                RoleRuleObservation(
                    rule_index=0,
                    verbs=("get",),
                    resource_names=("other", "report-api-token"),
                )
            ),
            TransformationType.RESTRICT_NAMED_SECRET_ACCESS,
            approved_secret_name="report-api-token",
        )
    )
    assert isinstance(narrowed, CompiledCandidate)
    assert narrowed.operations[0].after.resource_names == ("report-api-token",)

    widening = compile_candidate(
        request(
            snapshot(
                RoleRuleObservation(
                    rule_index=0, verbs=("get",), resource_names=("report-api-token",)
                )
            ),
            TransformationType.RESTRICT_NAMED_SECRET_ACCESS,
            approved_secret_name="other",
        )
    )
    assert widening.decision is PolicyDecision.REJECTED
    assert ReasonCode.PERMISSION_WIDENING in widening.reason_codes

    no_op = compile_candidate(
        request(
            snapshot(
                RoleRuleObservation(
                    rule_index=0, verbs=("get",), resource_names=("report-api-token",)
                )
            ),
            TransformationType.RESTRICT_NAMED_SECRET_ACCESS,
            approved_secret_name="report-api-token",
        )
    )
    assert no_op.decision is PolicyDecision.REJECTED
    assert ReasonCode.NO_OP in no_op.reason_codes


def test_requested_after_widening_is_rejected() -> None:
    result = compile_candidate(
        request(
            snapshot(RoleRuleObservation(rule_index=0, verbs=("get", "list"))),
            TransformationType.REMOVE_SECRET_LIST_WATCH,
            requested_after=RoleRuleObservation(rule_index=0, verbs=("get", "list")),
        )
    )

    assert result.decision is PolicyDecision.REJECTED
    assert ReasonCode.PERMISSION_WIDENING in result.reason_codes


def test_malformed_requested_after_is_typed_rejection_not_an_exception() -> None:
    result = compile_candidate(
        request(
            snapshot(RoleRuleObservation(rule_index=0, verbs=("get", "list"))),
            TransformationType.REMOVE_SECRET_LIST_WATCH,
            requested_after=RoleRuleObservation(rule_index=0, verbs=("wat",)),
        )
    )

    assert result.decision is PolicyDecision.REJECTED
    assert ReasonCode.UNSUPPORTED_RULE in result.reason_codes


def test_alternative_binding_and_unknown_grants_fail_closed() -> None:
    rejected = compile_candidate(
        request(
            snapshot(
                RoleRuleObservation(rule_index=0, verbs=("get",)),
                bindings=(binding(role_name="other-role"),),
            ),
            TransformationType.REMOVE_SECRET_ACCESS,
        )
    )
    assert rejected.decision is PolicyDecision.REJECTED
    assert ReasonCode.ALTERNATIVE_BINDING in rejected.reason_codes

    inconclusive = compile_candidate(
        request(
            snapshot(
                RoleRuleObservation(rule_index=0, verbs=("get",)),
                bindings=(binding(known=False),),
            ),
            TransformationType.REMOVE_SECRET_ACCESS,
        )
    )
    assert inconclusive.decision is PolicyDecision.INCONCLUSIVE
    assert ReasonCode.UNKNOWN_ALTERNATIVE_GRANT in inconclusive.reason_codes

    unrelated = compile_candidate(
        request(
            snapshot(
                RoleRuleObservation(rule_index=0, verbs=("get",)),
                bindings=(
                    binding(),
                    binding(
                        role_name="other-role",
                        subject_value=RbacSubject(
                            kind=RbacSubjectKind.SERVICE_ACCOUNT,
                            name="other",
                            namespace="workloads",
                        ),
                    ),
                ),
            ),
            TransformationType.REMOVE_SECRET_ACCESS,
        )
    )
    assert unrelated.decision is PolicyDecision.ELIGIBLE


def test_stale_identity_and_incomplete_visibility_are_ineligible() -> None:
    stale = compile_candidate(
        request(
            snapshot(RoleRuleObservation(rule_index=0, verbs=("get",))),
            TransformationType.REMOVE_SECRET_ACCESS,
            expected_uid="uid-old",
            expected_resource_version="rv-old",
        )
    )
    assert stale.decision is PolicyDecision.INCONCLUSIVE
    assert ReasonCode.STALE_UID in stale.reason_codes
    assert ReasonCode.STALE_RESOURCE_VERSION in stale.reason_codes

    incomplete = compile_candidate(
        request(
            snapshot(RoleRuleObservation(rule_index=0, verbs=("get",)), visibility_complete=False),
            TransformationType.REMOVE_SECRET_ACCESS,
        )
    )
    assert incomplete.decision is PolicyDecision.INCONCLUSIVE
    assert ReasonCode.INCOMPLETE_VISIBILITY in incomplete.reason_codes


def test_snapshot_completeness_defaults_false_and_missing_binding_is_unknown() -> None:
    snap = RoleSnapshot(
        name="worker-role",
        namespace="workloads",
        uid="uid-1",
        resource_version="rv-1",
        dedicated=True,
        dedicated_to=subject(),
        rules=(RoleRuleObservation(rule_index=0, verbs=("get",)),),
    )
    result = compile_candidate(
        request(snap, TransformationType.REMOVE_SECRET_ACCESS),
    )
    assert result.decision is PolicyDecision.INCONCLUSIVE
    assert ReasonCode.INCOMPLETE_SNAPSHOT in result.reason_codes
    assert ReasonCode.INCOMPLETE_VISIBILITY in result.reason_codes
    assert ReasonCode.UNKNOWN_CONSUMER in result.reason_codes


def test_wildcard_mixed_and_unsupported_rules_are_rejected() -> None:
    wildcard = compile_candidate(
        request(
            snapshot(RoleRuleObservation(rule_index=0, verbs=("*",))),
            TransformationType.REMOVE_SECRET_ACCESS,
        )
    )
    assert wildcard.decision is PolicyDecision.REJECTED
    assert ReasonCode.WILDCARD_RULE in wildcard.reason_codes

    mixed = compile_candidate(
        request(
            snapshot(
                RoleRuleObservation(
                    rule_index=0, resources=("secrets", "configmaps"), verbs=("get",)
                )
            ),
            TransformationType.REMOVE_SECRET_ACCESS,
        )
    )
    assert mixed.decision is PolicyDecision.REJECTED
    assert ReasonCode.MIXED_RESOURCE_RULE in mixed.reason_codes

    unsupported = compile_candidate(
        request(
            snapshot(RoleRuleObservation(rule_index=0, resource="pods", verbs=("get",))),
            TransformationType.REMOVE_SECRET_ACCESS,
        )
    )
    assert unsupported.decision is PolicyDecision.REJECTED
    assert ReasonCode.UNSUPPORTED_RULE in unsupported.reason_codes


def test_wrong_kind_namespace_and_binding_edits_are_rejected() -> None:
    wrong_kind = compile_candidate(
        request(
            snapshot(RoleRuleObservation(rule_index=0, verbs=("get",)), kind="ClusterRole"),
            TransformationType.REMOVE_SECRET_ACCESS,
        )
    )
    assert wrong_kind.decision is PolicyDecision.REJECTED
    assert ReasonCode.CLUSTER_SCOPED_ROLE in wrong_kind.reason_codes

    wrong_namespace = compile_candidate(
        request(
            snapshot(RoleRuleObservation(rule_index=0, verbs=("get",)), namespace=None),
            TransformationType.REMOVE_SECRET_ACCESS,
        )
    )
    assert wrong_namespace.decision is PolicyDecision.REJECTED
    assert ReasonCode.WRONG_NAMESPACE in wrong_namespace.reason_codes

    binding_edit = compile_candidate(
        request(
            snapshot(RoleRuleObservation(rule_index=0, verbs=("get",))),
            TransformationType.REMOVE_SECRET_ACCESS,
            edited_kinds=("RoleBinding",),
        )
    )
    assert binding_edit.decision is PolicyDecision.REJECTED
    assert ReasonCode.ROLE_BINDING_EDIT in binding_edit.reason_codes


def test_non_dedicated_duplicate_ambiguous_and_aggregated_inputs_are_rejected() -> None:
    non_dedicated = compile_candidate(
        request(
            snapshot(RoleRuleObservation(rule_index=0, verbs=("get",)), dedicated=False),
            TransformationType.REMOVE_SECRET_ACCESS,
        )
    )
    assert non_dedicated.decision is PolicyDecision.REJECTED
    assert ReasonCode.NON_DEDICATED_ROLE in non_dedicated.reason_codes

    duplicate = compile_candidate(
        request(
            snapshot(
                RoleRuleObservation(rule_index=0, verbs=("get",)),
                RoleRuleObservation(rule_index=0, verbs=("get",)),
            ),
            TransformationType.REMOVE_SECRET_ACCESS,
        )
    )
    assert duplicate.decision is PolicyDecision.REJECTED
    assert ReasonCode.DUPLICATE_RULE in duplicate.reason_codes

    ambiguous = compile_candidate(
        request(
            snapshot(
                RoleRuleObservation(rule_index=0, verbs=("get",)),
                RoleRuleObservation(rule_index=1, verbs=("get",), resource_names=("one",)),
            ),
            TransformationType.REMOVE_SECRET_ACCESS,
        )
    )
    assert ambiguous.decision is PolicyDecision.REJECTED
    assert ReasonCode.AMBIGUOUS_RULE in ambiguous.reason_codes

    aggregated = compile_candidate(
        request(
            snapshot(RoleRuleObservation(rule_index=0, verbs=("get",)), aggregated=True),
            TransformationType.REMOVE_SECRET_ACCESS,
        )
    )
    assert aggregated.decision is PolicyDecision.REJECTED
    assert ReasonCode.AGGREGATED_ROLE in aggregated.reason_codes


def test_arbitrary_manifest_command_and_missing_claims_are_rejected() -> None:
    assert compile_candidate({"kind": "Role"}).decision is PolicyDecision.REJECTED
    assert compile_candidate("kubectl apply -f role.yaml").decision is PolicyDecision.REJECTED

    snap = snapshot(RoleRuleObservation(rule_index=0, verbs=("get",)))
    constructed = CompileRequest.model_construct(
        snapshot=snap,
        transformation=TransformationType.REMOVE_SECRET_ACCESS,
        expected_uid=snap.uid,
        expected_resource_version=snap.resource_version,
        supporting_claim_ids=(),
    )
    assert compile_candidate(constructed).decision is PolicyDecision.REJECTED


def test_model_copy_revalidates_and_digest_is_stable() -> None:
    snap = snapshot(
        RoleRuleObservation(rule_index=1, verbs=("watch", "get")),
        RoleRuleObservation(rule_index=0, resource="configmaps", verbs=("list", "get")),
    )
    with pytest.raises(ValidationError):
        snap.model_copy(update={"uid": ""})

    first = compile_candidate(
        request(
            snap,
            TransformationType.REMOVE_SECRET_LIST_WATCH,
            supporting_claim_ids=("claim-b", "claim-a"),
        )
    )
    second = compile_candidate(
        request(
            snapshot(
                RoleRuleObservation(rule_index=0, resource="configmaps", verbs=("get", "list")),
                RoleRuleObservation(rule_index=1, verbs=("get", "watch")),
            ),
            TransformationType.REMOVE_SECRET_LIST_WATCH,
            supporting_claim_ids=("claim-a", "claim-b"),
        )
    )
    assert isinstance(first, CompiledCandidate)
    assert isinstance(second, CompiledCandidate)
    assert first.digest == second.digest
    assert first.operations == second.operations
