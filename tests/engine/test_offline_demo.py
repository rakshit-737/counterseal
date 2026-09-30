from counterseal.domain import TransformationType
from counterseal.engine.compiler import CompiledCandidate, compile_candidate
from counterseal.engine.offline_demo import (
    DemoCandidate,
    build_demo_role_snapshot,
    run_candidate_matrix,
)
from counterseal.engine.policy import CompileRequest


def test_demo_fixture_is_deterministic_and_preserves_configmap_rule() -> None:
    first = run_candidate_matrix()
    second = run_candidate_matrix()

    assert first == second
    assert first.fixture_id == "counterseal-demo-role-v1"
    assert {item.name for item in first.candidates} == set(DemoCandidate)
    assert all(item.status == "CANDIDATE_ONLY" for item in first.candidates)


def test_demo_candidate_c_compiles_named_get_without_claiming_validation() -> None:
    snapshot = build_demo_role_snapshot()
    result = compile_candidate(
        CompileRequest(
            snapshot=snapshot,
            transformation=TransformationType.RESTRICT_NAMED_SECRET_ACCESS,
            approved_secret_name="report-api-token",
            expected_uid=snapshot.uid,
            expected_resource_version=snapshot.resource_version,
            supporting_claim_ids=("claim-role-visibility",),
        )
    )

    assert isinstance(result, CompiledCandidate)
    assert result.status.value == "CANDIDATE_ONLY"
    assert result.approval_eligible is False
    assert result.operations[0].after is not None
    assert result.operations[0].after.verbs == ("get",)
    assert result.operations[0].after.resource_names == ("report-api-token",)
