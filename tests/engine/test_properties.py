from hypothesis import given
from hypothesis import strategies as st

from counterseal.domain import TransformationType
from counterseal.engine.compiler import CompiledCandidate, compile_candidate
from counterseal.engine.offline_demo import build_demo_role_snapshot
from counterseal.engine.policy import CompileRequest


@given(st.permutations((0, 1)))
def test_role_rule_order_does_not_change_fixture_or_candidate_digest(
    permutation: list[int],
) -> None:
    baseline = build_demo_role_snapshot()
    reordered = baseline.model_copy(
        update={"rules": tuple(baseline.rules[index] for index in permutation)}
    )

    assert reordered.canonical_digest() == baseline.canonical_digest()
    request = CompileRequest(
        snapshot=reordered,
        transformation=TransformationType.RESTRICT_NAMED_SECRET_ACCESS,
        approved_secret_name="report-api-token",
        expected_uid=reordered.uid,
        expected_resource_version=reordered.resource_version,
        supporting_claim_ids=("claim-role-visibility",),
    )
    result = compile_candidate(request)
    assert isinstance(result, CompiledCandidate)
    assert (
        result.canonical_digest()
        == compile_candidate(request.model_copy(update={"snapshot": baseline})).canonical_digest()
    )
