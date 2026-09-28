from hypothesis import given
from hypothesis import strategies as st

from counterseal.domain import (
    ALLOWED_TRANSITIONS,
    CountersealState,
    RbacRule,
    TransformationType,
    can_transition,
    canonical_digest,
    canonical_json,
)


@given(st.dictionaries(st.text(min_size=1, max_size=12), st.integers(-1000, 1000), max_size=8))
def test_rfc8785_digest_ignores_object_key_order(values: dict[str, int]) -> None:
    reversed_values = dict(reversed(tuple(values.items())))
    assert canonical_json(values) == canonical_json(reversed_values)
    assert canonical_digest(values) == canonical_digest(reversed_values)


@given(st.integers(min_value=-1000, max_value=1000))
def test_rfc8785_integer_and_integral_float_have_same_digest(value: int) -> None:
    assert canonical_digest({"value": value}) == canonical_digest({"value": float(value)})


@given(st.sampled_from(tuple(CountersealState)), st.sampled_from(tuple(CountersealState)))
def test_state_guard_matches_its_closed_transition_table(
    source: CountersealState, target: CountersealState
) -> None:
    assert can_transition(source, target) == (target in ALLOWED_TRANSITIONS[source])


@given(st.sampled_from(("get", "list", "watch")), st.sampled_from(("get", "list", "watch")))
def test_secret_rule_values_are_always_bounded(verb: str, second: str) -> None:
    # Duplicate verbs are rejected; every accepted rule stays in the secret-only grammar.
    if verb == second:
        return
    rule = RbacRule(verbs=(verb, second))
    assert rule.resource == "secrets"
    assert rule.api_group == ""
    assert set(rule.verbs) <= {"get", "list", "watch"}
    assert set(TransformationType) == {
        TransformationType.REMOVE_SECRET_ACCESS,
        TransformationType.REMOVE_SECRET_LIST_WATCH,
        TransformationType.RESTRICT_NAMED_SECRET_ACCESS,
    }
