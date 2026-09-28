"""Workflow adjacency only. These guards grant no approval or execution authority.

A future coordinator must separately verify evidence, freshness, policy and
approval. In particular a public CANDIDATE_ONLY label has no transition here.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType

from .enums import CountersealState
from .schemas import PersistedState


class InvalidTransitionError(ValueError):
    def __init__(self, source: CountersealState, target: CountersealState) -> None:
        super().__init__(f"invalid Counterseal transition: {source.value} -> {target.value}")
        self.source, self.target = source, target


@dataclass(frozen=True, slots=True)
class StateTransition:
    from_state: CountersealState
    to_state: CountersealState


_EDGES = {
    "NEW": "INVESTIGATING CANCELLED",
    "INVESTIGATING": "NEEDS_EVIDENCE BASELINING UNSUPPORTED ESCALATED INCONCLUSIVE FAILED CANCELLED",
    "NEEDS_EVIDENCE": "INVESTIGATING INCONCLUSIVE CANCELLED",
    "BASELINING": "EVALUATING NEEDS_EVIDENCE UNSUPPORTED INCONCLUSIVE STALE FAILED CANCELLED",
    "EVALUATING": "NO_SAFE_CANDIDATE AWAITING_APPROVAL NEEDS_EVIDENCE UNSUPPORTED ESCALATED INCONCLUSIVE STALE FAILED CANCELLED",
    "AWAITING_APPROVAL": "APPLYING STALE ESCALATED FAILED CANCELLED",
    "APPLYING": "POSTCHECK INCONCLUSIVE FAILED",
    "POSTCHECK": "MITIGATED_SCOPED ESCALATED INCONCLUSIVE STALE FAILED",
}
ALLOWED_TRANSITIONS: Mapping[CountersealState, frozenset[CountersealState]] = MappingProxyType(
    {
        state: frozenset(CountersealState(s) for s in _EDGES.get(state.value, "").split())
        for state in CountersealState
    }
)


def normalize_state(value: CountersealState | str) -> CountersealState:
    if isinstance(value, CountersealState):
        return value
    if type(value) is not str:
        raise TypeError("workflow state must be a CountersealState or exact wire string")
    return CountersealState(value)


def require_transition(
    source: CountersealState | str, target: CountersealState | str
) -> StateTransition:
    source, target = normalize_state(source), normalize_state(target)
    if target not in ALLOWED_TRANSITIONS[source]:
        raise InvalidTransitionError(source, target)
    return StateTransition(source, target)


def can_transition(source: CountersealState | str, target: CountersealState | str) -> bool:
    try:
        require_transition(source, target)
    except (ValueError, TypeError):
        return False
    return True


def transition(
    current: PersistedState,
    target: CountersealState | str,
    *,
    updated_at: datetime,
    updated_by: str,
    transition_id: str,
    reason: str,
) -> PersistedState:
    """Return a new marker; an allowed edge is not evidence that its gates passed."""
    edge = require_transition(current.state, target)
    next_state = PersistedState(
        case_id=current.case_id,
        state=edge.to_state,
        previous_state=edge.from_state,
        revision=current.revision + 1,
        updated_at=updated_at,
        updated_by=updated_by,
        transition_id=transition_id,
        reason=reason,
    )
    if next_state.updated_at < current.updated_at:
        raise ValueError("workflow time cannot move backwards")
    return next_state


def apply_transition(
    current: PersistedState,
    target: CountersealState | str,
    *,
    updated_at: datetime,
    updated_by: str,
    transition_id: str,
    reason: str,
) -> PersistedState:
    """Explicit alias for adapters; it still performs no authorization check."""
    return transition(
        current,
        target,
        updated_at=updated_at,
        updated_by=updated_by,
        transition_id=transition_id,
        reason=reason,
    )
