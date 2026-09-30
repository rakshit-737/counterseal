"""Small synthetic Phase 2 demonstration with no external I/O.

This module demonstrates candidate *compilation* only.  It deliberately does
not claim that any candidate blocks an attack or preserves a workload: those
claims require the later rehearsal and independent-verifier phases.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from counterseal.domain import RbacSubject, RbacSubjectKind, TransformationType, canonical_digest

from .compiler import CompiledCandidate, compile_candidate
from .policy import BindingObservation, PolicyDecision, RoleRuleObservation, RoleSnapshot


class DemoCandidate(StrEnum):
    REMOVE_SECRET_ACCESS = "A_REMOVE_SECRET_ACCESS"
    REMOVE_LIST_WATCH = "B_REMOVE_LIST_WATCH"
    RESTRICT_NAMED_GET = "C_RESTRICT_NAMED_GET"


@dataclass(frozen=True, slots=True)
class OfflineCandidateSummary:
    name: DemoCandidate
    decision: PolicyDecision
    status: str
    reason_codes: tuple[str, ...]
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class OfflineMatrixResult:
    fixture_id: str
    fixture_digest: str
    candidates: tuple[OfflineCandidateSummary, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "fixture_id": self.fixture_id,
            "fixture_digest": self.fixture_digest,
            "candidates": [
                {
                    "name": item.name.value,
                    "decision": item.decision.value,
                    "status": item.status,
                    "reason_codes": list(item.reason_codes),
                    "artifact_digest": item.artifact_digest,
                }
                for item in self.candidates
            ],
            "claim_boundary": (
                "Compilation only. No Kubernetes authorization, rehearsal, workload, "
                "or production-safety result is produced."
            ),
        }


def _subject() -> RbacSubject:
    return RbacSubject(
        kind=RbacSubjectKind.SERVICE_ACCOUNT,
        name="report-worker",
        namespace="counterseal-demo",
    )


def build_demo_role_snapshot() -> RoleSnapshot:
    """Return the synthetic broad-secret-access Role fixture."""

    return RoleSnapshot(
        name="report-worker",
        namespace="counterseal-demo",
        uid="role-uid-1",
        resource_version="17",
        dedicated=True,
        dedicated_to=_subject(),
        rules=(
            RoleRuleObservation(
                rule_index=0,
                resource="secrets",
                verbs=("get", "list", "watch"),
            ),
            RoleRuleObservation(
                rule_index=1,
                resource="configmaps",
                verbs=("get",),
            ),
        ),
        complete=True,
        visibility_complete=True,
        bindings_complete=True,
        bindings=(
            BindingObservation(
                kind="RoleBinding",
                name="report-worker",
                role_kind="Role",
                role_name="report-worker",
                namespace="counterseal-demo",
                subject=_subject(),
                known=True,
            ),
        ),
        unknown_alternative_grants=False,
    )


def _summary(name: DemoCandidate, result: object) -> OfflineCandidateSummary:
    model_dump = getattr(result, "model_dump", None)
    payload = model_dump(mode="python") if callable(model_dump) else {"result": str(type(result))}
    digest = canonical_digest(payload)
    decision = getattr(result, "decision", PolicyDecision.UNSUPPORTED)
    reason_codes = tuple(code.value for code in getattr(result, "reason_codes", ()))
    status = getattr(result, "status", "UNSUPPORTED")
    status_value = getattr(status, "value", str(status))
    return OfflineCandidateSummary(
        name=name,
        decision=decision,
        status=status_value,
        reason_codes=reason_codes,
        artifact_digest=digest,
    )


def run_candidate_matrix() -> OfflineMatrixResult:
    """Compile Candidates A/B/C against one deterministic synthetic snapshot."""

    snapshot = build_demo_role_snapshot()
    results: list[OfflineCandidateSummary] = []
    requests = (
        (DemoCandidate.REMOVE_SECRET_ACCESS, TransformationType.REMOVE_SECRET_ACCESS, None),
        (DemoCandidate.REMOVE_LIST_WATCH, TransformationType.REMOVE_SECRET_LIST_WATCH, None),
        (
            DemoCandidate.RESTRICT_NAMED_GET,
            TransformationType.RESTRICT_NAMED_SECRET_ACCESS,
            "report-api-token",
        ),
    )
    for name, transformation, approved_name in requests:
        from .policy import CompileRequest

        request = CompileRequest(
            snapshot=snapshot,
            transformation=transformation,
            approved_secret_name=approved_name,
            expected_uid=snapshot.uid,
            expected_resource_version=snapshot.resource_version,
            supporting_claim_ids=("claim-role-visibility",),
        )
        result = compile_candidate(request)
        if isinstance(result, CompiledCandidate):
            # Keep the explicit type check in the demo: this is an artifact,
            # not a shortcut that turns policy output into a validation result.
            assert result.status.value == "CANDIDATE_ONLY"
        results.append(_summary(name, result))
    return OfflineMatrixResult(
        fixture_id="counterseal-demo-role-v1",
        fixture_digest=snapshot.canonical_digest(),
        candidates=tuple(results),
    )


__all__ = [
    "DemoCandidate",
    "OfflineCandidateSummary",
    "OfflineMatrixResult",
    "build_demo_role_snapshot",
    "run_candidate_matrix",
]
