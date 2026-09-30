"""Deterministic compiler for the bounded namespaced-Role transformations."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, StrictStr, ValidationError, model_validator

from counterseal.domain import (
    CanonicalCompiledDiff,
    PlanOperation,
    RbacRule,
    TargetObjectIdentity,
    TransformationType,
)

from .policy import (
    CompileRequest,
    PolicyDecision,
    PolicyGate,
    PolicyResult,
    ReasonCode,
    RejectedResult,
    RoleRuleObservation,
    RoleSnapshot,
    TypedRuleDelta,
    UnsupportedResult,
    revalidate_request,
)

Digest = Annotated[StrictStr, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
Name = Annotated[StrictStr, Field(min_length=1, max_length=253)]
Identifier = Annotated[StrictStr, Field(min_length=1, max_length=128)]
BoundedDeltas = Annotated[tuple[TypedRuleDelta, ...], Field(min_length=1, max_length=256)]
BoundedOperations = Annotated[tuple[PlanOperation, ...], Field(min_length=1, max_length=256)]


class CandidateStatus(StrEnum):
    CANDIDATE_ONLY = "CANDIDATE_ONLY"


class CompiledCandidate(PolicyResult):
    """A typed, digestable candidate; it is not an approval or apply request."""

    decision: Literal[PolicyDecision.ELIGIBLE] = PolicyDecision.ELIGIBLE
    status: Literal[CandidateStatus.CANDIDATE_ONLY] = CandidateStatus.CANDIDATE_ONLY
    source_snapshot_digest: Digest
    target_object_identity: TargetObjectIdentity
    target_uid: Identifier
    target_resource_version: Identifier
    transformation: TransformationType
    preserved_rules: tuple[RoleRuleObservation, ...]
    deltas: BoundedDeltas
    operations: BoundedOperations

    @model_validator(mode="after")
    def canonical_shape(self) -> Self:
        deltas = tuple(sorted(self.deltas, key=lambda item: item.rule_index))
        operations = tuple(sorted(self.operations, key=lambda item: item.rule_index))
        if tuple(item.rule_index for item in deltas) != tuple(
            item.rule_index for item in operations
        ):
            raise ValueError("deltas and operations must cover the same rule indexes")
        if any(item.transformation is not self.transformation for item in deltas):
            raise ValueError("all deltas must use the declared transformation")
        if len({item.rule_index for item in deltas}) != len(deltas):
            raise ValueError("each source rule may be changed only once")
        if operations != tuple(delta.to_plan_operation() for delta in deltas):
            raise ValueError("operations must exactly match their typed rule deltas")
        object.__setattr__(self, "deltas", deltas)
        object.__setattr__(self, "operations", operations)
        object.__setattr__(
            self,
            "preserved_rules",
            tuple(sorted(self.preserved_rules, key=lambda item: item.rule_index)),
        )
        return self

    @property
    def candidate_status(self) -> CandidateStatus:
        return self.status

    @property
    def compiled_diff(self) -> CanonicalCompiledDiff:
        return CanonicalCompiledDiff(operations=self.operations)

    @property
    def canonical_compiled_diff(self) -> CanonicalCompiledDiff:
        return self.compiled_diff

    @property
    def rule_deltas(self) -> tuple[TypedRuleDelta, ...]:
        return self.deltas


CompileResult = PolicyResult


def _canonical_rule(rule: RoleRuleObservation) -> RbacRule:
    order = {"get": 0, "list": 1, "watch": 2}
    return RbacRule(
        api_group="",
        resource=rule.resource_set[0],
        verbs=tuple(sorted(rule.verbs, key=lambda verb: (order.get(verb, 99), verb))),
        resource_names=tuple(sorted(rule.resource_names)),
    )


def _rule_delta(
    rule: RoleRuleObservation, transformation: TransformationType, after: RbacRule | None
) -> TypedRuleDelta:
    return TypedRuleDelta(
        operation_id=f"operation-{rule.rule_index}",
        rule_index=rule.rule_index,
        transformation=transformation,
        before=_canonical_rule(rule),
        after=after,
    )


def _rejection(request: CompileRequest, reason: ReasonCode) -> RejectedResult:
    return RejectedResult(
        reason_codes=(reason,),
        supporting_claim_ids=request.supporting_claim_ids,
    )


def _requested_after(request: CompileRequest, expected: RbacRule | None) -> RejectedResult | None:
    if request.requested_after is None:
        return None
    if expected is None:
        return _rejection(request, ReasonCode.PERMISSION_WIDENING)
    try:
        requested = _canonical_rule(request.requested_after)
    except (ValidationError, TypeError, ValueError):
        return _rejection(request, ReasonCode.UNSUPPORTED_RULE)
    if requested != expected:
        return _rejection(request, ReasonCode.PERMISSION_WIDENING)
    return None


def _after_without_list_watch(before: RbacRule) -> RbacRule | None:
    verbs = tuple(verb for verb in before.verbs if verb not in {"list", "watch"})
    return RbacRule(verbs=verbs, resource_names=before.resource_names) if verbs else None


def _secret_rules(snapshot: RoleSnapshot) -> tuple[RoleRuleObservation, ...]:
    return tuple(rule for rule in snapshot.rules if rule.is_secret)


class CandidateCompiler:
    """Compile a revalidated typed request through the policy gate."""

    def __init__(self, policy_gate: PolicyGate | None = None) -> None:
        self._policy_gate = policy_gate or PolicyGate()

    def compile(self, request: object) -> CompileResult:
        policy = self._policy_gate.evaluate(request)
        if policy.decision is not PolicyDecision.ELIGIBLE:
            return policy
        checked = revalidate_request(request)
        if not isinstance(checked, CompileRequest):
            return checked
        request = checked
        snapshot = request.snapshot
        secret_rules = _secret_rules(snapshot)
        preserved_rules = tuple(rule for rule in snapshot.rules if not rule.is_secret)
        deltas: list[TypedRuleDelta] = []

        if request.transformation is TransformationType.REMOVE_SECRET_ACCESS:
            requested = _requested_after(request, None)
            if requested is not None:
                return requested
            deltas = [_rule_delta(rule, request.transformation, None) for rule in secret_rules]

        elif request.transformation is TransformationType.REMOVE_SECRET_LIST_WATCH:
            changed = [
                (rule, _canonical_rule(rule))
                for rule in secret_rules
                if set(rule.verbs).intersection({"list", "watch"})
            ]
            if not changed:
                return _rejection(
                    request,
                    ReasonCode.PERMISSION_WIDENING
                    if request.requested_after is not None
                    else ReasonCode.NO_OP,
                )
            if request.requested_after is not None:
                if len(changed) != 1:
                    return _rejection(request, ReasonCode.AMBIGUOUS_RULE)
                requested = _requested_after(request, _after_without_list_watch(changed[0][1]))
                if requested is not None:
                    return requested
            deltas = [
                _rule_delta(rule, request.transformation, _after_without_list_watch(before))
                for rule, before in changed
            ]

        elif request.transformation is TransformationType.RESTRICT_NAMED_SECRET_ACCESS:
            approved = request.approved_secret_name
            if approved is None:
                return _rejection(request, ReasonCode.MISSING_APPROVED_SECRET)
            get_rules = [rule for rule in secret_rules if "get" in rule.verbs]
            if len(get_rules) != 1:
                return _rejection(
                    request,
                    ReasonCode.MISSING_GET_PERMISSION
                    if not get_rules
                    else ReasonCode.AMBIGUOUS_RULE,
                )
            get_rule = get_rules[0]
            before_get = _canonical_rule(get_rule)
            old_names = set(before_get.resource_names)
            if old_names and approved not in old_names:
                return _rejection(request, ReasonCode.PERMISSION_WIDENING)
            after_get = RbacRule(verbs=("get",), resource_names=(approved,))
            if request.requested_after is not None:
                requested = _requested_after(request, after_get)
                if requested is not None:
                    return requested
            if before_get != after_get:
                deltas.append(_rule_delta(get_rule, request.transformation, after_get))
            for rule in secret_rules:
                if rule.rule_index == get_rule.rule_index:
                    continue
                before = _canonical_rule(rule)
                if set(before.verbs).intersection({"list", "watch"}):
                    deltas.append(_rule_delta(rule, request.transformation, None))

        else:
            return UnsupportedResult(
                reason_codes=(ReasonCode.UNSUPPORTED_TRANSFORMATION,),
                supporting_claim_ids=request.supporting_claim_ids,
            )

        if not deltas:
            return _rejection(request, ReasonCode.NO_OP)
        deltas = sorted(deltas, key=lambda item: item.rule_index)
        try:
            operations = [delta.to_plan_operation() for delta in deltas]
            CanonicalCompiledDiff(operations=tuple(operations))
        except (ValidationError, TypeError, ValueError):
            # The domain PlanOperation grammar is the typed conversion boundary.
            # Do not bypass it with model_construct or a generic manifest.
            return UnsupportedResult(
                reason_codes=(ReasonCode.UNSUPPORTED_RULE,),
                supporting_claim_ids=request.supporting_claim_ids,
            )
        target = request.target_object_identity or TargetObjectIdentity(
            namespace=snapshot.namespace,
            name=snapshot.name,
            dedicated=True,
            dedicated_to=snapshot.dedicated_to,
        )
        return CompiledCandidate(
            source_snapshot_digest=snapshot.canonical_digest(),
            target_object_identity=target,
            target_uid=snapshot.uid,
            target_resource_version=snapshot.resource_version,
            transformation=request.transformation,
            preserved_rules=tuple(preserved_rules),
            deltas=tuple(deltas),
            operations=tuple(operations),
            supporting_claim_ids=request.supporting_claim_ids,
        )

    __call__ = compile


def compile_candidate(request: object) -> CompileResult:
    """Compile only a typed CompileRequest; raw mappings and strings are rejected."""

    return CandidateCompiler().compile(request)


__all__ = [
    "CandidateCompiler",
    "CandidateStatus",
    "CompiledCandidate",
    "CompileResult",
    "compile_candidate",
]
