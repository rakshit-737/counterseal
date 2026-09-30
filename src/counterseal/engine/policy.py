"""Bounded offline policy for the deterministic Role candidate compiler."""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Annotated, Any, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    ValidationError,
    model_validator,
)

from counterseal.domain import (
    PlanOperation,
    RbacRule,
    RbacSubject,
    RbacSubjectKind,
    TargetObjectIdentity,
    TransformationType,
    canonical_digest,
)

type BoundedItems[T] = Annotated[tuple[T, ...], Field(max_length=256)]
Token = Annotated[
    StrictStr,
    Field(min_length=1, max_length=253, pattern=r"^[A-Za-z0-9*][A-Za-z0-9.*:/_-]*$"),
]
Name = Annotated[
    StrictStr,
    Field(min_length=1, max_length=253, pattern=r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$"),
]
Namespace = Annotated[
    StrictStr,
    Field(min_length=1, max_length=63, pattern=r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$"),
]
Identifier = Annotated[
    StrictStr,
    Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$"),
]
ApiGroup = Annotated[StrictStr, Field(max_length=253, pattern=r"^[A-Za-z0-9.*-]*$")]
Digest = Annotated[StrictStr, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
Text = Annotated[StrictStr, Field(min_length=1, max_length=2048)]
RuleIndex = Annotated[StrictInt, Field(ge=0, le=255)]


class PolicyDecision(StrEnum):
    ELIGIBLE = "ELIGIBLE"
    REJECTED = "REJECTED"
    UNSUPPORTED = "UNSUPPORTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class ReasonCode(StrEnum):
    ARBITRARY_INPUT = "arbitrary_input"
    WRONG_KIND = "wrong_kind"
    WRONG_API_GROUP = "wrong_api_group"
    WRONG_NAMESPACE = "wrong_namespace"
    NON_DEDICATED_ROLE = "non_dedicated_role"
    TARGET_MISMATCH = "target_mismatch"
    ROLE_BINDING_EDIT = "role_binding_edit"
    CLUSTER_ROLE_BINDING_EDIT = "cluster_role_binding_edit"
    CLUSTER_SCOPED_ROLE = "cluster_scoped_role"
    AGGREGATED_ROLE = "aggregated_role"
    WILDCARD_RULE = "wildcard_rule"
    UNSUPPORTED_RULE = "unsupported_rule"
    MIXED_RESOURCE_RULE = "mixed_resource_rule"
    INCOMPLETE_SNAPSHOT = "incomplete_snapshot"
    INCOMPLETE_VISIBILITY = "incomplete_visibility"
    UNKNOWN_ALTERNATIVE_GRANT = "unknown_alternative_grant"
    UNKNOWN_CONSUMER = "unknown_consumer"
    ALTERNATIVE_BINDING = "alternative_binding"
    ALTERNATIVE_GRANT = "alternative_grant"
    MISSING_PRECONDITION = "missing_precondition"
    STALE_UID = "stale_uid"
    STALE_RESOURCE_VERSION = "stale_resource_version"
    DUPLICATE_RULE = "duplicate_rule"
    AMBIGUOUS_RULE = "ambiguous_rule"
    PERMISSION_WIDENING = "permission_widening"
    NO_OP = "no_op"
    UNSUPPORTED_TRANSFORMATION = "unsupported_transformation"
    MISSING_APPROVED_SECRET = "missing_approved_secret"
    MISSING_GET_PERMISSION = "missing_get_permission"
    MISSING_SUPPORTING_CLAIMS = "missing_supporting_claims"


class _PolicyModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_default=True,
        revalidate_instances="always",
        allow_inf_nan=False,
    )

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        """Copy through validation; Pydantic's default update is unchecked."""

        return type(self).model_validate({**self.model_dump(mode="python"), **(update or {})})

    def canonical_digest(self) -> str:
        return canonical_digest(self)

    @property
    def digest(self) -> str:
        return self.canonical_digest()


class RoleRuleObservation(_PolicyModel):
    """One complete bounded Role rule observation."""

    rule_index: RuleIndex
    api_group: ApiGroup = ""
    resource: Token = "secrets"
    api_groups: BoundedItems[ApiGroup] | None = None
    resources: BoundedItems[Token] | None = None
    verbs: BoundedItems[Token]
    resource_names: BoundedItems[Token] = ()
    subresource: Token | None = None
    namespace: Namespace | None = None
    kind: Token = "Role"
    aggregated: StrictBool = False
    aggregation_rule: StrictBool = False

    @model_validator(mode="after")
    def canonical_order(self) -> Self:
        verb_order = {"get": 0, "list": 1, "watch": 2}
        if self.api_groups is not None:
            if "api_group" in self.model_fields_set and self.api_groups != (self.api_group,):
                raise ValueError("api_group and api_groups conflict")
            object.__setattr__(self, "api_groups", tuple(sorted(self.api_groups)))
        if self.resources is not None:
            if "resource" in self.model_fields_set and self.resources != (self.resource,):
                raise ValueError("resource and resources conflict")
            object.__setattr__(self, "resources", tuple(sorted(self.resources)))
        object.__setattr__(
            self,
            "verbs",
            tuple(sorted(self.verbs, key=lambda verb: (verb_order.get(verb, 99), verb))),
        )
        object.__setattr__(self, "resource_names", tuple(sorted(self.resource_names)))
        return self

    @property
    def groups(self) -> tuple[str, ...]:
        return (self.api_group,) if self.api_groups is None else self.api_groups

    @property
    def resource_set(self) -> tuple[str, ...]:
        return (self.resource,) if self.resources is None else self.resources

    @property
    def is_secret(self) -> bool:
        return self.groups == ("",) and self.resource_set == ("secrets",)

    @property
    def is_configmap(self) -> bool:
        return self.groups == ("",) and self.resource_set == ("configmaps",)


class BindingObservation(_PolicyModel):
    """One binding-to-subject edge; unknown edges fail closed."""

    kind: Token
    name: Name
    role_kind: Token
    role_name: Name
    namespace: Namespace | None = None
    subject: RbacSubject | None = None
    known: StrictBool = False


class AlternativeGrantObservation(_PolicyModel):
    source_kind: Token
    source_name: Name
    source_namespace: Namespace | None = None
    subject: RbacSubject | None = None
    known: StrictBool = False


class RoleSnapshot(_PolicyModel):
    """The complete Role rule set and bounded grant-source visibility."""

    api_group: ApiGroup = "rbac.authorization.k8s.io"
    kind: Token = "Role"
    namespace: Namespace | None = None
    name: Name
    uid: Identifier
    resource_version: Identifier
    dedicated: StrictBool = False
    dedicated_to: RbacSubject | None = None
    rules: BoundedItems[RoleRuleObservation]
    complete: StrictBool = False
    visibility_complete: StrictBool = False
    bindings_complete: StrictBool = False
    missing_resources: BoundedItems[Token] = ()
    unknown_alternative_grants: StrictBool = False
    bindings: BoundedItems[BindingObservation] = ()
    alternative_grants: BoundedItems[AlternativeGrantObservation] = ()
    aggregated: StrictBool = False
    aggregation_rule: StrictBool = False

    @model_validator(mode="after")
    def canonical_order(self) -> Self:
        object.__setattr__(
            self,
            "rules",
            tuple(
                sorted(
                    self.rules,
                    key=lambda rule: (rule.rule_index, rule.canonical_digest()),
                )
            ),
        )
        object.__setattr__(self, "bindings", tuple(sorted(self.bindings, key=canonical_digest)))
        object.__setattr__(
            self,
            "alternative_grants",
            tuple(sorted(self.alternative_grants, key=canonical_digest)),
        )
        object.__setattr__(self, "missing_resources", tuple(sorted(self.missing_resources)))
        return self


class CompileRequest(_PolicyModel):
    """All compiler preconditions are explicit typed fields."""

    snapshot: RoleSnapshot
    transformation: TransformationType
    supporting_claim_ids: BoundedItems[Identifier]
    expected_uid: Identifier
    expected_resource_version: Identifier
    target_object_identity: TargetObjectIdentity | None = None
    approved_secret_name: Name | None = None
    edited_kinds: BoundedItems[Token] = ("Role",)
    requested_after: RoleRuleObservation | None = None

    @model_validator(mode="after")
    def canonical_claims(self) -> Self:
        if not self.supporting_claim_ids:
            raise ValueError("supporting_claim_ids must be explicit and nonempty")
        if len(set(self.supporting_claim_ids)) != len(self.supporting_claim_ids):
            raise ValueError("supporting claim IDs must be unique")
        object.__setattr__(self, "supporting_claim_ids", tuple(sorted(self.supporting_claim_ids)))
        return self


class TypedRuleDelta(_PolicyModel):
    """Typed rule change; it contains no manifest or executable command."""

    operation_id: Identifier
    rule_index: RuleIndex
    transformation: TransformationType
    before: RbacRule
    after: RbacRule | None

    def to_plan_operation(self) -> PlanOperation:
        return PlanOperation(
            operation_id=self.operation_id,
            rule_index=self.rule_index,
            transformation=self.transformation,
            before=self.before,
            after=self.after,
        )


LIMITATIONS = (
    "Offline input declarations and claim references are not independently verified here.",
    "Eligibility permits candidate compilation only; no rehearsal or workload verdict is produced.",
    "UID and resourceVersion are compared only with supplied preconditions, not a current cluster.",
)


class PolicyResult(_PolicyModel):
    decision: PolicyDecision
    reason_codes: BoundedItems[ReasonCode] = ()
    supporting_claim_ids: BoundedItems[Identifier] = ()
    limitations: BoundedItems[Text] = LIMITATIONS
    approval_eligible: Literal[False] = False

    @model_validator(mode="after")
    def canonical_order(self) -> Self:
        object.__setattr__(self, "reason_codes", tuple(sorted(set(self.reason_codes))))
        object.__setattr__(
            self, "supporting_claim_ids", tuple(sorted(set(self.supporting_claim_ids)))
        )
        object.__setattr__(self, "limitations", tuple(sorted(set(self.limitations))))
        return self

    @property
    def eligible(self) -> bool:
        return self.decision is PolicyDecision.ELIGIBLE


class RejectedResult(PolicyResult):
    decision: Literal[PolicyDecision.REJECTED] = PolicyDecision.REJECTED


class InconclusiveResult(PolicyResult):
    decision: Literal[PolicyDecision.INCONCLUSIVE] = PolicyDecision.INCONCLUSIVE


class UnsupportedResult(PolicyResult):
    decision: Literal[PolicyDecision.UNSUPPORTED] = PolicyDecision.UNSUPPORTED


def revalidate_request(value: object) -> CompileRequest | RejectedResult:
    """Revalidate typed instances, including model_construct-created values."""

    if type(value) is not CompileRequest:
        return RejectedResult(reason_codes=(ReasonCode.ARBITRARY_INPUT,))
    try:
        return CompileRequest.model_validate(value)
    except (ValidationError, TypeError, ValueError):
        return RejectedResult(reason_codes=(ReasonCode.ARBITRARY_INPUT,))


def _rule_fingerprint(rule: RoleRuleObservation) -> tuple[Any, ...]:
    return (
        rule.groups,
        rule.resource_set,
        rule.verbs,
        rule.resource_names,
        rule.subresource,
        rule.namespace,
        rule.kind,
    )


def _rules_overlap(left: RoleRuleObservation, right: RoleRuleObservation) -> bool:
    if left.groups != right.groups or left.resource_set != right.resource_set:
        return False
    if left.subresource != right.subresource or left.namespace != right.namespace:
        return False
    if not set(left.verbs).intersection(right.verbs):
        return False
    left_names, right_names = set(left.resource_names), set(right.resource_names)
    return not left_names or not right_names or bool(left_names.intersection(right_names))


def _reason_result(
    decision: PolicyDecision,
    reasons: tuple[ReasonCode, ...],
    request: CompileRequest,
) -> PolicyResult:
    kwargs = {"reason_codes": reasons, "supporting_claim_ids": request.supporting_claim_ids}
    if decision is PolicyDecision.REJECTED:
        return RejectedResult(**kwargs)
    if decision is PolicyDecision.INCONCLUSIVE:
        return InconclusiveResult(**kwargs)
    return UnsupportedResult(**kwargs)


class PolicyGate:
    """Fail-closed structural and transformation precondition gate."""

    def evaluate(self, request: object) -> PolicyResult:
        checked = revalidate_request(request)
        if isinstance(checked, PolicyResult):
            return checked
        request = checked
        snapshot = request.snapshot
        rejected: list[ReasonCode] = []
        inconclusive: list[ReasonCode] = []

        if snapshot.kind != "Role":
            rejected.append(
                ReasonCode.CLUSTER_SCOPED_ROLE
                if snapshot.kind == "ClusterRole"
                else ReasonCode.WRONG_KIND
            )
        if snapshot.api_group != "rbac.authorization.k8s.io":
            rejected.append(ReasonCode.WRONG_API_GROUP)
        if snapshot.namespace is None:
            rejected.append(ReasonCode.WRONG_NAMESPACE)
        if not snapshot.dedicated or snapshot.dedicated_to is None:
            rejected.append(ReasonCode.NON_DEDICATED_ROLE)
        elif (
            snapshot.dedicated_to.kind is not RbacSubjectKind.SERVICE_ACCOUNT
            or snapshot.dedicated_to.namespace != snapshot.namespace
        ):
            rejected.append(ReasonCode.NON_DEDICATED_ROLE)
        if snapshot.aggregated or snapshot.aggregation_rule:
            rejected.append(ReasonCode.AGGREGATED_ROLE)
        if request.expected_uid != snapshot.uid:
            inconclusive.append(ReasonCode.STALE_UID)
        if request.expected_resource_version != snapshot.resource_version:
            inconclusive.append(ReasonCode.STALE_RESOURCE_VERSION)
        if request.target_object_identity is not None:
            target = request.target_object_identity
            if (
                target.kind != "Role"
                or target.name != snapshot.name
                or target.namespace != snapshot.namespace
                or target.dedicated_to != snapshot.dedicated_to
            ):
                rejected.append(ReasonCode.TARGET_MISMATCH)
        for kind in request.edited_kinds:
            if kind == "RoleBinding":
                rejected.append(ReasonCode.ROLE_BINDING_EDIT)
            elif kind == "ClusterRoleBinding":
                rejected.append(ReasonCode.CLUSTER_ROLE_BINDING_EDIT)
            elif kind == "ClusterRole":
                rejected.append(ReasonCode.CLUSTER_SCOPED_ROLE)
            elif kind != "Role":
                rejected.append(ReasonCode.WRONG_KIND)
        if len(request.edited_kinds) != 1 or request.edited_kinds[0] != "Role":
            rejected.append(ReasonCode.TARGET_MISMATCH)

        if not snapshot.complete:
            inconclusive.append(ReasonCode.INCOMPLETE_SNAPSHOT)
        if (
            not snapshot.visibility_complete
            or not snapshot.bindings_complete
            or snapshot.missing_resources
        ):
            inconclusive.append(ReasonCode.INCOMPLETE_VISIBILITY)
        if snapshot.unknown_alternative_grants:
            inconclusive.append(ReasonCode.UNKNOWN_ALTERNATIVE_GRANT)
        if not request.supporting_claim_ids:
            rejected.append(ReasonCode.MISSING_SUPPORTING_CLAIMS)

        target_subject = snapshot.dedicated_to
        target_binding = False
        if not snapshot.bindings:
            inconclusive.append(ReasonCode.UNKNOWN_CONSUMER)
        for binding in snapshot.bindings:
            if not binding.known or binding.subject is None:
                inconclusive.append(ReasonCode.UNKNOWN_ALTERNATIVE_GRANT)
                continue
            subject_matches = _binding_subject_matches(binding.subject, target_subject)
            role_matches = (
                binding.kind == "RoleBinding"
                and binding.role_kind == "Role"
                and binding.role_name == snapshot.name
                and binding.namespace == snapshot.namespace
            )
            if role_matches and not subject_matches:
                rejected.append(ReasonCode.NON_DEDICATED_ROLE)
                continue
            if subject_matches and not role_matches:
                rejected.append(
                    ReasonCode.CLUSTER_ROLE_BINDING_EDIT
                    if binding.kind == "ClusterRoleBinding"
                    else ReasonCode.ALTERNATIVE_BINDING
                )
                continue
            exact = role_matches and subject_matches
            if exact:
                target_binding = True
        if snapshot.bindings and not target_binding:
            inconclusive.append(ReasonCode.UNKNOWN_CONSUMER)
        for grant in snapshot.alternative_grants:
            if not grant.known or grant.subject is None:
                inconclusive.append(ReasonCode.UNKNOWN_ALTERNATIVE_GRANT)
            elif _binding_subject_matches(grant.subject, target_subject):
                rejected.append(ReasonCode.ALTERNATIVE_GRANT)

        indexes: set[int] = set()
        fingerprints: set[tuple[Any, ...]] = set()
        for rule in snapshot.rules:
            if rule.rule_index in indexes or _rule_fingerprint(rule) in fingerprints:
                rejected.append(ReasonCode.DUPLICATE_RULE)
            indexes.add(rule.rule_index)
            fingerprints.add(_rule_fingerprint(rule))
            if any(
                "*" in value
                for value in (*rule.groups, *rule.resource_set, *rule.verbs, *rule.resource_names)
            ):
                rejected.append(ReasonCode.WILDCARD_RULE)
            if len(rule.groups) != 1 or len(rule.resource_set) != 1:
                rejected.append(ReasonCode.MIXED_RESOURCE_RULE)
            if (
                len(set(rule.groups)) != len(rule.groups)
                or len(set(rule.resource_set)) != len(rule.resource_set)
                or len(set(rule.verbs)) != len(rule.verbs)
                or len(set(rule.resource_names)) != len(rule.resource_names)
            ):
                rejected.append(ReasonCode.DUPLICATE_RULE)
            if rule.aggregated or rule.aggregation_rule:
                rejected.append(ReasonCode.AGGREGATED_ROLE)
            if (
                not rule.groups
                or not rule.resource_set
                or rule.subresource is not None
                or rule.namespace is not None
                or not rule.verbs
                or any(verb not in {"get", "list", "watch"} for verb in rule.verbs)
                or rule.kind != "Role"
            ):
                rejected.append(ReasonCode.UNSUPPORTED_RULE)
            if not rule.is_secret and not rule.is_configmap:
                rejected.append(ReasonCode.UNSUPPORTED_RULE)
        for index, left in enumerate(snapshot.rules):
            for right in snapshot.rules[index + 1 :]:
                if _rules_overlap(left, right):
                    rejected.append(ReasonCode.AMBIGUOUS_RULE)

        if rejected:
            return _reason_result(PolicyDecision.REJECTED, tuple(sorted(set(rejected))), request)
        if inconclusive:
            return _reason_result(
                PolicyDecision.INCONCLUSIVE, tuple(sorted(set(inconclusive))), request
            )

        secret_rules = tuple(rule for rule in snapshot.rules if rule.is_secret)
        if not secret_rules:
            return RejectedResult(
                reason_codes=(ReasonCode.NO_OP,), supporting_claim_ids=request.supporting_claim_ids
            )
        if request.transformation is TransformationType.RESTRICT_NAMED_SECRET_ACCESS:
            if request.approved_secret_name is None:
                return RejectedResult(
                    reason_codes=(ReasonCode.MISSING_APPROVED_SECRET,),
                    supporting_claim_ids=request.supporting_claim_ids,
                )
            get_rules = tuple(rule for rule in secret_rules if "get" in rule.verbs)
            if not get_rules:
                return RejectedResult(
                    reason_codes=(ReasonCode.MISSING_GET_PERMISSION,),
                    supporting_claim_ids=request.supporting_claim_ids,
                )
            if len(get_rules) > 1:
                return RejectedResult(
                    reason_codes=(ReasonCode.AMBIGUOUS_RULE,),
                    supporting_claim_ids=request.supporting_claim_ids,
                )
        elif request.transformation not in {
            TransformationType.REMOVE_SECRET_ACCESS,
            TransformationType.REMOVE_SECRET_LIST_WATCH,
        }:
            return UnsupportedResult(
                reason_codes=(ReasonCode.UNSUPPORTED_TRANSFORMATION,),
                supporting_claim_ids=request.supporting_claim_ids,
            )
        return PolicyResult(
            decision=PolicyDecision.ELIGIBLE,
            supporting_claim_ids=request.supporting_claim_ids,
        )


def _binding_subject_matches(subject: RbacSubject, target: RbacSubject | None) -> bool:
    if target is None:
        return False
    if subject == target:
        return True
    if target.kind is not RbacSubjectKind.SERVICE_ACCOUNT:
        return False
    if subject.kind is RbacSubjectKind.USER:
        return subject.name == f"system:serviceaccount:{target.namespace}:{target.name}"
    if subject.kind is RbacSubjectKind.GROUP:
        return subject.name in {
            "system:serviceaccounts",
            "system:authenticated",
            f"system:serviceaccounts:{target.namespace}",
        }
    return False


def evaluate_policy(request: object) -> PolicyResult:
    return PolicyGate().evaluate(request)


__all__ = [
    "AlternativeGrantObservation",
    "BindingObservation",
    "CompileRequest",
    "InconclusiveResult",
    "PolicyDecision",
    "PolicyGate",
    "PolicyResult",
    "ReasonCode",
    "RejectedResult",
    "RoleRuleObservation",
    "RoleSnapshot",
    "TypedRuleDelta",
    "UnsupportedResult",
    "evaluate_policy",
    "revalidate_request",
]
