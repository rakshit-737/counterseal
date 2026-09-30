"""Offline, snapshot-scoped Kubernetes RBAC analysis.

This module deliberately models only the metadata and policy rules needed to
answer one question: which read-only ``Secret`` permissions are effective for
one ServiceAccount in one RBAC snapshot.  It never accepts or stores Secret
data, token data, manifest bodies, or command text.

The records in this module are frozen and bounded.  The analyzer is a pure
function of its input records; it does not use a Kubernetes client or any
ambient cluster state.  Unknown, widening, and incomplete inputs fail closed
so that a result marked as supported is still limited to the supplied
snapshot.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from enum import StrEnum
from hashlib import sha256
from itertools import chain, islice
from typing import Any, Final, cast

from pydantic import ValidationError

from counterseal.domain import (
    ClaimPredicate,
    GraphEdge,
    GraphEdgeType,
    GraphNode,
    GraphNodeType,
    TypedClaim,
    canonical_digest,
)

MAX_ITEMS: Final = 256
MAX_TEXT: Final = 253
MAX_GRANTS: Final = 4096
SUPPORTED_SECRET_VERBS: Final = frozenset({"get", "list", "watch"})
SUPPORTED_RESOURCES: Final = frozenset({"secrets", "configmaps"})
CORE_API_GROUP: Final = ""
SECRET_RESOURCE: Final = "secrets"


def _bounded_text(value: str, field_name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    if not allow_empty and not value:
        raise ValueError(f"{field_name} must not be empty")
    if len(value) > MAX_TEXT:
        raise ValueError(f"{field_name} exceeds the bounded length")
    if any(ord(character) < 0x20 for character in value):
        raise ValueError(f"{field_name} contains a control character")
    return value


def _bounded_tuple(
    values: Iterable[str] | None,
    field_name: str,
    *,
    allow_empty: bool = True,
    allow_empty_items: bool = False,
    sort_values: bool = True,
) -> tuple[str, ...]:
    if values is None:
        values = ()
    if isinstance(values, str):
        values = (values,)
    try:
        bounded_values = islice(values, MAX_ITEMS + 1)
        result = tuple(
            _bounded_text(value, field_name, allow_empty=allow_empty_items)
            for value in bounded_values
        )
    except TypeError as exc:
        raise TypeError(f"{field_name} must be a bounded sequence") from exc
    if len(result) > MAX_ITEMS:
        raise ValueError(f"{field_name} exceeds the bounded item count")
    if not allow_empty and not result:
        raise ValueError(f"{field_name} must contain at least one item")
    if len(set(result)) != len(result):
        raise ValueError(f"{field_name} must not contain duplicate items")
    return tuple(sorted(result)) if sort_values else result


def _bounded_ids(values: Iterable[str] | None, field_name: str = "evidence_ids") -> tuple[str, ...]:
    result = _bounded_tuple(values, field_name, sort_values=True)
    for value in result:
        _identifier(value, field_name)
    return result


def _identifier(value: str, field_name: str) -> str:
    _bounded_text(value, field_name)
    if len(value) > 128 or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]*", value) is None:
        raise ValueError(f"{field_name} must be a bounded identifier")
    return value


def _strict_bool(value: bool, field_name: str) -> None:
    if type(value) is not bool:
        raise TypeError(f"{field_name} must be a boolean")


def _aggregation_present(value: object | None) -> bool:
    # Only presence is retained: selectors or other arbitrary nested data are
    # unnecessary when every aggregated role is unsupported.
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, Mapping):
        return True
    raise TypeError("aggregation_rule must be a presence flag or mapping")


def _response_code(value: int) -> None:
    if type(value) is not int or not 100 <= value <= 599:
        raise ValueError("response_code must be an HTTP integer status")


def _digest(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise ValueError("object_digest must be a SHA-256 digest")
    return value


def _validate_fact_object_fields(value: Any) -> None:
    source_id = getattr(value, "source_id", None)
    object_id = getattr(value, "object_id", None)
    object_digest = getattr(value, "object_digest", None)
    if source_id is not None:
        _identifier(source_id, "source_id")
    if object_id is not None:
        _identifier(object_id, "object_id")
    if object_digest is not None:
        _digest(object_digest)


def _coerce_records(values: Iterable[Any] | Mapping[str, Any] | None) -> tuple[Any, ...]:
    """Accept a sequence or an ID-keyed mapping without accepting free-form facts."""

    if values is None:
        return ()
    if isinstance(values, Mapping):
        values = values.values()
    result = tuple(islice(values, MAX_ITEMS + 1))
    if len(result) > MAX_ITEMS:
        raise ValueError("records exceeds the bounded item count")
    return result


def _bounded_materialize(
    values: Iterable[Any], field_name: str, *, limit: int = MAX_ITEMS
) -> tuple[Any, ...]:
    result = tuple(islice(values, limit + 1))
    if len(result) > limit:
        raise ValueError(f"{field_name} exceeds the bounded item count")
    return result


class AnalysisStatus(StrEnum):
    """Outcome of the bounded permission question."""

    GRANTED = "granted"
    DENIED = "denied"
    ABSTAIN = "abstain"
    UNSUPPORTED = "unsupported"


class Completeness(StrEnum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    UNSUPPORTED = "unsupported"


class ReasonCode(StrEnum):
    GRANTED = "granted"
    NO_MATCHING_GRANT = "no_matching_grant"
    ADDITIVE_GRANT = "additive_grant"
    INCOMPLETE_SNAPSHOT = "incomplete_snapshot"
    WILDCARD_RULE = "wildcard_rule"
    AGGREGATED_ROLE = "aggregated_role"
    UNKNOWN_KIND = "unknown_kind"
    UNSUPPORTED_SUBRESOURCE = "unsupported_subresource"
    UNSUPPORTED_RESOURCE = "unsupported_resource"
    UNSUPPORTED_VERB = "unsupported_verb"
    CAPACITY_EXCEEDED = "capacity_exceeded"
    REQUEST_INCOMPLETE = "request_incomplete"
    NAMED_GET_REQUIRES_RESOURCE_NAME = "named_get_requires_resource_name"
    NAMED_LIST_WATCH_REQUIRES_FIELD_SELECTOR = "named_list_watch_requires_field_selector"
    MISSING_SUBJECT_NAMESPACE = "missing_subject_namespace"
    NAMESPACE_MISMATCH = "namespace_mismatch"
    MISSING_ROLE_REFERENCE = "missing_role_reference"
    SNAPSHOT_SCOPE_MISMATCH = "snapshot_scope_mismatch"
    GRAPH_EVIDENCE_MISSING = "graph_evidence_missing"
    CLAIM_CONTEXT_MISSING = "claim_context_missing"
    CLAIM_SNAPSHOT_MISMATCH = "claim_snapshot_mismatch"
    CLAIM_ARGUMENT_MISMATCH = "claim_argument_mismatch"
    CLAIM_EVIDENCE_MISSING = "claim_evidence_missing"
    CLAIM_EVIDENCE_MISMATCH = "claim_evidence_mismatch"
    CLAIM_FACT_MISSING = "claim_fact_missing"
    CLAIM_FACT_FALSE = "claim_fact_false"
    CLAIM_SOURCE_MISMATCH = "claim_source_mismatch"
    CLAIM_CONTENT_MISMATCH = "claim_content_mismatch"


@dataclass(frozen=True, slots=True)
class RbacRuleRecord:
    """A bounded Kubernetes policy rule; it contains no object data."""

    api_groups: tuple[str, ...] = (CORE_API_GROUP,)
    resources: tuple[str, ...] = (SECRET_RESOURCE,)
    verbs: tuple[str, ...] = ("get",)
    resource_names: tuple[str, ...] = ()
    rule_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "api_groups",
            _bounded_tuple(self.api_groups, "api_groups", allow_empty_items=True),
        )
        object.__setattr__(
            self, "resources", _bounded_tuple(self.resources, "resources", allow_empty=False)
        )
        object.__setattr__(self, "verbs", _bounded_tuple(self.verbs, "verbs", allow_empty=False))
        object.__setattr__(
            self,
            "resource_names",
            _bounded_tuple(self.resource_names, "resource_names"),
        )
        if self.rule_id is not None:
            object.__setattr__(self, "rule_id", _bounded_text(self.rule_id, "rule_id"))

    @property
    def has_wildcard(self) -> bool:
        return any(
            "*" in value
            for values in (self.api_groups, self.resources, self.verbs, self.resource_names)
            for value in values
        )

    @property
    def has_unsupported_subresource(self) -> bool:
        return any("/" in resource for resource in self.resources)


@dataclass(frozen=True, slots=True)
class RoleRecord:
    """A namespaced Role and its rules."""

    name: str
    namespace: str
    rules: tuple[RbacRuleRecord, ...]
    evidence_ids: tuple[str, ...] = ()
    aggregation_rule: object | None = None
    aggregated: bool = False
    kind: str = "Role"
    snapshot_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _bounded_text(self.name, "name"))
        object.__setattr__(self, "namespace", _bounded_text(self.namespace, "namespace"))
        object.__setattr__(self, "rules", _normalize_rules(self.rules))
        object.__setattr__(self, "evidence_ids", _bounded_ids(self.evidence_ids))
        object.__setattr__(self, "aggregation_rule", _aggregation_present(self.aggregation_rule))
        object.__setattr__(self, "kind", _bounded_text(self.kind, "kind"))
        _strict_bool(self.aggregated, "aggregated")
        if self.snapshot_id is not None:
            _identifier(self.snapshot_id, "snapshot_id")

    @property
    def role_id(self) -> str:
        return _role_id(self.kind, self.namespace, self.name)

    @property
    def is_aggregated(self) -> bool:
        return bool(self.aggregated or self.aggregation_rule)


@dataclass(frozen=True, slots=True)
class ClusterRoleRecord:
    """A cluster-scoped ClusterRole and its rules."""

    name: str
    rules: tuple[RbacRuleRecord, ...]
    evidence_ids: tuple[str, ...] = ()
    aggregation_rule: object | None = None
    aggregated: bool = False
    kind: str = "ClusterRole"
    namespace: str | None = None

    snapshot_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _bounded_text(self.name, "name"))
        object.__setattr__(self, "rules", _normalize_rules(self.rules))
        object.__setattr__(self, "evidence_ids", _bounded_ids(self.evidence_ids))
        object.__setattr__(self, "aggregation_rule", _aggregation_present(self.aggregation_rule))
        object.__setattr__(self, "kind", _bounded_text(self.kind, "kind"))
        _strict_bool(self.aggregated, "aggregated")
        if self.snapshot_id is not None:
            _identifier(self.snapshot_id, "snapshot_id")
        if self.namespace is not None:
            object.__setattr__(self, "namespace", _bounded_text(self.namespace, "namespace"))

    @property
    def role_id(self) -> str:
        return _role_id(self.kind, None, self.name)

    @property
    def is_aggregated(self) -> bool:
        return bool(self.aggregated or self.aggregation_rule)


def _normalize_rules(rules: Iterable[RbacRuleRecord] | None) -> tuple[RbacRuleRecord, ...]:
    if rules is None:
        rules = ()
    result = tuple(
        rule if isinstance(rule, RbacRuleRecord) else RbacRuleRecord(**rule)
        for rule in _coerce_records(rules)
    )
    if len(result) > MAX_ITEMS:
        raise ValueError("rules exceeds the bounded item count")
    return result


@dataclass(frozen=True, slots=True)
class SubjectRecord:
    """A binding subject.  No credentials or token material is represented."""

    kind: str
    name: str
    namespace: str | None = None
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _bounded_text(self.kind, "kind"))
        object.__setattr__(self, "name", _bounded_text(self.name, "name"))
        if self.namespace is not None:
            object.__setattr__(self, "namespace", _bounded_text(self.namespace, "namespace"))
        object.__setattr__(self, "evidence_ids", _bounded_ids(self.evidence_ids))


@dataclass(frozen=True, slots=True)
class ServiceAccountRef:
    name: str
    namespace: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _bounded_text(self.name, "name"))
        object.__setattr__(self, "namespace", _bounded_text(self.namespace, "namespace"))

    @property
    def kind(self) -> str:
        return "ServiceAccount"


@dataclass(frozen=True, slots=True)
class RoleBindingRecord:
    """A namespaced RoleBinding and its Role/ClusterRole reference."""

    name: str
    namespace: str
    role_ref_kind: str
    role_ref_name: str
    subjects: tuple[SubjectRecord, ...]
    evidence_ids: tuple[str, ...] = ()
    kind: str = "RoleBinding"
    snapshot_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _bounded_text(self.name, "name"))
        object.__setattr__(self, "namespace", _bounded_text(self.namespace, "namespace"))
        object.__setattr__(
            self, "role_ref_kind", _bounded_text(self.role_ref_kind, "role_ref_kind")
        )
        object.__setattr__(
            self, "role_ref_name", _bounded_text(self.role_ref_name, "role_ref_name")
        )
        object.__setattr__(self, "subjects", _normalize_subjects(self.subjects))
        object.__setattr__(self, "evidence_ids", _bounded_ids(self.evidence_ids))
        object.__setattr__(self, "kind", _bounded_text(self.kind, "kind"))
        if self.snapshot_id is not None:
            _identifier(self.snapshot_id, "snapshot_id")

    @property
    def binding_id(self) -> str:
        return _binding_id(self.kind, self.namespace, self.name)


@dataclass(frozen=True, slots=True)
class ClusterRoleBindingRecord:
    """A cluster-scoped ClusterRoleBinding."""

    name: str
    role_ref_kind: str
    role_ref_name: str
    subjects: tuple[SubjectRecord, ...]
    evidence_ids: tuple[str, ...] = ()
    kind: str = "ClusterRoleBinding"
    namespace: str | None = None
    snapshot_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _bounded_text(self.name, "name"))
        object.__setattr__(
            self, "role_ref_kind", _bounded_text(self.role_ref_kind, "role_ref_kind")
        )
        object.__setattr__(
            self, "role_ref_name", _bounded_text(self.role_ref_name, "role_ref_name")
        )
        object.__setattr__(self, "subjects", _normalize_subjects(self.subjects))
        object.__setattr__(self, "evidence_ids", _bounded_ids(self.evidence_ids))
        object.__setattr__(self, "kind", _bounded_text(self.kind, "kind"))
        if self.snapshot_id is not None:
            _identifier(self.snapshot_id, "snapshot_id")
        if self.namespace is not None:
            object.__setattr__(self, "namespace", _bounded_text(self.namespace, "namespace"))

    @property
    def binding_id(self) -> str:
        return _binding_id(self.kind, None, self.name)


def _normalize_subjects(subjects: Iterable[SubjectRecord] | None) -> tuple[SubjectRecord, ...]:
    if subjects is None:
        subjects = ()
    result = tuple(
        subject if isinstance(subject, SubjectRecord) else SubjectRecord(**subject)
        for subject in _coerce_records(subjects)
    )
    if len(result) > MAX_ITEMS:
        raise ValueError("subjects exceeds the bounded item count")
    return tuple(sorted(result, key=lambda item: (item.kind, item.namespace or "", item.name)))


@dataclass(frozen=True, slots=True)
class SnapshotObjectRecord:
    """Metadata-only source object identity used by claim verification."""

    object_id: str
    kind: str
    name: str
    namespace: str | None
    object_digest: str
    snapshot_id: str
    evidence_ids: tuple[str, ...] = ()
    source_id: str | None = None

    def __post_init__(self) -> None:
        for field_name in ("object_id", "kind", "name", "object_digest", "snapshot_id"):
            object.__setattr__(
                self, field_name, _bounded_text(getattr(self, field_name), field_name)
            )
        if self.namespace is not None:
            object.__setattr__(self, "namespace", _bounded_text(self.namespace, "namespace"))
        if self.source_id is not None:
            object.__setattr__(self, "source_id", _identifier(self.source_id, "source_id"))
        object.__setattr__(self, "evidence_ids", _bounded_ids(self.evidence_ids))

        _digest(self.object_digest)
        _identifier(self.snapshot_id, "snapshot_id")


@dataclass(frozen=True, slots=True)
class RbacSnapshotRecord:
    """The complete, bounded input to one analysis."""

    snapshot_id: str
    roles: tuple[RoleRecord, ...] = ()
    cluster_roles: tuple[ClusterRoleRecord, ...] = ()
    role_bindings: tuple[RoleBindingRecord, ...] = ()
    cluster_role_bindings: tuple[ClusterRoleBindingRecord, ...] = ()
    complete: bool = False
    missing_resources: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    namespaces: tuple[str, ...] = ()
    unknown_kinds: tuple[str, ...] = ()
    objects: tuple[SnapshotObjectRecord, ...] = ()
    source_id: str | None = None
    scope_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "snapshot_id", _identifier(self.snapshot_id, "snapshot_id"))
        _strict_bool(self.complete, "complete")
        object.__setattr__(self, "roles", _normalize_roles(self.roles, RoleRecord))
        object.__setattr__(
            self, "cluster_roles", _normalize_roles(self.cluster_roles, ClusterRoleRecord)
        )
        object.__setattr__(
            self, "role_bindings", _normalize_bindings(self.role_bindings, RoleBindingRecord)
        )
        object.__setattr__(
            self,
            "cluster_role_bindings",
            _normalize_bindings(self.cluster_role_bindings, ClusterRoleBindingRecord),
        )
        object.__setattr__(
            self, "missing_resources", _bounded_tuple(self.missing_resources, "missing_resources")
        )
        object.__setattr__(self, "evidence_ids", _bounded_ids(self.evidence_ids))
        object.__setattr__(self, "namespaces", _bounded_tuple(self.namespaces, "namespaces"))
        object.__setattr__(
            self, "unknown_kinds", _bounded_tuple(self.unknown_kinds, "unknown_kinds")
        )
        object.__setattr__(self, "objects", _normalize_objects(self.objects))
        if self.source_id is not None:
            object.__setattr__(self, "source_id", _identifier(self.source_id, "source_id"))
        if self.scope_id is not None:
            _identifier(self.scope_id, "scope_id")
        identities: set[tuple[str, str | None, str]] = set()
        all_evidence = set(self.evidence_ids)
        for field_name in ("roles", "cluster_roles", "role_bindings", "cluster_role_bindings"):
            scoped = []
            for record in getattr(self, field_name):
                if record.snapshot_id not in (None, self.snapshot_id):
                    raise ValueError("RBAC records cannot mix snapshots")
                identity = (record.kind, record.namespace, record.name)
                if identity in identities:
                    raise ValueError("snapshot contains duplicate RBAC identities")
                identities.add(identity)
                all_evidence.update(record.evidence_ids)
                scoped.append(replace(record, snapshot_id=self.snapshot_id))
            object.__setattr__(self, field_name, tuple(scoped))
        if len(identities) > MAX_ITEMS or len(all_evidence) > MAX_ITEMS:
            raise ValueError("snapshot exceeds bounded objects or evidence")
        object_ids: set[str] = set()
        for item in self.objects:
            if item.snapshot_id != self.snapshot_id:
                raise ValueError("source objects cannot mix snapshots")
            if item.object_id in object_ids:
                raise ValueError("snapshot contains duplicate source object IDs")
            object_ids.add(item.object_id)

    @property
    def is_complete(self) -> bool:
        return bool(self.complete and not self.missing_resources and not self.unknown_kinds)


def _normalize_roles(values: Iterable[Any] | None, expected_type: type[Any]) -> tuple[Any, ...]:
    records = _coerce_records(values)
    result = tuple(
        value if isinstance(value, expected_type) else expected_type(**value) for value in records
    )
    if len(result) > MAX_ITEMS:
        raise ValueError("roles exceeds the bounded item count")
    return tuple(sorted(result, key=lambda item: (item.kind, item.namespace or "", item.name)))


def _normalize_bindings(values: Iterable[Any] | None, expected_type: type[Any]) -> tuple[Any, ...]:
    records = _coerce_records(values)
    result = tuple(
        value if isinstance(value, expected_type) else expected_type(**value) for value in records
    )
    if len(result) > MAX_ITEMS:
        raise ValueError("bindings exceeds the bounded item count")
    return tuple(sorted(result, key=lambda item: (item.kind, item.namespace or "", item.name)))


def _normalize_objects(values: Iterable[Any] | None) -> tuple[SnapshotObjectRecord, ...]:
    records = _coerce_records(values)
    result = tuple(
        value if isinstance(value, SnapshotObjectRecord) else SnapshotObjectRecord(**value)
        for value in records
    )
    if len(result) > MAX_ITEMS:
        raise ValueError("objects exceeds the bounded item count")
    return tuple(sorted(result, key=lambda item: (item.kind, item.namespace or "", item.name)))


@dataclass(frozen=True, slots=True)
class EffectivePermission:
    api_group: str
    resource: str
    verb: str
    namespace: str
    resource_name: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "api_group", _bounded_text(self.api_group, "api_group", allow_empty=True)
        )
        object.__setattr__(self, "resource", _bounded_text(self.resource, "resource"))
        object.__setattr__(self, "verb", _bounded_text(self.verb, "verb"))
        object.__setattr__(self, "namespace", _bounded_text(self.namespace, "namespace"))
        if self.resource_name is not None:
            object.__setattr__(
                self, "resource_name", _bounded_text(self.resource_name, "resource_name")
            )

    def sort_key(self) -> tuple[str, str, str, str, str]:
        return (self.namespace, self.api_group, self.resource, self.verb, self.resource_name or "")


@dataclass(frozen=True, slots=True)
class PermissionRequest:
    """A typed, read-only authorization question.

    ``field_selector_resource_name`` is intentionally structured.  A free-form
    field selector cannot be interpreted as a named-resource authorization
    request without a parser and an explicit request contract.
    """

    api_group: str = CORE_API_GROUP
    resource: str = SECRET_RESOURCE
    verb: str | None = None
    resource_name: str | None = None
    field_selector: str | None = None
    field_selector_resource_name: str | None = None
    namespace: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "api_group",
            _bounded_text(self.api_group, "api_group", allow_empty=True),
        )
        object.__setattr__(self, "resource", _bounded_text(self.resource, "resource"))
        if self.namespace is not None:
            object.__setattr__(self, "namespace", _bounded_text(self.namespace, "namespace"))
        if self.verb is not None:
            object.__setattr__(self, "verb", _bounded_text(self.verb, "verb"))
        for field_name in ("resource_name", "field_selector_resource_name"):
            value = getattr(self, field_name)
            if value is not None:
                object.__setattr__(self, field_name, _bounded_text(value, field_name))
        if self.field_selector is not None:
            object.__setattr__(
                self, "field_selector", _bounded_text(self.field_selector, "field_selector")
            )
            match = re.fullmatch(r"metadata\.name=([a-z0-9][a-z0-9.-]*)", self.field_selector)
            if match:
                parsed_name = match.group(1)
                if (
                    self.field_selector_resource_name is not None
                    and self.field_selector_resource_name != parsed_name
                ):
                    raise ValueError("field selector name conflicts with its parsed resource name")
                object.__setattr__(self, "field_selector_resource_name", parsed_name)
            elif self.field_selector_resource_name is not None:
                raise ValueError("field selector is not a supported metadata.name selector")

    @property
    def is_actual_request(self) -> bool:
        return self.verb is not None


@dataclass(frozen=True, slots=True)
class MatchingGrant:
    permission: EffectivePermission
    binding_kind: str
    binding_name: str
    binding_namespace: str | None
    role_kind: str
    role_name: str
    role_namespace: str | None
    rule_index: int
    rule_id: str
    snapshot_id: str
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for field_name in (
            "binding_kind",
            "binding_name",
            "role_kind",
            "role_name",
            "rule_id",
            "snapshot_id",
        ):
            object.__setattr__(
                self, field_name, _bounded_text(getattr(self, field_name), field_name)
            )
        for field_name in ("binding_namespace", "role_namespace"):
            value = getattr(self, field_name)
            if value is not None:
                object.__setattr__(self, field_name, _bounded_text(value, field_name))
        if self.rule_index < 0 or self.rule_index >= MAX_ITEMS:
            raise ValueError("rule_index is outside the bounded range")
        object.__setattr__(self, "evidence_ids", _bounded_ids(self.evidence_ids))

    @property
    def grant_id(self) -> str:
        return _stable_id(
            "grant",
            self.snapshot_id,
            self.binding_kind,
            self.binding_namespace or "cluster",
            self.binding_name,
            self.role_kind,
            self.role_namespace or "cluster",
            self.role_name,
            str(self.rule_index),
            self.rule_id,
        )


@dataclass(frozen=True, slots=True)
class AlternativePathFinding:
    permission: EffectivePermission
    grants: tuple[MatchingGrant, ...]
    reason_code: ReasonCode = ReasonCode.ADDITIVE_GRANT

    def __post_init__(self) -> None:
        grants = _bounded_materialize(self.grants, "alternative grants", limit=MAX_GRANTS)
        object.__setattr__(self, "grants", grants)
        if len(self.grants) < 2:
            raise ValueError("an alternative path requires at least two grants")
        if any(
            not _permissions_overlap(grant.permission, self.permission) for grant in self.grants
        ):
            raise ValueError("alternative grants must overlap one permission")
        if any(grant.snapshot_id != self.grants[0].snapshot_id for grant in self.grants):
            raise ValueError("alternative grants must belong to one snapshot")
        object.__setattr__(
            self, "grants", tuple(sorted(self.grants, key=lambda item: item.grant_id))
        )


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    snapshot_id: str
    subject: ServiceAccountRef
    status: AnalysisStatus
    completeness: Completeness
    effective_permissions: tuple[EffectivePermission, ...]
    matching_grants: tuple[MatchingGrant, ...]
    alternative_paths: tuple[AlternativePathFinding, ...]
    reason_codes: tuple[ReasonCode, ...]
    graph_nodes: tuple[GraphNode, ...] = ()
    graph_edges: tuple[GraphEdge, ...] = ()
    request: PermissionRequest | None = None
    request_status: AnalysisStatus | None = None
    request_grants: tuple[MatchingGrant, ...] = ()
    requested_permission: EffectivePermission | None = None

    def __post_init__(self) -> None:
        effective_permissions = _bounded_materialize(
            self.effective_permissions, "effective_permissions", limit=MAX_GRANTS
        )
        matching_grants = _bounded_materialize(
            self.matching_grants, "matching_grants", limit=MAX_GRANTS
        )
        alternative_paths = _bounded_materialize(
            self.alternative_paths, "alternative_paths", limit=MAX_GRANTS
        )
        reason_codes = _bounded_materialize(self.reason_codes, "reason_codes")
        request_grants = _bounded_materialize(
            self.request_grants, "request_grants", limit=MAX_GRANTS
        )
        object.__setattr__(
            self,
            "effective_permissions",
            tuple(sorted(set(effective_permissions), key=lambda item: item.sort_key())),
        )
        object.__setattr__(
            self,
            "matching_grants",
            tuple(sorted(matching_grants, key=lambda item: item.grant_id)),
        )
        object.__setattr__(self, "alternative_paths", alternative_paths)
        object.__setattr__(self, "reason_codes", tuple(dict.fromkeys(reason_codes)))
        object.__setattr__(
            self,
            "request_grants",
            tuple(sorted(request_grants, key=lambda item: item.grant_id)),
        )
        if any(grant.snapshot_id != self.snapshot_id for grant in self.matching_grants):
            raise ValueError("matching grants must belong to the result snapshot")
        if any(grant.snapshot_id != self.snapshot_id for grant in self.request_grants):
            raise ValueError("request grants must belong to the result snapshot")
        if any(
            grant.snapshot_id != self.snapshot_id
            for finding in self.alternative_paths
            for grant in finding.grants
        ):
            raise ValueError("alternative grants must belong to the result snapshot")
        if self.request is None and self.request_status is not None:
            raise ValueError("request_status requires a request")
        if any(node.snapshot_id != self.snapshot_id for node in self.graph_nodes):
            raise ValueError("graph nodes must belong to the result snapshot")
        if any(edge.snapshot_id != self.snapshot_id for edge in self.graph_edges):
            raise ValueError("graph edges must belong to the result snapshot")

    @property
    def complete(self) -> bool:
        return self.completeness is Completeness.COMPLETE

    @property
    def abstained(self) -> bool:
        return self.status in {AnalysisStatus.ABSTAIN, AnalysisStatus.UNSUPPORTED}

    @property
    def supported(self) -> bool:
        return not self.abstained

    @property
    def permissions(self) -> tuple[EffectivePermission, ...]:
        return self.effective_permissions

    @property
    def grants(self) -> tuple[MatchingGrant, ...]:
        return self.matching_grants

    @property
    def permission_inventory(self) -> tuple[EffectivePermission, ...]:
        return self.effective_permissions

    @property
    def request_decision(self) -> AnalysisStatus | None:
        return self.request_status

    @property
    def requested_grants(self) -> tuple[MatchingGrant, ...]:
        return self.request_grants


def _stable_id(prefix: str, *parts: str) -> str:
    material = "\x1f".join(parts).encode("utf-8")
    return f"{prefix}-{sha256(material).hexdigest()[:32]}"


def _role_id(kind: str, namespace: str | None, name: str) -> str:
    return _stable_id("role", kind, namespace or "cluster", name)


def _binding_id(kind: str, namespace: str | None, name: str) -> str:
    return _stable_id("binding", kind, namespace or "cluster", name)


def _rule_id(role: RoleRecord | ClusterRoleRecord, index: int, rule: RbacRuleRecord) -> str:
    if rule.rule_id is not None:
        return rule.rule_id
    return _stable_id("rule", role.role_id, str(index))


def _permissions_overlap(left: EffectivePermission, right: EffectivePermission) -> bool:
    return (
        (left.api_group == right.api_group or "*" in {left.api_group, right.api_group})
        and (left.resource == right.resource or "*" in {left.resource, right.resource})
        and (left.verb == right.verb or "*" in {left.verb, right.verb})
        and (left.namespace == right.namespace or "*" in {left.namespace, right.namespace})
        and (
            left.resource_name is None
            or right.resource_name is None
            or "*" in {left.resource_name, right.resource_name}
            or left.resource_name == right.resource_name
        )
    )


def _permission_field_matches(granted: str, requested: str) -> bool:
    """Return whether one potentially-wildcard grant covers a request field."""

    return granted == requested or granted == "*"


def _subject_matches(
    subject: SubjectRecord,
    account: ServiceAccountRef,
    binding_namespace: str | None,
) -> tuple[bool, bool]:
    if subject.kind == "ServiceAccount":
        if subject.namespace is None:
            return False, True
        return subject.name == account.name and subject.namespace == account.namespace, False
    if subject.kind == "User":
        if subject.namespace is not None:
            return False, True
        expected = f"system:serviceaccount:{account.namespace}:{account.name}"
        return subject.name == expected, False
    if subject.kind == "Group":
        if subject.namespace is not None:
            return False, True
        return (
            subject.name
            in {
                "system:serviceaccounts",
                f"system:serviceaccounts:{account.namespace}",
                "system:authenticated",
            },
            False,
        )
    return False, True


class RbacAnalyzer:
    """Compute read-only core-resource permissions from one snapshot."""

    def analyze(
        self,
        snapshot: RbacSnapshotRecord,
        subject: ServiceAccountRef | SubjectRecord | str,
        *,
        namespace: str | None = None,
        name: str | None = None,
        api_group: str = CORE_API_GROUP,
        resource: str = SECRET_RESOURCE,
        target_namespace: str | None = None,
        verb: str | None = None,
        resource_name: str | None = None,
        request: PermissionRequest | None = None,
    ) -> AnalysisResult:
        snapshot = _coerce_snapshot(snapshot)
        account = _coerce_service_account(subject, namespace=namespace, name=name)
        reasons: list[ReasonCode] = []

        if request is not None and (
            api_group != CORE_API_GROUP or verb is not None or resource_name is not None
        ):
            raise ValueError("request cannot be combined with legacy permission arguments")
        if request is None and (verb is not None or resource_name is not None):
            request = PermissionRequest(
                api_group=api_group,
                resource=resource,
                namespace=target_namespace,
                verb=verb,
                resource_name=resource_name,
            )
        if (
            request is not None
            and target_namespace is not None
            and request.namespace
            not in {
                None,
                target_namespace,
            }
        ):
            raise ValueError("request namespace differs from target namespace")
        requested_namespace = (
            request.namespace
            if request is not None and request.namespace is not None
            else target_namespace
        )
        if request is not None and requested_namespace is None:
            requested_namespace = account.namespace
        if requested_namespace is not None:
            _bounded_text(requested_namespace, "target_namespace")
        inventory_api_group = request.api_group if request is not None else api_group
        inventory_resource = request.resource if request is not None else resource
        if inventory_api_group != CORE_API_GROUP:
            return self._result(
                snapshot,
                account,
                status=AnalysisStatus.UNSUPPORTED,
                completeness=Completeness.UNSUPPORTED,
                permissions=(),
                grants=(),
                reasons=(ReasonCode.UNSUPPORTED_RESOURCE,),
                request=request,
                request_status=AnalysisStatus.UNSUPPORTED if request is not None else None,
            )
        if inventory_resource not in SUPPORTED_RESOURCES:
            reason = (
                ReasonCode.UNSUPPORTED_SUBRESOURCE
                if "/" in inventory_resource
                else ReasonCode.UNSUPPORTED_RESOURCE
            )
            return self._result(
                snapshot,
                account,
                status=AnalysisStatus.UNSUPPORTED,
                completeness=Completeness.UNSUPPORTED,
                permissions=(),
                grants=(),
                reasons=(reason,),
                request=request,
                request_status=AnalysisStatus.UNSUPPORTED if request is not None else None,
            )
        if (
            snapshot.namespaces
            and requested_namespace is not None
            and requested_namespace not in snapshot.namespaces
        ):
            reasons.append(ReasonCode.SNAPSHOT_SCOPE_MISMATCH)
        if not snapshot.is_complete:
            reasons.append(ReasonCode.INCOMPLETE_SNAPSHOT)
        unsupported = bool(snapshot.unknown_kinds)
        if snapshot.unknown_kinds:
            reasons.append(ReasonCode.UNKNOWN_KIND)

        roles = cast(tuple[RoleRecord, ...], snapshot.roles)
        cluster_roles = cast(tuple[ClusterRoleRecord, ...], snapshot.cluster_roles)
        role_bindings = cast(tuple[RoleBindingRecord, ...], snapshot.role_bindings)
        cluster_role_bindings = cast(
            tuple[ClusterRoleBindingRecord, ...], snapshot.cluster_role_bindings
        )
        roles_by_key: dict[tuple[str, str | None, str], RoleRecord | ClusterRoleRecord] = {}
        if len(roles) + len(cluster_roles) > MAX_ITEMS:
            reasons.append(ReasonCode.CAPACITY_EXCEEDED)
            unsupported = True
        role_records = cast(
            Iterable[RoleRecord | ClusterRoleRecord],
            islice(chain(roles, cluster_roles), MAX_ITEMS + 1),
        )
        for role in role_records:
            roles_by_key[(role.kind, getattr(role, "namespace", None), role.name)] = role

        grants: list[MatchingGrant] = []
        capacity_exceeded = False
        if len(role_bindings) + len(cluster_role_bindings) > MAX_ITEMS:
            reasons.append(ReasonCode.CAPACITY_EXCEEDED)
            unsupported = True
            capacity_exceeded = True
        binding_records = cast(
            Iterable[RoleBindingRecord | ClusterRoleBindingRecord],
            islice(chain(role_bindings, cluster_role_bindings), MAX_ITEMS + 1),
        )
        for binding in binding_records:
            if binding.kind not in {"RoleBinding", "ClusterRoleBinding"}:
                if self._binding_scope_relevant(binding, account):
                    reasons.append(ReasonCode.UNKNOWN_KIND)
                    unsupported = True
                continue
            if not self._binding_scope_relevant(binding, account, requested_namespace):
                continue
            binding_namespace = getattr(binding, "namespace", None)
            if (
                snapshot.namespaces
                and binding.kind == "RoleBinding"
                and binding_namespace not in snapshot.namespaces
                and requested_namespace is None
            ):
                reasons.append(ReasonCode.SNAPSHOT_SCOPE_MISMATCH)
                unsupported = True
                continue
            binding_matches, subject_unsupported, subject_reason = self._binding_subject_state(
                binding,
                account,
            )
            if subject_unsupported:
                reasons.append(subject_reason)
                unsupported = True
            if not binding_matches:
                continue
            resolved_role, role_reason = self._resolve_role(binding, account, roles_by_key)
            if role_reason is not None:
                reasons.append(role_reason)
                unsupported = True
                continue
            if resolved_role is None:
                reasons.append(ReasonCode.MISSING_ROLE_REFERENCE)
                unsupported = True
                continue
            role_unsupported = False
            for index, rule in enumerate(resolved_role.rules):
                condition = _rule_condition(rule)
                if condition == ReasonCode.UNSUPPORTED_SUBRESOURCE:
                    reasons.append(condition)
                    role_unsupported = True
                    continue
                if condition == ReasonCode.WILDCARD_RULE:
                    reasons.append(condition)
                    role_unsupported = True
                if CORE_API_GROUP not in rule.api_groups and "*" not in rule.api_groups:
                    continue
                target_api_groups = ("*",) if "*" in rule.api_groups else (CORE_API_GROUP,)
                target_resources: tuple[str, ...] = (
                    ("*",) if "*" in rule.resources else (inventory_resource,)
                )
                if "*" not in rule.resources and inventory_resource not in rule.resources:
                    target_resources = ()
                if not target_resources:
                    continue
                target_verbs = ("*",) if "*" in rule.verbs else rule.verbs
                for rule_verb in target_verbs:
                    if rule_verb not in SUPPORTED_SECRET_VERBS and rule_verb != "*":
                        reasons.append(ReasonCode.UNSUPPORTED_VERB)
                        role_unsupported = True
                        continue
                    names: tuple[str | None, ...] = (
                        ("*",) if "*" in rule.resource_names else (rule.resource_names or (None,))
                    )
                    for target_resource in target_resources:
                        for target_api_group in target_api_groups:
                            for rule_name in names:
                                if len(grants) >= MAX_GRANTS:
                                    capacity_exceeded = True
                                    break
                                permission_namespace = (
                                    binding_namespace
                                    if binding.kind == "RoleBinding"
                                    else (requested_namespace or account.namespace)
                                )
                                if permission_namespace is None:
                                    permission_namespace = "*"
                                permission = EffectivePermission(
                                    api_group=target_api_group,
                                    resource=target_resource,
                                    verb=rule_verb,
                                    namespace=permission_namespace,
                                    resource_name=rule_name,
                                )
                                subject_evidence = tuple(
                                    evidence_id
                                    for subject in binding.subjects
                                    if _subject_matches(
                                        subject, account, getattr(binding, "namespace", None)
                                    )[0]
                                    for evidence_id in subject.evidence_ids
                                )
                                try:
                                    grant_evidence = _merge_ids(
                                        snapshot.evidence_ids,
                                        getattr(binding, "evidence_ids", ()),
                                        getattr(resolved_role, "evidence_ids", ()),
                                        subject_evidence,
                                    )
                                except ValueError:
                                    reasons.append(ReasonCode.CAPACITY_EXCEEDED)
                                    capacity_exceeded = True
                                    unsupported = True
                                    break
                                grants.append(
                                    MatchingGrant(
                                        permission=permission,
                                        binding_kind=binding.kind,
                                        binding_name=binding.name,
                                        binding_namespace=binding_namespace,
                                        role_kind=resolved_role.kind,
                                        role_name=resolved_role.name,
                                        role_namespace=getattr(resolved_role, "namespace", None),
                                        rule_index=index,
                                        rule_id=_rule_id(resolved_role, index, rule),
                                        snapshot_id=snapshot.snapshot_id,
                                        evidence_ids=grant_evidence,
                                    )
                                )
                            if capacity_exceeded:
                                break
                        if capacity_exceeded:
                            break
                    if capacity_exceeded:
                        break
                if capacity_exceeded:
                    break
            if role_unsupported:
                unsupported = True
            if capacity_exceeded:
                break
        if capacity_exceeded:
            reasons.append(ReasonCode.CAPACITY_EXCEEDED)
            unsupported = True

        permissions = tuple(
            sorted({grant.permission for grant in grants}, key=lambda item: item.sort_key())
        )
        by_overlap: list[list[MatchingGrant]] = []
        for grant in grants:
            overlapping = [
                group
                for group in by_overlap
                if any(
                    _permissions_overlap(grant.permission, existing.permission)
                    for existing in group
                )
            ]
            if not overlapping:
                by_overlap.append([grant])
                continue
            first = overlapping[0]
            first.append(grant)
            for group in overlapping[1:]:
                first.extend(group)
                by_overlap.remove(group)
        alternatives = tuple(
            AlternativePathFinding(
                permission=min(
                    (grant.permission for grant in group),
                    key=lambda item: (item.resource_name is not None, item.sort_key()),
                ),
                grants=tuple(group),
            )
            for group in sorted(
                (group for group in by_overlap if len(group) > 1),
                key=lambda item: min(grant.grant_id for grant in item),
            )
        )
        if alternatives:
            reasons.append(ReasonCode.ADDITIVE_GRANT)
        if not permissions:
            reasons.append(ReasonCode.NO_MATCHING_GRANT)
        else:
            reasons.append(ReasonCode.GRANTED)

        request_status: AnalysisStatus | None = None
        request_grants: tuple[MatchingGrant, ...] = ()
        requested_permission: EffectivePermission | None = None
        if request is not None:
            (
                request_status,
                request_grants,
                requested_permission,
                request_reasons,
            ) = self._evaluate_request(request, account, grants, requested_namespace)
            reasons.extend(request_reasons)

        if ReasonCode.SNAPSHOT_SCOPE_MISMATCH in reasons:
            status = AnalysisStatus.ABSTAIN
            completeness = Completeness.UNSUPPORTED
        elif not snapshot.complete or snapshot.missing_resources:
            status = AnalysisStatus.ABSTAIN
            completeness = Completeness.INCOMPLETE
        elif snapshot.unknown_kinds:
            status = AnalysisStatus.UNSUPPORTED
            completeness = Completeness.UNSUPPORTED
        elif unsupported:
            status = AnalysisStatus.UNSUPPORTED
            completeness = Completeness.UNSUPPORTED
        elif permissions:
            status = AnalysisStatus.GRANTED
            completeness = Completeness.COMPLETE
        else:
            status = AnalysisStatus.DENIED
            completeness = Completeness.COMPLETE
        if request is not None and status not in {
            AnalysisStatus.ABSTAIN,
            AnalysisStatus.UNSUPPORTED,
        }:
            status = request_status or AnalysisStatus.UNSUPPORTED
        if request is not None and status in {AnalysisStatus.ABSTAIN, AnalysisStatus.UNSUPPORTED}:
            # No nested request decision may bypass the snapshot-level boundary.
            request_status = status
            request_grants = ()
        return self._result(
            snapshot,
            account,
            status=status,
            completeness=completeness,
            permissions=permissions,
            grants=tuple(grants),
            reasons=tuple(reasons),
            alternatives=alternatives,
            request=request,
            request_status=request_status,
            request_grants=request_grants,
            requested_permission=requested_permission,
        )

    @staticmethod
    def _binding_scope_relevant(
        binding: RoleBindingRecord | ClusterRoleBindingRecord,
        account: ServiceAccountRef,
        target_namespace: str | None = None,
    ) -> bool:
        binding_namespace = getattr(binding, "namespace", None)
        if target_namespace is not None and binding.kind == "RoleBinding":
            return binding_namespace == target_namespace
        return True

    @staticmethod
    def _binding_subject_state(
        binding: RoleBindingRecord | ClusterRoleBindingRecord,
        account: ServiceAccountRef,
    ) -> tuple[bool, bool, ReasonCode]:
        matches = False
        unsupported = False
        reason = ReasonCode.UNKNOWN_KIND
        for subject in islice(binding.subjects, MAX_ITEMS + 1):
            match, ambiguous = _subject_matches(
                subject, account, getattr(binding, "namespace", None)
            )
            if ambiguous:
                unsupported = True
                reason = (
                    ReasonCode.MISSING_SUBJECT_NAMESPACE
                    if subject.kind == "ServiceAccount" and subject.namespace is None
                    else ReasonCode.UNKNOWN_KIND
                )
            matches = matches or match
        return matches, unsupported, reason

    @classmethod
    def _binding_applies(
        cls,
        binding: RoleBindingRecord | ClusterRoleBindingRecord,
        account: ServiceAccountRef,
    ) -> bool:
        if not cls._binding_scope_relevant(binding, account):
            return False
        return cls._binding_subject_state(binding, account)[0]

    @staticmethod
    def _resolve_role(
        binding: RoleBindingRecord | ClusterRoleBindingRecord,
        account: ServiceAccountRef,
        roles: Mapping[tuple[str, str | None, str], RoleRecord | ClusterRoleRecord],
    ) -> tuple[RoleRecord | ClusterRoleRecord | None, ReasonCode | None]:
        role_kind = binding.role_ref_kind
        binding_namespace = getattr(binding, "namespace", None)
        if role_kind not in {"Role", "ClusterRole"}:
            return None, ReasonCode.UNKNOWN_KIND
        if binding.kind == "ClusterRoleBinding" and binding_namespace is not None:
            return None, ReasonCode.NAMESPACE_MISMATCH
        if binding.kind == "ClusterRoleBinding" and role_kind != "ClusterRole":
            return None, ReasonCode.NAMESPACE_MISMATCH
        if binding.kind == "RoleBinding" and role_kind == "Role":
            role = roles.get(("Role", binding_namespace, binding.role_ref_name))
            if role is None:
                return None, ReasonCode.MISSING_ROLE_REFERENCE
        else:
            role = roles.get(("ClusterRole", None, binding.role_ref_name))
            if role is None:
                return None, ReasonCode.MISSING_ROLE_REFERENCE
        if role.kind not in {"Role", "ClusterRole"}:
            return None, ReasonCode.UNKNOWN_KIND
        if role.is_aggregated:
            return None, ReasonCode.AGGREGATED_ROLE
        if role.kind == "Role" and getattr(role, "namespace", None) != binding_namespace:
            return None, ReasonCode.NAMESPACE_MISMATCH
        if role.kind == "ClusterRole" and role.namespace is not None:
            return None, ReasonCode.NAMESPACE_MISMATCH
        return role, None

    @staticmethod
    def _evaluate_request(
        request: PermissionRequest,
        account: ServiceAccountRef,
        grants: Sequence[MatchingGrant],
        target_namespace: str | None = None,
    ) -> tuple[
        AnalysisStatus,
        tuple[MatchingGrant, ...],
        EffectivePermission | None,
        tuple[ReasonCode, ...],
    ]:
        reasons: list[ReasonCode] = []
        if request.api_group != CORE_API_GROUP:
            return AnalysisStatus.UNSUPPORTED, (), None, (ReasonCode.UNSUPPORTED_RESOURCE,)
        if request.resource not in SUPPORTED_RESOURCES:
            reason = (
                ReasonCode.UNSUPPORTED_SUBRESOURCE
                if "/" in request.resource
                else ReasonCode.UNSUPPORTED_RESOURCE
            )
            return AnalysisStatus.UNSUPPORTED, (), None, (reason,)
        if request.verb is None:
            return AnalysisStatus.UNSUPPORTED, (), None, (ReasonCode.REQUEST_INCOMPLETE,)
        if request.verb not in SUPPORTED_SECRET_VERBS:
            return AnalysisStatus.UNSUPPORTED, (), None, (ReasonCode.UNSUPPORTED_VERB,)
        request_namespace = request.namespace or target_namespace or account.namespace
        matching = tuple(
            grant
            for grant in grants
            if _permission_field_matches(grant.permission.api_group, request.api_group)
            and _permission_field_matches(grant.permission.resource, request.resource)
            and _permission_field_matches(grant.permission.verb, request.verb)
            and _permission_field_matches(grant.permission.namespace, request_namespace)
        )
        if request.verb == "get":
            if request.resource_name is None:
                return (
                    AnalysisStatus.UNSUPPORTED,
                    (),
                    None,
                    (ReasonCode.NAMED_GET_REQUIRES_RESOURCE_NAME,),
                )
            requested = EffectivePermission(
                request.api_group,
                request.resource,
                request.verb,
                account.namespace,
                request.resource_name,
            )
            matching = tuple(
                grant
                for grant in matching
                if grant.permission.resource_name in {None, "*", request.resource_name}
            )
        else:
            selector_name = request.field_selector_resource_name
            if request.resource_name is not None and selector_name != request.resource_name:
                return (
                    AnalysisStatus.UNSUPPORTED,
                    (),
                    None,
                    (ReasonCode.NAMED_LIST_WATCH_REQUIRES_FIELD_SELECTOR,),
                )
            if selector_name is None:
                unrestricted = tuple(
                    grant for grant in matching if grant.permission.resource_name is None
                )
                named = tuple(
                    grant for grant in matching if grant.permission.resource_name is not None
                )
                if unrestricted:
                    matching = unrestricted
                elif named:
                    return (
                        AnalysisStatus.UNSUPPORTED,
                        (),
                        None,
                        (ReasonCode.NAMED_LIST_WATCH_REQUIRES_FIELD_SELECTOR,),
                    )
                else:
                    matching = ()
            else:
                requested = EffectivePermission(
                    request.api_group,
                    request.resource,
                    request.verb,
                    request_namespace,
                    selector_name,
                )
                matching = tuple(
                    grant
                    for grant in matching
                    if grant.permission.resource_name in {None, "*", selector_name}
                )
        if request.verb == "get":
            requested = EffectivePermission(
                request.api_group,
                request.resource,
                request.verb,
                request_namespace,
                request.resource_name,
            )
        elif request.field_selector_resource_name is None:
            requested = EffectivePermission(
                request.api_group,
                request.resource,
                request.verb,
                request_namespace,
                None,
            )
        if matching:
            return AnalysisStatus.GRANTED, matching, requested, tuple(reasons)
        return AnalysisStatus.DENIED, (), requested, tuple(reasons)

    def _result(
        self,
        snapshot: RbacSnapshotRecord,
        account: ServiceAccountRef,
        *,
        status: AnalysisStatus,
        completeness: Completeness,
        permissions: tuple[EffectivePermission, ...],
        grants: tuple[MatchingGrant, ...],
        reasons: Sequence[ReasonCode],
        alternatives: tuple[AlternativePathFinding, ...] = (),
        request: PermissionRequest | None = None,
        request_status: AnalysisStatus | None = None,
        request_grants: tuple[MatchingGrant, ...] = (),
        requested_permission: EffectivePermission | None = None,
    ) -> AnalysisResult:
        try:
            nodes, edges, graph_missing = _build_graph(snapshot, account, grants)
        except ValueError:
            nodes, edges, graph_missing = (), (), True
        all_reasons = list(reasons)
        if graph_missing and grants:
            all_reasons.append(ReasonCode.GRAPH_EVIDENCE_MISSING)
        return AnalysisResult(
            snapshot_id=snapshot.snapshot_id,
            subject=account,
            status=status,
            completeness=completeness,
            effective_permissions=permissions,
            matching_grants=grants,
            alternative_paths=alternatives,
            reason_codes=tuple(all_reasons),
            graph_nodes=nodes,
            graph_edges=edges,
            request=request,
            request_status=request_status,
            request_grants=request_grants,
            requested_permission=requested_permission,
        )


def _coerce_snapshot(snapshot: RbacSnapshotRecord) -> RbacSnapshotRecord:
    if isinstance(snapshot, RbacSnapshotRecord):
        return snapshot
    if isinstance(snapshot, Mapping):
        return RbacSnapshotRecord(**snapshot)
    raise TypeError("snapshot must be an RbacSnapshotRecord")


def _coerce_service_account(
    subject: ServiceAccountRef | SubjectRecord | str,
    *,
    namespace: str | None,
    name: str | None,
) -> ServiceAccountRef:
    if isinstance(subject, ServiceAccountRef):
        account = subject
    elif isinstance(subject, SubjectRecord):
        if subject.kind != "ServiceAccount" or subject.namespace is None:
            raise ValueError("subject must be a namespaced ServiceAccount")
        account = ServiceAccountRef(subject.name, subject.namespace)
    elif isinstance(subject, str):
        account = ServiceAccountRef(name or subject, namespace or "")
    else:
        raise TypeError("subject must be a ServiceAccountRef, SubjectRecord, or name")
    if namespace is not None and namespace != account.namespace:
        raise ValueError("subject namespace differs from the requested namespace")
    if name is not None and name != account.name:
        raise ValueError("subject name differs from the requested name")
    return account


def _rule_condition(rule: RbacRuleRecord) -> ReasonCode | None:
    if rule.has_unsupported_subresource:
        return ReasonCode.UNSUPPORTED_SUBRESOURCE
    if rule.has_wildcard:
        return ReasonCode.WILDCARD_RULE
    # An explicitly named unsupported verb on a Secret rule is detected by
    # the analyzer after the resource/api-group intersection is known.
    return None


def _merge_ids(*collections: Iterable[str]) -> tuple[str, ...]:
    values: set[str] = set()
    for collection in collections:
        for value in islice(collection, MAX_ITEMS + 1):
            values.add(value)
            if len(values) > MAX_ITEMS:
                raise ValueError("merged evidence exceeds the bounded item count")
    return tuple(sorted(values))


def _node_id(snapshot_id: str, node_type: GraphNodeType, object_ref: str) -> str:
    return _stable_id("node", snapshot_id, node_type.value, object_ref)


def _edge_id(
    snapshot_id: str,
    edge_type: GraphEdgeType,
    from_node_id: str,
    to_node_id: str,
) -> str:
    return _stable_id("edge", snapshot_id, edge_type.value, from_node_id, to_node_id)


def _graph_evidence(*records: Any) -> tuple[str, ...]:
    return _merge_ids(*(getattr(record, "evidence_ids", ()) for record in records))


def _build_graph(
    snapshot: RbacSnapshotRecord,
    account: ServiceAccountRef,
    grants: Sequence[MatchingGrant],
) -> tuple[tuple[GraphNode, ...], tuple[GraphEdge, ...], bool]:
    if not grants:
        return (), (), False
    # A graph item with no source evidence cannot be presented as evidence.
    # The caller still gets the deterministic permission result, while the
    # graph is omitted rather than inventing a provenance ID.
    if not any(grant.evidence_ids for grant in grants):
        return (), (), True

    node_data: dict[tuple[GraphNodeType, str], tuple[str, ...]] = {}
    edge_data: dict[tuple[GraphEdgeType, str, str], tuple[str, ...]] = {}

    subject_ref = f"ServiceAccount:{account.namespace}/{account.name}"
    subject_node_key = (GraphNodeType.SUBJECT, subject_ref)
    node_data[subject_node_key] = _merge_ids(
        snapshot.evidence_ids, *(grant.evidence_ids for grant in grants)
    )
    for grant in grants:
        binding_ref = (
            f"{grant.binding_kind}:{grant.binding_namespace or 'cluster'}/{grant.binding_name}"
        )
        role_ref = f"{grant.role_kind}:{grant.role_namespace or 'cluster'}/{grant.role_name}"
        resource_name = grant.permission.resource_name or "all"
        operation_ref = (
            f"operation:{grant.permission.namespace}:{grant.permission.verb}:"
            f"{grant.permission.resource}:{resource_name}"
        )
        binding_key = (GraphNodeType.BINDING, binding_ref)
        role_key = (GraphNodeType.ROLE, role_ref)
        operation_key = (GraphNodeType.OPERATION, operation_ref)
        evidence = grant.evidence_ids
        node_data[binding_key] = _merge_ids(node_data.get(binding_key, ()), evidence)
        node_data[role_key] = _merge_ids(node_data.get(role_key, ()), evidence)
        node_data[operation_key] = _merge_ids(node_data.get(operation_key, ()), evidence)
        edge_data[(GraphEdgeType.BINDS_SUBJECT, subject_ref, binding_ref)] = evidence
        edge_data[(GraphEdgeType.REFERENCES_ROLE, binding_ref, role_ref)] = evidence
        edge_data[(GraphEdgeType.CONTAINS_RULE, role_ref, operation_ref)] = evidence
        edge_data[(GraphEdgeType.OBSERVED_ACCESS, subject_ref, operation_ref)] = evidence

    nodes: list[GraphNode] = []
    for (node_type, object_ref), evidence_ids in sorted(
        node_data.items(), key=lambda item: (item[0][0].value, item[0][1])
    ):
        if not evidence_ids:
            continue
        nodes.append(
            GraphNode(
                node_id=_node_id(snapshot.snapshot_id, node_type, object_ref),
                node_type=node_type,
                snapshot_id=snapshot.snapshot_id,
                evidence_ids=evidence_ids,
                object_ref=object_ref,
            )
        )
    node_ids = {(node.object_ref, node.node_type): node.node_id for node in nodes}
    edges: list[GraphEdge] = []
    for (edge_type, from_ref, to_ref), evidence_ids in sorted(
        edge_data.items(), key=lambda item: (item[0][0].value, item[0][1], item[0][2])
    ):
        from_type = (
            GraphNodeType.SUBJECT
            if from_ref.startswith("ServiceAccount:")
            else (
                GraphNodeType.BINDING
                if from_ref.startswith(("RoleBinding:", "ClusterRoleBinding:"))
                else GraphNodeType.ROLE
            )
        )
        to_type = (
            GraphNodeType.BINDING
            if to_ref.startswith(("RoleBinding:", "ClusterRoleBinding:"))
            else (
                GraphNodeType.ROLE
                if to_ref.startswith(("Role:", "ClusterRole:"))
                else GraphNodeType.OPERATION
            )
        )
        from_id = node_ids.get((from_ref, from_type))
        to_id = node_ids.get((to_ref, to_type))
        if from_id is None or to_id is None or not evidence_ids:
            continue
        edges.append(
            GraphEdge(
                edge_id=_edge_id(snapshot.snapshot_id, edge_type, from_id, to_id),
                edge_type=edge_type,
                snapshot_id=snapshot.snapshot_id,
                from_node_id=from_id,
                to_node_id=to_id,
                evidence_ids=evidence_ids,
            )
        )
    return tuple(nodes), tuple(edges), len(nodes) == 0 or len(edges) == 0


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    evidence_id: str
    snapshot_id: str
    kind: str = "rbac"
    source_id: str | None = None
    object_id: str | None = None
    object_digest: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence_id", _bounded_text(self.evidence_id, "evidence_id"))
        object.__setattr__(self, "snapshot_id", _identifier(self.snapshot_id, "snapshot_id"))
        object.__setattr__(self, "kind", _bounded_text(self.kind, "kind"))
        if self.source_id is not None:
            object.__setattr__(self, "source_id", _identifier(self.source_id, "source_id"))
        if self.object_id is not None:
            object.__setattr__(self, "object_id", _identifier(self.object_id, "object_id"))
        if self.object_digest is not None:
            _digest(self.object_digest)


@dataclass(frozen=True, slots=True)
class ApiSuccessFact:
    audit_id: str
    snapshot_id: str
    response_code: int
    evidence_ids: tuple[str, ...]
    source_id: str | None = None
    object_id: str | None = None
    object_digest: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "audit_id", _bounded_text(self.audit_id, "audit_id"))
        object.__setattr__(self, "snapshot_id", _identifier(self.snapshot_id, "snapshot_id"))
        _response_code(self.response_code)
        object.__setattr__(self, "evidence_ids", _bounded_ids(self.evidence_ids))
        _validate_fact_object_fields(self)


@dataclass(frozen=True, slots=True)
class BindingReferenceFact:
    binding_id: str
    role_id: str
    snapshot_id: str
    evidence_ids: tuple[str, ...]
    source_id: str | None = None
    object_id: str | None = None
    object_digest: str | None = None

    def __post_init__(self) -> None:
        for field_name in ("binding_id", "role_id", "snapshot_id"):
            object.__setattr__(
                self, field_name, _bounded_text(getattr(self, field_name), field_name)
            )
        object.__setattr__(self, "evidence_ids", _bounded_ids(self.evidence_ids))
        _validate_fact_object_fields(self)


@dataclass(frozen=True, slots=True)
class RoleRuleFact:
    role_id: str
    rule_id: str
    snapshot_id: str
    evidence_ids: tuple[str, ...]
    source_id: str | None = None
    object_id: str | None = None
    object_digest: str | None = None

    def __post_init__(self) -> None:
        for field_name in ("role_id", "rule_id", "snapshot_id"):
            object.__setattr__(
                self, field_name, _bounded_text(getattr(self, field_name), field_name)
            )
        object.__setattr__(self, "evidence_ids", _bounded_ids(self.evidence_ids))
        _validate_fact_object_fields(self)


@dataclass(frozen=True, slots=True)
class ForbiddenProbeFact:
    probe_id: str
    snapshot_id: str
    response_code: int
    evidence_ids: tuple[str, ...]
    source_id: str | None = None
    object_id: str | None = None
    object_digest: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "probe_id", _bounded_text(self.probe_id, "probe_id"))
        object.__setattr__(self, "snapshot_id", _identifier(self.snapshot_id, "snapshot_id"))
        _response_code(self.response_code)
        object.__setattr__(self, "evidence_ids", _bounded_ids(self.evidence_ids))
        _validate_fact_object_fields(self)


@dataclass(frozen=True, slots=True)
class BusinessInvariantFact:
    contract_id: str
    result_id: str
    snapshot_id: str
    passed: bool
    evidence_ids: tuple[str, ...]
    source_id: str | None = None
    object_id: str | None = None
    object_digest: str | None = None

    def __post_init__(self) -> None:
        for field_name in ("contract_id", "result_id", "snapshot_id"):
            object.__setattr__(
                self, field_name, _bounded_text(getattr(self, field_name), field_name)
            )
        _strict_bool(self.passed, "passed")
        object.__setattr__(self, "evidence_ids", _bounded_ids(self.evidence_ids))
        _validate_fact_object_fields(self)


@dataclass(frozen=True, slots=True)
class SnapshotScopeFact:
    snapshot_id: str
    scope_id: str
    complete: bool
    evidence_ids: tuple[str, ...]
    source_id: str | None = None
    object_id: str | None = None
    object_digest: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "snapshot_id", _identifier(self.snapshot_id, "snapshot_id"))
        object.__setattr__(self, "scope_id", _bounded_text(self.scope_id, "scope_id"))
        _strict_bool(self.complete, "complete")
        object.__setattr__(self, "evidence_ids", _bounded_ids(self.evidence_ids))
        _validate_fact_object_fields(self)


@dataclass(frozen=True, slots=True)
class SourceObjectFact:
    source_id: str
    object_id: str
    object_digest: str
    snapshot_id: str
    evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        for field_name in ("source_id", "object_id", "object_digest", "snapshot_id"):
            object.__setattr__(
                self, field_name, _bounded_text(getattr(self, field_name), field_name)
            )
        _identifier(self.source_id, "source_id")
        _identifier(self.object_id, "object_id")
        _identifier(self.snapshot_id, "snapshot_id")
        _digest(self.object_digest)
        object.__setattr__(self, "evidence_ids", _bounded_ids(self.evidence_ids))


@dataclass(frozen=True, slots=True)
class ClaimContext:
    """Typed claim facts and evidence references; narrative text has no field."""

    snapshot: RbacSnapshotRecord | None = None
    evidence: tuple[EvidenceRef, ...] = ()
    api_success: tuple[ApiSuccessFact, ...] = ()
    binding_references: tuple[BindingReferenceFact, ...] = ()
    role_rules: tuple[RoleRuleFact, ...] = ()
    forbidden_probes: tuple[ForbiddenProbeFact, ...] = ()
    business_invariants: tuple[BusinessInvariantFact, ...] = ()
    snapshot_scopes: tuple[SnapshotScopeFact, ...] = ()
    source_objects: tuple[SourceObjectFact, ...] = ()

    def __post_init__(self) -> None:
        if self.snapshot is not None and not isinstance(self.snapshot, RbacSnapshotRecord):
            object.__setattr__(self, "snapshot", _coerce_snapshot(self.snapshot))
        object.__setattr__(self, "evidence", _normalize_context_records(self.evidence, EvidenceRef))
        evidence_ids = tuple(item.evidence_id for item in self.evidence)
        if len(set(evidence_ids)) != len(evidence_ids):
            raise ValueError("claim context contains duplicate evidence IDs")
        for field_name, expected_type in (
            ("api_success", ApiSuccessFact),
            ("binding_references", BindingReferenceFact),
            ("role_rules", RoleRuleFact),
            ("forbidden_probes", ForbiddenProbeFact),
            ("business_invariants", BusinessInvariantFact),
            ("snapshot_scopes", SnapshotScopeFact),
            ("source_objects", SourceObjectFact),
        ):
            object.__setattr__(
                self,
                field_name,
                _normalize_context_records(getattr(self, field_name), expected_type),
            )


def _normalize_context_records(
    values: Iterable[Any] | Mapping[str, Any] | None, expected_type: type[Any]
) -> tuple[Any, ...]:
    records = _coerce_records(values)
    result = tuple(
        value if isinstance(value, expected_type) else expected_type(**value) for value in records
    )
    if len(result) > MAX_ITEMS:
        raise ValueError("claim context exceeds the bounded item count")
    return result


@dataclass(frozen=True, slots=True)
class ClaimVerification:
    claim_id: str
    predicate: ClaimPredicate
    snapshot_id: str
    verified: bool
    reason_codes: tuple[ReasonCode, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "claim_id", _bounded_text(self.claim_id, "claim_id"))
        object.__setattr__(self, "snapshot_id", _bounded_text(self.snapshot_id, "snapshot_id"))
        reason_codes = _bounded_materialize(self.reason_codes, "claim reason_codes")
        object.__setattr__(self, "reason_codes", tuple(dict.fromkeys(reason_codes)))

    @property
    def ok(self) -> bool:
        return self.verified

    @property
    def verification_scope(self) -> str:
        return "SUPPLIED_RECORDS_ONLY"

    @property
    def source_authenticated(self) -> bool:
        return False

    def __bool__(self) -> bool:
        return self.verified


class ClaimVerifier:
    """Verify fixed-predicate claims against typed, source-bound facts.

    The verifier accepts the domain's ``TypedClaim`` only.  It does not parse
    payload documents, narrative strings, runner assertions, or generic trust
    flags into facts.
    """

    def __init__(self, context: ClaimContext):
        self.context = context
        self._evidence = {item.evidence_id: item for item in context.evidence}

    def verify(self, claim: TypedClaim) -> ClaimVerification:
        if isinstance(claim, TypedClaim):
            try:
                claim = TypedClaim.model_validate(claim)
            except (ValidationError, TypeError, ValueError):
                claim = None  # type: ignore[assignment]
        if not isinstance(claim, TypedClaim):
            return ClaimVerification(
                claim_id="invalid-claim",
                predicate=ClaimPredicate.OBSERVED_API_SUCCESS,
                snapshot_id="unknown",
                verified=False,
                reason_codes=(ReasonCode.CLAIM_ARGUMENT_MISMATCH,),
            )
        predicate = _claim_predicate(claim)
        claim_id = getattr(claim, "claim_id", "claim")
        snapshot_id = getattr(claim, "snapshot_id", "")
        reasons: list[ReasonCode] = []
        if predicate is None:
            return ClaimVerification(
                claim_id=claim_id,
                predicate=ClaimPredicate.OBSERVED_API_SUCCESS,
                snapshot_id=snapshot_id or "unknown",
                verified=False,
                reason_codes=(ReasonCode.CLAIM_ARGUMENT_MISMATCH,),
            )
        expected_arity = {
            ClaimPredicate.OBSERVED_API_SUCCESS: 1,
            ClaimPredicate.BINDING_REFERENCES_ROLE: 2,
            ClaimPredicate.ROLE_CONTAINS_RULE: 2,
            ClaimPredicate.PROBE_RETURNED_FORBIDDEN: 1,
            ClaimPredicate.BUSINESS_INVARIANT_PASSED: 2,
            ClaimPredicate.SNAPSHOT_COMPLETE_FOR_SCOPE: 2,
            ClaimPredicate.SOURCE_OBJECT_MATCHES: 3,
        }[predicate]
        arguments = tuple(getattr(claim, "arguments", ()))
        evidence_ids = tuple(getattr(claim, "evidence_ids", ()))
        if len(arguments) != expected_arity:
            reasons.append(ReasonCode.CLAIM_ARGUMENT_MISMATCH)
        if self.context.snapshot is None:
            reasons.append(ReasonCode.CLAIM_CONTEXT_MISSING)
        elif self.context.snapshot.snapshot_id != snapshot_id:
            reasons.append(ReasonCode.CLAIM_SNAPSHOT_MISMATCH)
        if not evidence_ids or any(
            evidence_id not in self._evidence for evidence_id in evidence_ids
        ):
            reasons.append(ReasonCode.CLAIM_EVIDENCE_MISSING)
        else:
            if any(
                self._evidence[evidence_id].snapshot_id != snapshot_id
                for evidence_id in evidence_ids
            ):
                reasons.append(ReasonCode.CLAIM_EVIDENCE_MISMATCH)
            if any(self._evidence[evidence_id].source_id is None for evidence_id in evidence_ids):
                reasons.append(ReasonCode.CLAIM_SOURCE_MISMATCH)
        if reasons:
            return self._result(claim_id, predicate, snapshot_id, False, reasons)

        fact: Any | None = None
        verified = False
        if predicate is ClaimPredicate.OBSERVED_API_SUCCESS and len(arguments) == 1:
            fact = _find(self.context.api_success, "audit_id", arguments[0])
            verified = fact is not None and 200 <= fact.response_code < 300
        elif predicate is ClaimPredicate.BINDING_REFERENCES_ROLE and len(arguments) == 2:
            fact = next(
                (
                    item
                    for item in self.context.binding_references
                    if item.binding_id == arguments[0] and item.role_id == arguments[1]
                ),
                None,
            )
            verified = (
                fact is not None
                and self._binding_role_exists(arguments[0], arguments[1], snapshot_id)
                and self._fact_object_matches_binding(fact, arguments[0])
            )
        elif predicate is ClaimPredicate.ROLE_CONTAINS_RULE and len(arguments) == 2:
            fact = next(
                (
                    item
                    for item in self.context.role_rules
                    if item.role_id == arguments[0] and item.rule_id == arguments[1]
                ),
                None,
            )
            verified = (
                fact is not None
                and self._role_rule_exists(arguments[0], arguments[1], snapshot_id)
                and self._fact_object_matches_role(fact, arguments[0])
            )
        elif predicate is ClaimPredicate.PROBE_RETURNED_FORBIDDEN and len(arguments) == 1:
            fact = _find(self.context.forbidden_probes, "probe_id", arguments[0])
            verified = fact is not None and fact.response_code == 403
        elif predicate is ClaimPredicate.BUSINESS_INVARIANT_PASSED and len(arguments) == 2:
            fact = next(
                (
                    item
                    for item in self.context.business_invariants
                    if item.contract_id == arguments[0] and item.result_id == arguments[1]
                ),
                None,
            )
            verified = fact is not None and fact.passed
        elif predicate is ClaimPredicate.SNAPSHOT_COMPLETE_FOR_SCOPE and len(arguments) == 2:
            fact = next(
                (
                    item
                    for item in self.context.snapshot_scopes
                    if item.snapshot_id == arguments[0] and item.scope_id == arguments[1]
                ),
                None,
            )
            verified = (
                fact is not None
                and fact.complete
                and self.context.snapshot is not None
                and self.context.snapshot.snapshot_id == arguments[0]
                and self.context.snapshot.is_complete
                and self.context.snapshot.scope_id == arguments[1]
            )
        elif predicate is ClaimPredicate.SOURCE_OBJECT_MATCHES and len(arguments) == 3:
            fact = next(
                (
                    item
                    for item in self.context.source_objects
                    if item.source_id == arguments[0]
                    and item.object_id == arguments[1]
                    and item.object_digest == arguments[2]
                ),
                None,
            )
            verified = fact is not None and self._source_object_exists(fact, snapshot_id)
        if fact is None:
            reasons.append(ReasonCode.CLAIM_FACT_MISSING)
        elif not self._fact_references_match(fact, evidence_ids):
            reasons.append(ReasonCode.CLAIM_EVIDENCE_MISMATCH)
        elif not self._content_matches(fact):
            reasons.append(ReasonCode.CLAIM_CONTENT_MISMATCH)
        if not verified:
            reasons.append(ReasonCode.CLAIM_FACT_FALSE)
        return self._result(claim_id, predicate, snapshot_id, verified and not reasons, reasons)

    def _result(
        self,
        claim_id: str,
        predicate: ClaimPredicate,
        snapshot_id: str,
        verified: bool,
        reasons: Iterable[ReasonCode],
    ) -> ClaimVerification:
        return ClaimVerification(
            claim_id=claim_id,
            predicate=predicate,
            snapshot_id=snapshot_id,
            verified=verified,
            reason_codes=tuple(dict.fromkeys(reasons)),
        )

    def _binding_role_exists(self, binding_id: str, role_id: str, snapshot_id: str) -> bool:
        snapshot = self.context.snapshot
        if snapshot is None or snapshot.snapshot_id != snapshot_id:
            return False
        bindings = cast(tuple[RoleBindingRecord, ...], snapshot.role_bindings) + cast(
            tuple[ClusterRoleBindingRecord, ...], snapshot.cluster_role_bindings
        )
        binding = next(
            (item for item in bindings if item.binding_id == binding_id or item.name == binding_id),
            None,
        )
        if binding is None:
            return False
        role = self._find_role(role_id, snapshot)
        if role is None:
            return False
        if binding.role_ref_name != role.name:
            return False
        if binding.role_ref_kind != role.kind:
            return False
        if binding.role_ref_kind == "Role":
            return getattr(binding, "namespace", None) == getattr(role, "namespace", None)
        return True

    def _role_rule_exists(self, role_id: str, rule_id: str, snapshot_id: str) -> bool:
        snapshot = self.context.snapshot
        if snapshot is None or snapshot.snapshot_id != snapshot_id:
            return False
        role = self._find_role(role_id, snapshot)
        if role is None:
            return False
        return any(_rule_id(role, index, rule) == rule_id for index, rule in enumerate(role.rules))

    def _fact_object_matches_binding(self, fact: BindingReferenceFact, binding_id: str) -> bool:
        snapshot = self.context.snapshot
        if snapshot is None or fact.object_id is None or fact.object_digest is None:
            return False
        bindings = cast(tuple[RoleBindingRecord, ...], snapshot.role_bindings) + cast(
            tuple[ClusterRoleBindingRecord, ...], snapshot.cluster_role_bindings
        )
        binding = next(
            (item for item in bindings if item.binding_id == binding_id or item.name == binding_id),
            None,
        )
        actual = next((item for item in snapshot.objects if item.object_id == fact.object_id), None)
        return bool(
            binding
            and actual
            and actual.kind == binding.kind
            and actual.name == binding.name
            and actual.namespace == getattr(binding, "namespace", None)
            and actual.object_digest == fact.object_digest
        )

    def _fact_object_matches_role(self, fact: RoleRuleFact, role_id: str) -> bool:
        snapshot = self.context.snapshot
        if snapshot is None or fact.object_id is None or fact.object_digest is None:
            return False
        role = self._find_role(role_id, snapshot)
        actual = next((item for item in snapshot.objects if item.object_id == fact.object_id), None)
        return bool(
            role
            and actual
            and actual.kind == role.kind
            and actual.name == role.name
            and actual.namespace == getattr(role, "namespace", None)
            and actual.object_digest == fact.object_digest
        )

    @staticmethod
    def _find_role(
        role_id: str, snapshot: RbacSnapshotRecord
    ) -> RoleRecord | ClusterRoleRecord | None:
        roles = cast(tuple[RoleRecord, ...], snapshot.roles) + cast(
            tuple[ClusterRoleRecord, ...], snapshot.cluster_roles
        )
        for role in roles:
            if role.role_id == role_id or role.name == role_id:
                return role
        return None

    def _source_object_exists(self, fact: SourceObjectFact, snapshot_id: str) -> bool:
        snapshot = self.context.snapshot
        if snapshot is None or fact.snapshot_id != snapshot_id:
            return False
        if snapshot.source_id != fact.source_id:
            return False
        actual = next(
            (item for item in snapshot.objects if item.object_id == fact.object_id),
            None,
        )
        return bool(
            actual
            and actual.snapshot_id == snapshot_id
            and actual.source_id == fact.source_id
            and actual.object_digest == fact.object_digest
        )

    def _content_matches(self, fact: Any) -> bool:
        """Check that the metadata-object digest covers the typed fact fields."""

        snapshot = self.context.snapshot
        object_id = getattr(fact, "object_id", None)
        object_digest = getattr(fact, "object_digest", None)
        if snapshot is None or object_id is None or object_digest is None:
            return False
        if not isinstance(
            fact,
            (ApiSuccessFact, ForbiddenProbeFact, BusinessInvariantFact, SnapshotScopeFact),
        ):
            return True
        payload = asdict(fact)
        for field_name in ("evidence_ids", "source_id", "object_id", "object_digest"):
            payload.pop(field_name, None)
        return canonical_digest(payload) == object_digest

    def _fact_references_match(self, fact: Any, claim_evidence: Sequence[str]) -> bool:
        snapshot = self.context.snapshot
        fact_snapshot = getattr(fact, "snapshot_id", None)
        source_id = getattr(fact, "source_id", None)
        if snapshot is None or fact_snapshot != snapshot.snapshot_id:
            return False
        if source_id is None or snapshot.source_id != source_id:
            return False
        if not _fact_evidence_is_claimed(fact, claim_evidence):
            return False
        for evidence_id in getattr(fact, "evidence_ids", ()):
            evidence = self._evidence.get(evidence_id)
            if evidence is None or evidence.snapshot_id != snapshot.snapshot_id:
                return False
            if evidence.source_id != source_id:
                return False
            object_id = getattr(fact, "object_id", None)
            object_digest = getattr(fact, "object_digest", None)
            if object_id is not None and evidence.object_id not in {None, object_id}:
                return False
            if object_digest is not None and evidence.object_digest not in {None, object_digest}:
                return False
        object_id = getattr(fact, "object_id", None)
        object_digest = getattr(fact, "object_digest", None)
        if object_id is None or object_digest is None:
            return False
        actual = next((item for item in snapshot.objects if item.object_id == object_id), None)
        if not actual or not (
            actual.snapshot_id == snapshot.snapshot_id
            and actual.source_id == source_id
            and actual.object_digest == object_digest
        ):
            return False
        expected_object = _fact_object_identity(fact)
        if (
            expected_object is not None
            and (
                actual.kind,
                actual.name,
            )
            != expected_object
        ):
            return False
        actual_evidence = set(actual.evidence_ids)
        return bool(
            actual_evidence and set(getattr(fact, "evidence_ids", ())).issubset(actual_evidence)
        )


def _claim_predicate(claim: Any) -> ClaimPredicate | None:
    value = getattr(claim, "predicate", None)
    try:
        if isinstance(value, ClaimPredicate):
            return value
        if isinstance(value, str):
            return ClaimPredicate(value)
        return None
    except (TypeError, ValueError):
        return None


def _find(records: Iterable[Any], field_name: str, value: str) -> Any | None:
    return next((record for record in records if getattr(record, field_name, None) == value), None)


def _fact_evidence_is_claimed(fact: Any, claim_evidence: Sequence[str]) -> bool:
    fact_evidence = tuple(getattr(fact, "evidence_ids", ()))
    return bool(fact_evidence) and set(fact_evidence) == set(claim_evidence)


def _fact_object_identity(fact: Any) -> tuple[str, str] | None:
    """Return the metadata-object type/name required for scalar typed facts."""

    if isinstance(fact, ApiSuccessFact):
        return "AuditMetadata", fact.audit_id
    if isinstance(fact, ForbiddenProbeFact):
        return "ProbeResult", fact.probe_id
    if isinstance(fact, BusinessInvariantFact):
        return "BusinessInvariantResult", fact.result_id
    if isinstance(fact, SnapshotScopeFact):
        return "SnapshotScope", fact.scope_id
    return None


def analyze_rbac(
    snapshot: RbacSnapshotRecord,
    subject: ServiceAccountRef | SubjectRecord | str,
    **kwargs: Any,
) -> AnalysisResult:
    return RbacAnalyzer().analyze(snapshot, subject, **kwargs)


def verify_claim(claim: TypedClaim, context: ClaimContext) -> ClaimVerification:
    return ClaimVerifier(context).verify(claim)


def verify_typed_claim(claim: TypedClaim, context: ClaimContext) -> ClaimVerification:
    return verify_claim(claim, context)


# Short aliases make the records convenient in fixture tests while retaining
# descriptive names for callers that prefer explicit provenance terminology.
type RuleRecord = RbacRuleRecord
type RoleRule = RbacRuleRecord
type Rule = RbacRuleRecord
type Role = RoleRecord
type ClusterRole = ClusterRoleRecord
type RoleBinding = RoleBindingRecord
type ClusterRoleBinding = ClusterRoleBindingRecord
type RbacSnapshot = RbacSnapshotRecord
type Snapshot = RbacSnapshotRecord
type ServiceAccount = ServiceAccountRef
type Subject = SubjectRecord
type SubjectRef = SubjectRecord
type Permission = EffectivePermission
type PermissionQuery = PermissionRequest
type Grant = MatchingGrant
type AlternativePath = AlternativePathFinding


__all__ = [
    "AnalysisResult",
    "AnalysisStatus",
    "AlternativePath",
    "AlternativePathFinding",
    "ApiSuccessFact",
    "BindingReferenceFact",
    "BusinessInvariantFact",
    "ClaimContext",
    "ClaimVerification",
    "ClaimVerifier",
    "ClusterRole",
    "ClusterRoleBinding",
    "ClusterRoleBindingRecord",
    "ClusterRoleRecord",
    "Completeness",
    "EffectivePermission",
    "EvidenceRef",
    "ForbiddenProbeFact",
    "Grant",
    "MatchingGrant",
    "Permission",
    "PermissionRequest",
    "ReasonCode",
    "RbacAnalyzer",
    "RbacRuleRecord",
    "RbacSnapshot",
    "RbacSnapshotRecord",
    "Role",
    "RoleBinding",
    "RoleBindingRecord",
    "RoleRecord",
    "RoleRuleFact",
    "RoleRule",
    "Rule",
    "RuleRecord",
    "Snapshot",
    "ServiceAccount",
    "ServiceAccountRef",
    "SnapshotObjectRecord",
    "SnapshotScopeFact",
    "Subject",
    "SubjectRef",
    "SubjectRecord",
    "SourceObjectFact",
    "PermissionQuery",
    "analyze_rbac",
    "verify_claim",
    "verify_typed_claim",
]
