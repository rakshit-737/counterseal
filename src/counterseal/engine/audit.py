"""Deterministic offline audit metadata; parsing is not source authentication.

The input is an already-decoded, bounded metadata Mapping, never JSON text or
an arbitrary audit body. Unknown keys and body-bearing records are rejected
without reading their values. No logger, network client or model is involved.

Frozen engine records preserve names, groups, subresources, timestamps and
incomplete responses alongside explicit reason codes. Core Secret and ConfigMap
reads share the domain's contract vocabulary; other resources remain unsupported.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import cast

from counterseal.domain import (
    AuditStage,
    CountersealStatus,
    RbacPermission,
    RbacSubject,
    RbacSubjectKind,
    WorkloadContract,
)

MAX_RECORDS = 1024
MAX_MAPPING_ITEMS = 24
MAX_GROUPS = 64


class AuditReasonCode(StrEnum):
    NORMALIZED = "NORMALIZED"
    NOT_MAPPING = "NOT_MAPPING"
    MALFORMED_FIELD = "MALFORMED_FIELD"
    MISSING_FIELD = "MISSING_FIELD"
    UNKNOWN_FIELD = "UNKNOWN_FIELD"
    OVERSIZED_INPUT = "OVERSIZED_INPUT"
    SENSITIVE_PAYLOAD = "SENSITIVE_PAYLOAD"
    INVALID_STAGE = "INVALID_STAGE"
    INVALID_TIMESTAMP = "INVALID_TIMESTAMP"
    INCOMPLETE_TIMESTAMP = "INCOMPLETE_TIMESTAMP"
    CONFLICTING_TIMESTAMPS = "CONFLICTING_TIMESTAMPS"
    INVALID_RESPONSE_CODE = "INVALID_RESPONSE_CODE"
    INVALID_SUBJECT = "INVALID_SUBJECT"
    INVALID_GROUPS = "INVALID_GROUPS"
    INVALID_CONTRACT = "INVALID_CONTRACT"
    INVALID_NORMALIZED_EVENT = "INVALID_NORMALIZED_EVENT"
    DUPLICATE_CONFLICT = "DUPLICATE_CONFLICT"
    CONFLICTING_STAGES = "CONFLICTING_STAGES"
    UNSUPPORTED_LEVEL = "UNSUPPORTED_LEVEL"
    UNSUPPORTED_VERB = "UNSUPPORTED_VERB"
    UNSUPPORTED_RESOURCE = "UNSUPPORTED_RESOURCE"
    UNSUPPORTED_API_GROUP = "UNSUPPORTED_API_GROUP"
    UNSUPPORTED_SUBRESOURCE = "UNSUPPORTED_SUBRESOURCE"
    UNSUPPORTED_IMPERSONATION = "UNSUPPORTED_IMPERSONATION"
    MISSING_NAMESPACE = "MISSING_NAMESPACE"
    MISSING_RESOURCE_NAME = "MISSING_RESOURCE_NAME"
    NO_RESPONSE_OBSERVED = "NO_RESPONSE_OBSERVED"
    PANIC_STAGE = "PANIC_STAGE"
    NOT_SUCCESSFUL = "NOT_SUCCESSFUL"
    SUBJECT_MISMATCH = "SUBJECT_MISMATCH"
    CONTRACT_NOT_ACTIVE = "CONTRACT_NOT_ACTIVE"
    ALLOWED_OPERATION = "ALLOWED_OPERATION"
    OPERATION_NOT_REQUIRED = "OPERATION_NOT_REQUIRED"


class AuditNormalizationError(ValueError):
    """Only a reason and a fixed schema path; never a rejected value/key."""

    def __init__(self, reason_code: AuditReasonCode, *, path: str = "event") -> None:
        self.reason_code = reason_code
        self.path = path
        super().__init__(f"{reason_code.value}: {path}")


class ContractFindingDisposition(StrEnum):
    ALLOWED = "ALLOWED"
    VIOLATION = "VIOLATION"
    IGNORED = "IGNORED"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNSUPPORTED = "UNSUPPORTED"
    STALE = "STALE"


@dataclass(frozen=True, slots=True)
class AuditEventReference:
    source_id: str
    audit_id: str
    stage: AuditStage

    @property
    def key(self) -> tuple[str, str, AuditStage]:
        return self.source_id, self.audit_id, self.stage


@dataclass(frozen=True, slots=True)
class NormalizedAuditEvent:
    source_id: str
    audit_id: str
    stage: AuditStage
    username: str
    groups: tuple[str, ...]
    subject: RbacSubject
    verb: str
    namespace: str | None
    api_group: str
    resource: str
    subresource: str
    resource_name: str | None
    response_code: int | None
    occurred_at: datetime
    request_received_at: datetime | None
    level: str
    status: CountersealStatus
    reason_code: AuditReasonCode

    @property
    def reference(self) -> AuditEventReference:
        return AuditEventReference(self.source_id, self.audit_id, self.stage)

    @property
    def supported(self) -> bool:
        return self.status is CountersealStatus.OBSERVED

    @property
    def successful(self) -> bool:
        return (
            self.supported
            and self.stage in (AuditStage.RESPONSE_STARTED, AuditStage.RESPONSE_COMPLETE)
            and self.response_code is not None
            and 200 <= self.response_code < 300
        )

    @property
    def effective_groups(self) -> tuple[str, ...]:
        """Declared groups plus Kubernetes' intrinsic ServiceAccount groups."""
        groups = set(self.groups)
        if self.subject.kind is RbacSubjectKind.SERVICE_ACCOUNT:
            groups.update(
                (
                    "system:authenticated",
                    "system:serviceaccounts",
                    f"system:serviceaccounts:{self.subject.namespace}",
                )
            )
        return tuple(sorted(groups))


@dataclass(frozen=True, slots=True)
class AuditEventGroup:
    source_id: str
    audit_id: str
    events: tuple[NormalizedAuditEvent, ...]
    reason_code: AuditReasonCode

    @property
    def event_references(self) -> tuple[AuditEventReference, ...]:
        return tuple(event.reference for event in self.events)

    @property
    def terminal_event(self) -> NormalizedAuditEvent:
        # Events are ordered by stage, not arrival order or an attacker's last
        # timestamp. Conflicting stage times are separately marked inconclusive.
        return self.events[-1]


@dataclass(frozen=True, slots=True)
class AuditNormalizationResult:
    events: tuple[NormalizedAuditEvent, ...]
    groups: tuple[AuditEventGroup, ...]
    reason_code: AuditReasonCode = AuditReasonCode.NORMALIZED

    def __iter__(self) -> Iterator[NormalizedAuditEvent]:
        return iter(self.events)


@dataclass(frozen=True, slots=True)
class WorkloadContractFinding:
    contract_id: str
    contract_digest: str
    disposition: ContractFindingDisposition
    reason_code: AuditReasonCode
    event: NormalizedAuditEvent
    event_references: tuple[AuditEventReference, ...]

    @property
    def status(self) -> CountersealStatus:
        return {
            ContractFindingDisposition.ALLOWED: CountersealStatus.DERIVED,
            ContractFindingDisposition.VIOLATION: CountersealStatus.DERIVED,
            ContractFindingDisposition.IGNORED: CountersealStatus.OBSERVED,
            ContractFindingDisposition.INCONCLUSIVE: CountersealStatus.INCONCLUSIVE,
            ContractFindingDisposition.UNSUPPORTED: CountersealStatus.UNSUPPORTED,
            ContractFindingDisposition.STALE: CountersealStatus.STALE,
        }[self.disposition]


@dataclass(frozen=True, slots=True)
class ContractAuditResult:
    findings: tuple[WorkloadContractFinding, ...]

    @property
    def violations(self) -> tuple[WorkloadContractFinding, ...]:
        return tuple(
            f for f in self.findings if f.disposition is ContractFindingDisposition.VIOLATION
        )

    @property
    def allowed(self) -> tuple[WorkloadContractFinding, ...]:
        return tuple(
            f for f in self.findings if f.disposition is ContractFindingDisposition.ALLOWED
        )

    @property
    def unsupported(self) -> tuple[WorkloadContractFinding, ...]:
        return tuple(
            f for f in self.findings if f.disposition is ContractFindingDisposition.UNSUPPORTED
        )


_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]*")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")
_TOKEN = re.compile(r"[a-z][a-z0-9]*")
_RFC3339 = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})",
    re.ASCII,
)
_SA_PREFIX = "system:serviceaccount:"
_READ_VERBS = frozenset({"get", "list", "watch"})
_RESOURCES = frozenset({"secrets", "configmaps"})
_STAGE_ORDER = {stage: index for index, stage in enumerate(AuditStage)}
_ROOT_KEYS = frozenset(
    {
        "apiVersion",
        "kind",
        "level",
        "auditID",
        "stage",
        "requestURI",
        "user",
        "verb",
        "sourceIPs",
        "userAgent",
        "objectRef",
        "responseStatus",
        "stageTimestamp",
        "requestReceivedTimestamp",
        "timestamp",
        "annotations",
        "impersonatedUser",
    }
)
_SENSITIVE_KEYS = frozenset(
    {
        "requestObject",
        "responseObject",
        "requestBody",
        "responseBody",
        "request_body",
        "response_body",
        "authorization",
        "Authorization",
        "token",
        "bearerToken",
        "accessToken",
        "refreshToken",
        "password",
        "secret",
        "credential",
        "credentials",
        "cookie",
        "set-cookie",
        "headers",
        "data",
        "stringData",
        "raw",
        "payload",
    }
)
_CREDENTIAL_TEXT = re.compile(
    r"(?:\bbearer\s+[A-Za-z0-9._~+/=-]{8,}|(?:access[_-]?token|refresh[_-]?token|authorization|password|secret|credential|api[_-]?key)\s*[:=])",
    re.IGNORECASE,
)
_JWT_TEXT = re.compile(
    r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"
)


def _error(code: AuditReasonCode, path: str) -> AuditNormalizationError:
    return AuditNormalizationError(code, path=path)


def _mapping(value: object, keys: frozenset[str], path: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise _error(AuditReasonCode.NOT_MAPPING, path)
    size = len(value)
    if size > MAX_MAPPING_ITEMS:
        raise _error(AuditReasonCode.OVERSIZED_INPUT, path)
    seen: set[str] = set()
    # Do not call items(), values(), repr(), JSON encoding or a generic recursive
    # walker here: any of those could read or retain a body/token value.
    for index, key in enumerate(value):
        if index >= size:
            raise _error(AuditReasonCode.OVERSIZED_INPUT, path)
        if type(key) is not str or key in seen:
            raise _error(AuditReasonCode.MALFORMED_FIELD, path)
        if len(key) > 64:
            raise _error(AuditReasonCode.OVERSIZED_INPUT, path)
        seen.add(key)
    if len(seen) != size:
        raise _error(AuditReasonCode.MALFORMED_FIELD, path)
    if seen & _SENSITIVE_KEYS:
        raise _error(AuditReasonCode.SENSITIVE_PAYLOAD, path)
    if seen - keys:
        raise _error(AuditReasonCode.UNKNOWN_FIELD, path)
    return cast(Mapping[str, object], value)


def _discard_projection(
    value: object, path: str, *, depth: int = 0, budget: list[int] | None = None
) -> None:
    """Bound and inspect a known irrelevant field without retaining it."""

    if budget is None:
        budget = [256, 16384]
    budget[0] -= 1
    if depth > 3 or budget[0] < 0:
        raise _error(AuditReasonCode.OVERSIZED_INPUT, path)
    if value is None or type(value) in (bool, int, float):
        return
    if type(value) is str:
        budget[1] -= len(value)
        if len(value) > 4096 or budget[1] < 0:
            raise _error(AuditReasonCode.OVERSIZED_INPUT, path)
        if _CREDENTIAL_TEXT.search(value) or _JWT_TEXT.search(value):
            raise _error(AuditReasonCode.SENSITIVE_PAYLOAD, path)
        return
    if type(value) in (list, tuple):
        sequence = cast(list[object] | tuple[object, ...], value)
        if len(sequence) > MAX_GROUPS:
            raise _error(AuditReasonCode.OVERSIZED_INPUT, path)
        for index, item in enumerate(sequence):
            _discard_projection(item, f"{path}[{index}]", depth=depth + 1, budget=budget)
        return
    if isinstance(value, Mapping):
        if len(value) > MAX_MAPPING_ITEMS:
            raise _error(AuditReasonCode.OVERSIZED_INPUT, path)
        size = len(value)
        for index, key in enumerate(value):
            if index >= size:
                raise _error(AuditReasonCode.OVERSIZED_INPUT, path)
            if type(key) is not str:
                raise _error(AuditReasonCode.MALFORMED_FIELD, path)
            budget[1] -= len(key)
            if len(key) > 253 or budget[1] < 0:
                raise _error(AuditReasonCode.OVERSIZED_INPUT, path)
            if key.lower() in {k.lower() for k in _SENSITIVE_KEYS} or _CREDENTIAL_TEXT.search(key):
                raise _error(AuditReasonCode.SENSITIVE_PAYLOAD, path)
            _discard_projection(value[key], f"{path}.*", depth=depth + 1, budget=budget)
        return
    raise _error(AuditReasonCode.MALFORMED_FIELD, path)


def _discard_text(value: object, path: str) -> None:
    if type(value) is not str:
        raise _error(AuditReasonCode.MALFORMED_FIELD, path)
    _discard_projection(value, path)


def _discard_strings(value: object, path: str) -> None:
    if type(value) not in (list, tuple):
        raise _error(AuditReasonCode.MALFORMED_FIELD, path)
    sequence = cast(list[object] | tuple[object, ...], value)
    if len(sequence) > MAX_GROUPS:
        raise _error(AuditReasonCode.OVERSIZED_INPUT, path)
    if any(type(item) is not str for item in sequence):
        raise _error(AuditReasonCode.MALFORMED_FIELD, path)
    _discard_projection(value, path)


def _discard_fields(value: object, path: str, *, extra: bool = False) -> None:
    if not isinstance(value, Mapping):
        raise _error(AuditReasonCode.NOT_MAPPING, path)
    _discard_projection(value, path)
    for key in value:
        if extra:
            _discard_strings(value[key], path)
        else:
            _discard_text(value[key], path)


def _discard_user_projection(value: object, path: str) -> None:
    """Validate a standard user-shaped projection, retaining no fields."""

    mapping = _mapping(value, frozenset({"username", "groups", "uid", "extra"}), path)
    if "username" in mapping:
        _discard_text(mapping["username"], f"{path}.username")
    if "groups" in mapping:
        _discard_strings(mapping["groups"], f"{path}.groups")
    if "uid" in mapping:
        _discard_text(mapping["uid"], f"{path}.uid")
    if "extra" in mapping:
        _discard_fields(mapping["extra"], f"{path}.extra", extra=True)


def _required(value: Mapping[str, object], key: str, path: str) -> object:
    if key not in value:
        raise _error(AuditReasonCode.MISSING_FIELD, path)
    return value[key]


def _text(value: object, path: str, maximum: int = 128, *, empty: bool = False) -> str:
    if type(value) is not str:
        raise _error(AuditReasonCode.MALFORMED_FIELD, path)
    if len(value) > maximum:
        raise _error(AuditReasonCode.OVERSIZED_INPUT, path)
    if (not value and not empty) or not value.isascii() or any(ord(c) < 32 for c in value):
        raise _error(AuditReasonCode.MALFORMED_FIELD, path)
    return value


def _identifier(value: object, path: str, maximum: int = 128) -> str:
    text = _text(value, path, maximum)
    if not _IDENTIFIER.fullmatch(text):
        raise _error(AuditReasonCode.MALFORMED_FIELD, path)
    return text


def _dns_name(value: object, path: str, *, namespace: bool = False) -> str:
    text = _text(value, path, 63 if namespace else 253)
    labels = (text,) if namespace else text.split(".")
    if any(len(label) > 63 or not _LABEL.fullmatch(label) for label in labels):
        raise _error(AuditReasonCode.MALFORMED_FIELD, path)
    return text


def _timestamp(value: object, path: str) -> datetime:
    parsed: datetime | None = None
    if type(value) is datetime:
        parsed = value
    elif type(value) is str:
        if len(value) > 40:
            raise _error(AuditReasonCode.OVERSIZED_INPUT, path)
        if not _RFC3339.fullmatch(value) or value.endswith("-00:00"):
            raise _error(AuditReasonCode.INCOMPLETE_TIMESTAMP, path)
        if not value.endswith("Z") and (int(value[-5:-3]) > 23 or int(value[-2:]) > 59):
            raise _error(AuditReasonCode.INVALID_TIMESTAMP, path)
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
    else:
        raise _error(AuditReasonCode.INVALID_TIMESTAMP, path)
    # Raise outside the except block: no rejected values in chained errors.
    if parsed is None:
        raise _error(AuditReasonCode.INVALID_TIMESTAMP, path)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise _error(AuditReasonCode.INCOMPLETE_TIMESTAMP, path)
    converted: datetime | None = None
    try:
        converted = parsed.astimezone(UTC)
    except (ValueError, OverflowError):
        pass
    if converted is None:
        raise _error(AuditReasonCode.INVALID_TIMESTAMP, path)
    return converted


def _groups(value: object, path: str) -> tuple[str, ...]:
    if type(value) not in (list, tuple):
        raise _error(AuditReasonCode.INVALID_GROUPS, path)
    sequence = cast(list[object] | tuple[object, ...], value)
    if len(sequence) > MAX_GROUPS:
        raise _error(AuditReasonCode.OVERSIZED_INPUT, path)
    result: set[str] = set()
    for index, group in enumerate(sequence):
        item = _identifier(group, f"{path}[{index}]", 128)
        if _CREDENTIAL_TEXT.search(item) or _JWT_TEXT.search(item):
            raise _error(AuditReasonCode.SENSITIVE_PAYLOAD, path)
        result.add(item)
    return tuple(sorted(result))


def _subject(user: object) -> tuple[str, tuple[str, ...], RbacSubject]:
    mapping = _mapping(user, frozenset({"username", "groups", "uid", "extra"}), "user")
    # ``uid`` and ``extra`` are standard audit identity metadata. They are
    # deliberately bounded and discarded before this strict identity
    # projection is retained.
    if "uid" in mapping:
        _discard_text(mapping["uid"], "user.uid")
    if "extra" in mapping:
        _discard_fields(mapping["extra"], "user.extra", extra=True)
    username = _identifier(_required(mapping, "username", "user.username"), "user.username")
    if _CREDENTIAL_TEXT.search(username) or _JWT_TEXT.search(username):
        raise _error(AuditReasonCode.SENSITIVE_PAYLOAD, "user.username")
    groups = _groups(_required(mapping, "groups", "user.groups"), "user.groups")
    if "system:authenticated" in groups and "system:unauthenticated" in groups:
        raise _error(AuditReasonCode.INVALID_GROUPS, "user.groups")
    if username == "system:serviceaccount":
        raise _error(AuditReasonCode.INVALID_SUBJECT, "user.username")
    if username.startswith(_SA_PREFIX):
        components = username.split(":")
        if len(components) != 4 or components[:2] != ["system", "serviceaccount"]:
            raise _error(AuditReasonCode.INVALID_SUBJECT, "user.username")
        namespace = _dns_name(components[2], "user.username", namespace=True)
        name = _dns_name(components[3], "user.username")
        subject = RbacSubject(
            kind=RbacSubjectKind.SERVICE_ACCOUNT,
            namespace=namespace,
            name=name,
        )
        # A namespace-qualified service-account group is meaningful only for
        # that account namespace. Rejecting a contradictory well-formed group
        # avoids silently treating untrusted metadata as a membership proof.
        qualified = tuple(group for group in groups if group.startswith("system:serviceaccounts:"))
        if qualified and qualified != (f"system:serviceaccounts:{namespace}",):
            raise _error(AuditReasonCode.INVALID_GROUPS, "user.groups")
        if "system:unauthenticated" in groups:
            raise _error(AuditReasonCode.INVALID_GROUPS, "user.groups")
    else:
        subject = RbacSubject(kind=RbacSubjectKind.USER, name=username)
    return username, groups, subject


def _stage(raw: Mapping[str, object]) -> AuditStage:
    value = _text(_required(raw, "stage", "stage"), "stage", 32)
    result = None
    try:
        result = AuditStage(value)
    except ValueError:
        pass
    if result is None:
        raise _error(AuditReasonCode.INVALID_STAGE, "stage")
    return result


def _parse_object_ref(raw: object) -> tuple[str | None, str, str, str, str | None]:
    value = _mapping(
        raw,
        frozenset(
            {
                "apiVersion",
                "apiGroup",
                "resource",
                "subresource",
                "name",
                "namespace",
                "uid",
                "resourceVersion",
            }
        ),
        "objectRef",
    )
    for key in ("apiVersion", "uid", "resourceVersion"):
        if key in value:
            _discard_text(value[key], f"objectRef.{key}")
    api_group_raw = value.get("apiGroup", "")
    if type(api_group_raw) is not str:
        raise _error(AuditReasonCode.MALFORMED_FIELD, "objectRef.apiGroup")
    api_group = "" if api_group_raw == "" else _dns_name(api_group_raw, "objectRef.apiGroup")
    resource = _dns_name(
        _required(value, "resource", "objectRef.resource"),
        "objectRef.resource",
    )
    namespace = (
        _dns_name(value["namespace"], "objectRef.namespace", namespace=True)
        if "namespace" in value
        else None
    )
    subresource_raw = value.get("subresource", "")
    subresource = _text(subresource_raw, "objectRef.subresource", 63, empty=True)
    if subresource and not _TOKEN.fullmatch(subresource):
        raise _error(AuditReasonCode.MALFORMED_FIELD, "objectRef.subresource")
    resource_name = _dns_name(value["name"], "objectRef.name") if "name" in value else None
    return namespace, api_group, resource, subresource, resource_name


def _response_code(raw: object) -> int | None:
    value = _mapping(
        raw,
        frozenset({"code", "status", "reason", "message", "details"}),
        "responseStatus",
    )
    for key in ("status", "reason", "message"):
        if key in value:
            _discard_text(value[key], f"responseStatus.{key}")
    if "details" in value:
        _discard_status_details(value["details"])
    if "code" not in value:
        return None
    code = value["code"]
    if type(code) is not int or not 100 <= code <= 599:
        raise _error(AuditReasonCode.INVALID_RESPONSE_CODE, "responseStatus.code")
    return code


def _discard_status_details(raw: object) -> None:
    path = "responseStatus.details"
    details = _mapping(
        raw, frozenset({"name", "group", "kind", "uid", "causes", "retryAfterSeconds"}), path
    )
    for key in ("name", "group", "kind", "uid"):
        if key in details:
            _discard_text(details[key], f"{path}.{key}")
    if "retryAfterSeconds" in details:
        seconds = details["retryAfterSeconds"]
        if type(seconds) is not int or not 0 <= seconds < 2**31:
            raise _error(AuditReasonCode.MALFORMED_FIELD, path)
    if "causes" in details:
        causes = details["causes"]
        if type(causes) not in (list, tuple):
            raise _error(AuditReasonCode.MALFORMED_FIELD, path)
        sequence = cast(list[object] | tuple[object, ...], causes)
        if len(sequence) > MAX_GROUPS:
            raise _error(AuditReasonCode.OVERSIZED_INPUT, path)
        budget = [256, 16384]
        for cause in sequence:
            mapping = _mapping(cause, frozenset({"reason", "message", "field"}), f"{path}.causes")
            _discard_projection(mapping, f"{path}.causes", budget=budget)
            for key in mapping:
                _discard_text(mapping[key], f"{path}.causes")


def _timestamps(raw: Mapping[str, object], stage: AuditStage) -> tuple[datetime, datetime | None]:
    parsed = {
        key: _timestamp(raw[key], key)
        for key in ("stageTimestamp", "timestamp", "requestReceivedTimestamp")
        if key in raw
    }
    request_at = parsed.get("requestReceivedTimestamp")
    occurred_at = parsed.get("stageTimestamp", parsed.get("timestamp"))
    if occurred_at is None and stage is AuditStage.REQUEST_RECEIVED:
        occurred_at = request_at
    if occurred_at is None:
        raise _error(AuditReasonCode.MISSING_FIELD, "stageTimestamp")
    if (
        ("timestamp" in parsed and parsed["timestamp"] != occurred_at)
        or (request_at is not None and request_at > occurred_at)
        or (stage is AuditStage.REQUEST_RECEIVED and request_at not in (None, occurred_at))
    ):
        raise _error(AuditReasonCode.CONFLICTING_TIMESTAMPS, "stageTimestamp")
    return occurred_at, request_at


def normalize_audit_event(
    raw: Mapping[str, object],
    *,
    source_id: str | None = None,
) -> NormalizedAuditEvent:
    """Normalize one bounded Kubernetes audit event.

    Only selected scalar metadata is copied. All body-bearing and unknown
    fields fail closed, and the exception contains only a reason code/path.
    Known operations outside the narrow Phase 2 read scope return an immutable
    ``UNSUPPORTED`` record; they are never reported as successful observations.
    """

    failure: AuditNormalizationError | None = None
    try:
        return _normalize_audit_event(raw, source_id=source_id)
    except AuditNormalizationError as exc:
        failure = AuditNormalizationError(exc.reason_code, path=exc.path)
    except Exception:
        # Mapping implementations and timezone objects can raise arbitrary
        # exceptions. Do not retain their message, cause, or a rejected value.
        failure = AuditNormalizationError(AuditReasonCode.MALFORMED_FIELD)
    raise failure


def _normalize_audit_event(
    raw: Mapping[str, object], *, source_id: str | None
) -> NormalizedAuditEvent:
    root = _mapping(raw, _ROOT_KEYS, "event")
    if source_id is None:
        raise _error(AuditReasonCode.MISSING_FIELD, "source_id")
    source = _identifier(source_id, "source_id")
    audit_id = _identifier(_required(root, "auditID", "auditID"), "auditID")
    stage = _stage(root)
    # Kubernetes audit metadata commonly carries these fields. They are
    # bounded and inspected for credential markers, then intentionally not
    # copied into the normalized record.
    for key in ("requestURI", "userAgent"):
        if key in root:
            _discard_text(root[key], key)
    if "sourceIPs" in root:
        _discard_strings(root["sourceIPs"], "sourceIPs")
    if "annotations" in root:
        _discard_fields(root["annotations"], "annotations")
    username, groups, subject = _subject(_required(root, "user", "user"))
    impersonated = "impersonatedUser" in root
    if impersonated:
        _discard_user_projection(root["impersonatedUser"], "impersonatedUser")
    verb_raw = _text(_required(root, "verb", "verb"), "verb", 32)
    if not _TOKEN.fullmatch(verb_raw):
        raise _error(AuditReasonCode.MALFORMED_FIELD, "verb")
    namespace, api_group, resource, subresource, resource_name = _parse_object_ref(
        _required(root, "objectRef", "objectRef")
    )
    response_code = _response_code(root["responseStatus"]) if "responseStatus" in root else None
    occurred_at, request_received_at = _timestamps(root, stage)
    level = _text(_required(root, "level", "level"), "level", 32)
    if level not in {"Metadata", "Request", "RequestResponse", "None"}:
        raise _error(AuditReasonCode.UNSUPPORTED_LEVEL, "level")
    # These are identity fields in the Kubernetes audit schema. If supplied,
    # accepting a different object would make the normalized reference
    # ambiguous, so validate the only versions/kind this adapter understands.
    if "apiVersion" in root and _text(root["apiVersion"], "apiVersion", 32) != "audit.k8s.io/v1":
        raise _error(AuditReasonCode.MALFORMED_FIELD, "apiVersion")
    if "kind" in root and _text(root["kind"], "kind", 32) != "Event":
        raise _error(AuditReasonCode.MALFORMED_FIELD, "kind")

    reason = AuditReasonCode.NORMALIZED
    supported = True
    if impersonated:
        reason = AuditReasonCode.UNSUPPORTED_IMPERSONATION
        supported = False
    elif stage is AuditStage.PANIC:
        reason = AuditReasonCode.PANIC_STAGE
        supported = False
    elif level != "Metadata":
        reason = AuditReasonCode.UNSUPPORTED_LEVEL
        supported = False
    elif verb_raw not in _READ_VERBS:
        reason = AuditReasonCode.UNSUPPORTED_VERB
        supported = False
    elif api_group != "":
        reason = AuditReasonCode.UNSUPPORTED_API_GROUP
        supported = False
    elif resource not in _RESOURCES:
        reason = AuditReasonCode.UNSUPPORTED_RESOURCE
        supported = False
    elif subresource:
        reason = AuditReasonCode.UNSUPPORTED_SUBRESOURCE
        supported = False
    elif namespace is None:
        reason = AuditReasonCode.MISSING_NAMESPACE
        supported = False

    status = CountersealStatus.OBSERVED if supported else CountersealStatus.UNSUPPORTED
    return NormalizedAuditEvent(
        source_id=source,
        audit_id=audit_id,
        stage=stage,
        username=username,
        groups=groups,
        subject=subject,
        verb=verb_raw,
        namespace=namespace,
        api_group=api_group,
        resource=resource,
        subresource=subresource,
        resource_name=resource_name,
        response_code=response_code,
        occurred_at=occurred_at,
        request_received_at=request_received_at,
        level=level,
        status=status,
        reason_code=reason,
    )


def _event_sort_key(event: NormalizedAuditEvent) -> tuple[str, str, int, datetime]:
    return event.source_id, event.audit_id, _STAGE_ORDER[event.stage], event.occurred_at


def _group_reason(events: Sequence[NormalizedAuditEvent]) -> AuditReasonCode:
    exact_fields = (
        "username",
        "groups",
        "level",
        "status",
        "reason_code",
        "verb",
        "namespace",
        "api_group",
        "resource",
        "subresource",
    )
    if any(len({getattr(event, field) for event in events}) > 1 for field in exact_fields):
        return AuditReasonCode.CONFLICTING_STAGES
    names = {event.resource_name for event in events if event.resource_name is not None}
    if len(names) > 1:
        return AuditReasonCode.CONFLICTING_STAGES
    times = [event.occurred_at for event in events]
    if times != sorted(times):
        return AuditReasonCode.CONFLICTING_STAGES
    request_times = {event.request_received_at for event in events if event.request_received_at}
    if len(request_times) > 1 or (
        request_times
        and events[0].stage is AuditStage.REQUEST_RECEIVED
        and events[0].occurred_at not in request_times
    ):
        return AuditReasonCode.CONFLICTING_STAGES
    codes = {
        event.response_code
        for event in events
        if event.stage in (AuditStage.RESPONSE_STARTED, AuditStage.RESPONSE_COMPLETE)
        and event.response_code is not None
    }
    if len(codes) > 1:
        return AuditReasonCode.CONFLICTING_STAGES
    return AuditReasonCode.NORMALIZED


def _group_events(events: Sequence[NormalizedAuditEvent]) -> AuditNormalizationResult:
    by_key: dict[tuple[str, str, AuditStage], NormalizedAuditEvent] = {}
    for event in events:
        key = event.reference.key
        prior = by_key.get(key)
        if prior is not None and prior != event:
            raise _error(AuditReasonCode.DUPLICATE_CONFLICT, "events")
        by_key[key] = event
    ordered = tuple(sorted(by_key.values(), key=_event_sort_key))
    grouped: dict[tuple[str, str], list[NormalizedAuditEvent]] = {}
    for event in ordered:
        grouped.setdefault((event.source_id, event.audit_id), []).append(event)
    groups = tuple(
        AuditEventGroup(source, audit_id, tuple(group), _group_reason(group))
        for (source, audit_id), group in sorted(grouped.items())
    )
    return AuditNormalizationResult(events=ordered, groups=groups)


def normalize_audit_records(
    records: Mapping[str, object] | Sequence[Mapping[str, object]],
    *,
    source_id: str | None = None,
) -> AuditNormalizationResult:
    """Normalize, deduplicate equal metadata projections and group audit stages.

    Accept one Mapping or an exact list/tuple of at most MAX_RECORDS Mappings;
    generators are deliberately not consumed. Irrelevant discarded metadata
    does not affect projection identity. A conflicting retained stage is an
    error, never a last-record-wins merge.
    """

    if source_id is None:
        raise _error(AuditReasonCode.MISSING_FIELD, "source_id")
    source_id = _identifier(source_id, "source_id")
    if isinstance(records, Mapping):
        items: tuple[Mapping[str, object], ...] = (records,)
    elif type(records) in (list, tuple):
        if len(records) > MAX_RECORDS:
            raise _error(AuditReasonCode.OVERSIZED_INPUT, "events")
        if any(not isinstance(item, Mapping) for item in records):
            raise _error(AuditReasonCode.NOT_MAPPING, "events")
        items = tuple(records)
    else:
        raise _error(AuditReasonCode.NOT_MAPPING, "events")

    return _group_events(tuple(normalize_audit_event(item, source_id=source_id) for item in items))


def normalize_audit_events(
    records: Mapping[str, object] | Sequence[Mapping[str, object]],
    *,
    source_id: str | None = None,
) -> AuditNormalizationResult:
    """Plural spelling retained as the primary batch adapter name."""

    return normalize_audit_records(records, source_id=source_id)


def _groups_from_events(
    value: AuditNormalizationResult | Sequence[NormalizedAuditEvent],
) -> tuple[AuditEventGroup, ...]:
    events: Sequence[NormalizedAuditEvent]
    if type(value) is AuditNormalizationResult:
        events = value.events
    elif type(value) in (list, tuple):
        events = cast(Sequence[NormalizedAuditEvent], value)
    else:
        raise _error(AuditReasonCode.INVALID_NORMALIZED_EVENT, "events")
    if type(events) not in (list, tuple):
        raise _error(AuditReasonCode.INVALID_NORMALIZED_EVENT, "events")
    if len(events) > MAX_RECORDS:
        raise _error(AuditReasonCode.OVERSIZED_INPUT, "events")
    return _group_events(tuple(_validate_event(event) for event in events)).groups


def _validate_event(event: NormalizedAuditEvent) -> NormalizedAuditEvent:
    """Frozen dataclasses can be directly constructed; do not trust status flags."""
    if (
        type(event) is not NormalizedAuditEvent
        or type(event.stage) is not AuditStage
        or type(event.groups) is not tuple
        or type(event.subject) is not RbacSubject
        or type(event.status) is not CountersealStatus
        or type(event.reason_code) is not AuditReasonCode
    ):
        raise _error(AuditReasonCode.INVALID_NORMALIZED_EVENT, "events")
    object_ref: dict[str, object] = {
        "apiGroup": event.api_group,
        "resource": event.resource,
        "subresource": event.subresource,
    }
    if event.namespace is not None:
        object_ref["namespace"] = event.namespace
    if event.resource_name is not None:
        object_ref["name"] = event.resource_name
    raw: dict[str, object] = {
        "auditID": event.audit_id,
        "stage": event.stage.value,
        "user": {"username": event.username, "groups": event.groups},
        "verb": event.verb,
        "objectRef": object_ref,
        "level": event.level,
        "stageTimestamp": event.occurred_at,
    }
    if event.response_code is not None:
        raw["responseStatus"] = {"code": event.response_code}
    if event.request_received_at is not None:
        raw["requestReceivedTimestamp"] = event.request_received_at
    if event.reason_code is AuditReasonCode.UNSUPPORTED_IMPERSONATION:
        raw["impersonatedUser"] = {}
    validated = normalize_audit_event(raw, source_id=event.source_id)
    if validated != event:
        raise _error(AuditReasonCode.INVALID_NORMALIZED_EVENT, "events")
    return validated


def _subject_matches(event: NormalizedAuditEvent, contract: WorkloadContract) -> bool:
    expected = contract.subject
    if expected.kind is RbacSubjectKind.SERVICE_ACCOUNT:
        return event.subject == expected
    if expected.kind is RbacSubjectKind.USER:
        return event.username == expected.name
    # A Group subject is matched only against declared or Kubernetes-defined
    # groups. It is never inferred from a free-form prompt-like string.
    return expected.name in event.effective_groups


def _permission_matches(event: NormalizedAuditEvent, permission: RbacPermission) -> bool:
    # WorkloadContract.required_operations is Pydantic-validated, but keep the
    # adapter structural and fail closed if a caller supplies a forged model.
    namespace = getattr(permission, "namespace", None)
    api_group = getattr(permission, "api_group", None)
    resource = getattr(permission, "resource", None)
    verb = getattr(permission, "verb", None)
    resource_name = getattr(permission, "resource_name", None)
    if (
        event.namespace != namespace
        or event.api_group != api_group
        or event.resource != resource
        or event.verb != verb
        or event.subresource
    ):
        return False
    if resource_name is not None and event.resource_name != resource_name:
        return False
    return True


def _finding(
    contract: WorkloadContract,
    disposition: ContractFindingDisposition,
    reason: AuditReasonCode,
    group: AuditEventGroup,
) -> WorkloadContractFinding:
    terminal = group.terminal_event
    return WorkloadContractFinding(
        contract_id=contract.contract_id,
        contract_digest=contract.digest,
        disposition=disposition,
        reason_code=reason,
        event=terminal,
        event_references=group.event_references,
    )


def detect_workload_contract_violations(
    events: AuditNormalizationResult | Sequence[NormalizedAuditEvent],
    contract: WorkloadContract,
) -> ContractAuditResult:
    """Return one immutable finding per deduplicated audit request group.

    A 2xx read is a violation unless the exact namespace, API group, resource,
    verb and (when the contract is named) resource name match a required
    operation. Missing names never satisfy a named operation. Unsupported
    levels/resources/verbs are explicit UNSUPPORTED findings, never passes.
    """

    if not isinstance(contract, WorkloadContract):
        raise _error(AuditReasonCode.INVALID_CONTRACT, "contract")
    groups = _groups_from_events(events)
    findings: list[WorkloadContractFinding] = []
    for group in groups:
        event = group.terminal_event
        if not _subject_matches(event, contract):
            findings.append(
                _finding(
                    contract,
                    ContractFindingDisposition.IGNORED,
                    AuditReasonCode.SUBJECT_MISMATCH,
                    group,
                )
            )
            continue
        if group.reason_code is not AuditReasonCode.NORMALIZED:
            findings.append(
                _finding(
                    contract,
                    ContractFindingDisposition.INCONCLUSIVE,
                    group.reason_code,
                    group,
                )
            )
            continue
        if not (contract.reviewed_at <= event.occurred_at < contract.expires_at):
            findings.append(
                _finding(
                    contract,
                    ContractFindingDisposition.STALE,
                    AuditReasonCode.CONTRACT_NOT_ACTIVE,
                    group,
                )
            )
            continue
        if not event.supported:
            findings.append(
                _finding(
                    contract,
                    ContractFindingDisposition.UNSUPPORTED,
                    event.reason_code,
                    group,
                )
            )
            continue
        if event.stage is AuditStage.REQUEST_RECEIVED:
            findings.append(
                _finding(
                    contract,
                    ContractFindingDisposition.IGNORED,
                    AuditReasonCode.NO_RESPONSE_OBSERVED,
                    group,
                )
            )
            continue
        if event.response_code is None or not 200 <= event.response_code < 300:
            findings.append(
                _finding(
                    contract,
                    ContractFindingDisposition.IGNORED,
                    AuditReasonCode.NOT_SUCCESSFUL,
                    group,
                )
            )
            continue

        matching = False
        named_without_name = False
        for permission in contract.required_operations:
            if (
                getattr(permission, "resource_name", None) is not None
                and event.resource_name is None
                and event.namespace == getattr(permission, "namespace", None)
                and event.api_group == getattr(permission, "api_group", None)
                and event.resource == getattr(permission, "resource", None)
                and event.verb == getattr(permission, "verb", None)
            ):
                named_without_name = True
            if _permission_matches(event, permission):
                matching = True
                break
        if matching:
            findings.append(
                _finding(
                    contract,
                    ContractFindingDisposition.ALLOWED,
                    AuditReasonCode.ALLOWED_OPERATION,
                    group,
                )
            )
        else:
            findings.append(
                _finding(
                    contract,
                    ContractFindingDisposition.VIOLATION,
                    AuditReasonCode.MISSING_RESOURCE_NAME
                    if named_without_name
                    else AuditReasonCode.OPERATION_NOT_REQUIRED,
                    group,
                )
            )
    return ContractAuditResult(findings=tuple(findings))


def detect_contract_violations(
    contract: WorkloadContract,
    events: AuditNormalizationResult | Sequence[NormalizedAuditEvent],
) -> ContractAuditResult:
    """Compatibility alias with contract-first argument order."""

    return detect_workload_contract_violations(events, contract)


# Concise adapter names for callers that treat this file as an engine port.
normalize_audit = normalize_audit_event
analyze_workload_contract = detect_workload_contract_violations


__all__ = [
    "AuditEventGroup",
    "AuditEventReference",
    "AuditNormalizationError",
    "AuditNormalizationResult",
    "AuditReasonCode",
    "ContractAuditResult",
    "ContractFindingDisposition",
    "NormalizedAuditEvent",
    "WorkloadContractFinding",
    "analyze_workload_contract",
    "detect_contract_violations",
    "detect_workload_contract_violations",
    "normalize_audit",
    "normalize_audit_event",
    "normalize_audit_events",
    "normalize_audit_records",
]
