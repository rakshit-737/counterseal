"""Closed vocabularies; workflow position is not public assurance or authority."""

from enum import StrEnum


class CountersealState(StrEnum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    NEEDS_EVIDENCE = "NEEDS_EVIDENCE"
    UNSUPPORTED = "UNSUPPORTED"
    BASELINING = "BASELINING"
    EVALUATING = "EVALUATING"
    NO_SAFE_CANDIDATE = "NO_SAFE_CANDIDATE"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPLYING = "APPLYING"
    POSTCHECK = "POSTCHECK"
    MITIGATED_SCOPED = "MITIGATED_SCOPED"
    ESCALATED = "ESCALATED"
    INCONCLUSIVE = "INCONCLUSIVE"
    STALE = "STALE"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class CountersealStatus(StrEnum):
    OBSERVED = "OBSERVED"
    DERIVED = "DERIVED"
    BASELINE_REPRODUCED = "BASELINE_REPRODUCED"
    FIXTURE_VALIDATED = "FIXTURE_VALIDATED"
    CANDIDATE_ONLY = "CANDIDATE_ONLY"
    LAB_APPROVED = "LAB_APPROVED"
    APPLIED_LOCAL = "APPLIED_LOCAL"
    INCONCLUSIVE = "INCONCLUSIVE"
    STALE = "STALE"
    UNSUPPORTED = "UNSUPPORTED"


class SourceKind(StrEnum):
    LOCAL_KIND = "local_kind"
    SNAPSHOT_BUNDLE = "snapshot_bundle"


class RunnerTrust(StrEnum):
    UNVERIFIED = "unverified"
    ATTESTED_LOCAL = "attested_local"


class EvidenceKind(StrEnum):
    AUDIT_METADATA = "audit_metadata"
    RBAC_SNAPSHOT = "rbac_snapshot"
    PROBE_RESULT = "probe_result"
    BUSINESS_TEST = "business_test"


class GraphNodeType(StrEnum):
    SUBJECT = "subject"
    ROLE = "role"
    BINDING = "binding"
    RESOURCE = "resource"
    OPERATION = "operation"


class GraphEdgeType(StrEnum):
    BINDS_SUBJECT = "binds_subject"
    REFERENCES_ROLE = "references_role"
    CONTAINS_RULE = "contains_rule"
    OBSERVED_ACCESS = "observed_access"


class ClaimPredicate(StrEnum):
    OBSERVED_API_SUCCESS = "observed_api_success"
    BINDING_REFERENCES_ROLE = "binding_references_role"
    ROLE_CONTAINS_RULE = "role_contains_rule"
    PROBE_RETURNED_FORBIDDEN = "probe_returned_forbidden"
    BUSINESS_INVARIANT_PASSED = "business_invariant_passed"
    SNAPSHOT_COMPLETE_FOR_SCOPE = "snapshot_complete_for_scope"
    SOURCE_OBJECT_MATCHES = "source_object_matches"


class TransformationType(StrEnum):
    REMOVE_SECRET_ACCESS = "remove_secret_access"
    REMOVE_SECRET_LIST_WATCH = "remove_secret_list_watch"
    RESTRICT_NAMED_SECRET_ACCESS = "restrict_named_secret_access"


class ProbeKind(StrEnum):
    SECRET_ACCESS = "secret_access"
    BUSINESS_INVARIANT = "business_invariant"
    CONTROL = "control"


class ProbePhase(StrEnum):
    BASELINE = "BASELINE"
    CANDIDATE = "CANDIDATE"
    POSTCHECK = "POSTCHECK"


class ProbeStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNSUPPORTED = "UNSUPPORTED"


class RehearsalDecision(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    ABSTAIN = "ABSTAIN"


class ApprovalDecision(StrEnum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class ExecutionOutcome(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    ABORTED = "ABORTED"


class RbacResourceKind(StrEnum):
    ROLE = "Role"
    CLUSTER_ROLE = "ClusterRole"
    ROLE_BINDING = "RoleBinding"
    CLUSTER_ROLE_BINDING = "ClusterRoleBinding"
    SERVICE_ACCOUNT = "ServiceAccount"


class RbacSubjectKind(StrEnum):
    SERVICE_ACCOUNT = "ServiceAccount"
    USER = "User"
    GROUP = "Group"


class AuditStage(StrEnum):
    REQUEST_RECEIVED = "RequestReceived"
    RESPONSE_STARTED = "ResponseStarted"
    RESPONSE_COMPLETE = "ResponseComplete"
    PANIC = "Panic"
