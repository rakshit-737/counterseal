"""Closed control-plane contracts; these are not evidence or assurance claims."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from .auth import Role

SECURITY_ENGINE_NOT_IMPLEMENTED = "SECURITY_ENGINE_NOT_IMPLEMENTED"


class CaseState(StrEnum):
    NEEDS_EVIDENCE = "NEEDS_EVIDENCE"


class JobStatus(StrEnum):
    QUEUED = "QUEUED"
    LEASED = "LEASED"
    COMPLETED = "COMPLETED"


class AuditAction(StrEnum):
    CASE_CREATED = "CASE_CREATED"
    INVESTIGATION_REQUESTED = "INVESTIGATION_REQUESTED"
    JOB_CLAIMED = "JOB_CLAIMED"
    JOB_HEARTBEAT = "JOB_HEARTBEAT"
    JOB_COMPLETED = "JOB_COMPLETED"


class APIModel(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)


class MeResponse(APIModel):
    subject: str
    role: Role


class CaseCreate(APIModel):
    title: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)]
    description: Annotated[str, StringConstraints(strip_whitespace=True, max_length=8192)] = ""


class CaseResponse(APIModel):
    case_id: str
    title: str
    description: str
    state: CaseState
    reason: Literal["SECURITY_ENGINE_NOT_IMPLEMENTED"]
    created_by: str
    created_at: datetime
    updated_at: datetime


class CaseList(APIModel):
    items: list[CaseResponse]


IdempotencyKey = Annotated[
    str, StringConstraints(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
]


class InvestigationCreate(APIModel):
    idempotency_key: IdempotencyKey | None = None


class JobResponse(APIModel):
    job_id: str
    case_id: str
    kind: Literal["INVESTIGATION"]
    status: JobStatus
    reason: Literal["SECURITY_ENGINE_NOT_IMPLEMENTED"]
    requested_by: str
    created_at: datetime
    updated_at: datetime
    attempts: int
    lease_expires_at: datetime | None
    completed_at: datetime | None
    outcome: Literal["UNSUPPORTED"] | None


class LeasedJobResponse(JobResponse):
    lease_id: str


class ClaimResponse(APIModel):
    job: LeasedJobResponse | None


class ClaimRequest(APIModel):
    lease_seconds: int = Field(default=60, ge=1, le=300, strict=True)


class HeartbeatRequest(ClaimRequest):
    lease_id: UUID


class CompleteRequest(APIModel):
    lease_id: UUID


class AuditEventResponse(APIModel):
    sequence: int
    event_id: str
    case_id: str
    actor: str
    action: AuditAction
    occurred_at: datetime
    details: dict[str, str | int]


class TimelineResponse(APIModel):
    items: list[AuditEventResponse]
