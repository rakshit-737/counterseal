"""Local development control-plane API. Investigations remain unsupported."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Header, Query, Response

from .contracts import (
    CaseCreate,
    CaseList,
    CaseResponse,
    ClaimRequest,
    ClaimResponse,
    CompleteRequest,
    HeartbeatRequest,
    IdempotencyKey,
    InvestigationCreate,
    JobResponse,
    LeasedJobResponse,
    MeResponse,
    TimelineResponse,
)
from .db.models import Case, Job
from .db.repositories import ControlPlaneRepository
from .dependencies import Analyst, Authenticated, DatabaseSession, Reader, Worker
from .errors import APIError

router = APIRouter(prefix="/v1")


@router.get("/me", response_model=MeResponse)
def me(principal: Authenticated) -> MeResponse:
    return MeResponse(subject=principal.subject, role=principal.role)


@router.get("/cases", response_model=CaseList)
def list_cases(
    principal: Reader,
    session: DatabaseSession,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> CaseList:
    return CaseList(items=ControlPlaneRepository(session).list_cases(limit=limit, offset=offset))


@router.post("/cases", status_code=201, response_model=CaseResponse)
def create_case(body: CaseCreate, principal: Analyst, session: DatabaseSession) -> Case:
    case = ControlPlaneRepository(session).create_case(
        title=body.title,
        description=body.description,
        principal=principal,
    )
    session.commit()
    return case


@router.get("/cases/{case_id}", response_model=CaseResponse)
def get_case(case_id: UUID, principal: Reader, session: DatabaseSession) -> Case:
    return ControlPlaneRepository(session).get_case(str(case_id))


@router.post("/cases/{case_id}/investigations", status_code=202, response_model=JobResponse)
def investigate(
    case_id: UUID,
    principal: Analyst,
    session: DatabaseSession,
    response: Response,
    body: InvestigationCreate | None = None,
    idempotency_key: Annotated[IdempotencyKey | None, Header(alias="Idempotency-Key")] = None,
) -> Job:
    body_key = body.idempotency_key if body else None
    if idempotency_key and body_key and idempotency_key != body_key:
        raise APIError(
            422, "IDEMPOTENCY_KEY_MISMATCH", "Header and body idempotency keys must match."
        )
    key = idempotency_key or body_key
    if key is None:
        raise APIError(
            422,
            "IDEMPOTENCY_KEY_REQUIRED",
            "An Idempotency-Key header or idempotency_key is required.",
        )
    job, created = ControlPlaneRepository(session).investigate(
        str(case_id),
        principal=principal,
        idempotency_key=key,
    )
    session.commit()
    response.headers["Idempotency-Replayed"] = "false" if created else "true"
    return job


@router.get("/cases/{case_id}/timeline", response_model=TimelineResponse)
def timeline(
    case_id: UUID,
    principal: Reader,
    session: DatabaseSession,
    after: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> TimelineResponse:
    return TimelineResponse(
        items=ControlPlaneRepository(session).timeline(str(case_id), after=after, limit=limit)
    )


@router.post("/workers/jobs/claim", response_model=ClaimResponse)
def claim(
    principal: Worker, session: DatabaseSession, body: ClaimRequest | None = None
) -> ClaimResponse:
    body = body or ClaimRequest()
    job = ControlPlaneRepository(session).claim(
        principal=principal, lease_seconds=body.lease_seconds
    )
    session.commit()
    return ClaimResponse(job=job)


@router.post("/workers/jobs/{job_id}/heartbeat", response_model=LeasedJobResponse)
def heartbeat(
    job_id: UUID, body: HeartbeatRequest, principal: Worker, session: DatabaseSession
) -> Job:
    job = ControlPlaneRepository(session).heartbeat(
        str(job_id),
        principal=principal,
        lease_id=str(body.lease_id),
        lease_seconds=body.lease_seconds,
    )
    session.commit()
    return job


@router.post("/workers/jobs/{job_id}/complete", response_model=JobResponse)
def complete(
    job_id: UUID, body: CompleteRequest, principal: Worker, session: DatabaseSession
) -> Job:
    job = ControlPlaneRepository(session).complete(
        str(job_id), principal=principal, lease_id=str(body.lease_id)
    )
    session.commit()
    return job
