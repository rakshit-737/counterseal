"""Transactional case/job operations with no security-engine implementation."""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import NoReturn
from uuid import uuid4

from sqlalchemy import and_, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from ..auth import AuthenticationError, IssuedToken, Principal, Role, TokenRecord, hash_token
from ..contracts import SECURITY_ENGINE_NOT_IMPLEMENTED, AuditAction, CaseState, JobStatus
from ..errors import APIError
from .models import AuditEvent, AuthToken, Case, Job, User


def utcnow() -> datetime:
    return datetime.now(UTC)


class TokenRepository:
    def __init__(self, session: Session, *, hash_secret: object | None = None) -> None:
        self.session = session
        self.hash_secret = hash_secret

    def issue(
        self, *, subject: str, role: Role, ttl: timedelta, now: datetime | None = None
    ) -> IssuedToken:
        """Return a clear token once; the caller commits before delivering it."""

        if not subject.strip() or subject != subject.strip() or len(subject) > 256:
            raise ValueError("subject must be nonblank and at most 256 characters")
        if ttl <= timedelta(0):
            raise ValueError("token lifetime must be positive")
        role = Role(role)
        now = now or utcnow()
        user = self.session.get(User, subject)
        if user is None:
            self.session.add(User(subject=subject, created_at=now))
            self.session.flush()
        elif user.disabled_at is not None:
            raise ValueError("identity is disabled")
        token = secrets.token_urlsafe(32)
        record = TokenRecord(
            token_hash=hash_token(token, secret=self.hash_secret),
            subject=subject,
            role=role,
            issued_at=now,
            expires_at=now + ttl,
        )
        self.session.add(
            AuthToken(
                token_id=str(uuid4()),
                token_hash=record.token_hash,
                subject=subject,
                role=role.value,
                issued_at=record.issued_at,
                expires_at=record.expires_at,
            )
        )
        self.session.flush()
        return IssuedToken(token=token, record=record)

    def authenticate(self, token: str, *, now: datetime | None = None) -> Principal:
        if not token or len(token) > 512:
            raise AuthenticationError("invalid bearer token")
        token_hash = hash_token(token, secret=self.hash_secret)
        record = self.session.scalar(
            select(AuthToken)
            .join(User, User.subject == AuthToken.subject)
            .where(
                AuthToken.token_hash == token_hash,
                AuthToken.revoked_at.is_(None),
                AuthToken.expires_at > (now or utcnow()),
                User.disabled_at.is_(None),
            )
        )
        if record is None:
            raise AuthenticationError("invalid bearer token")
        try:
            role = Role(record.role)
        except ValueError as exc:
            raise AuthenticationError("invalid bearer token") from exc
        return Principal(subject=record.subject, role=role, token_id=record.token_id)


class ControlPlaneRepository:
    """All mutations and their audit rows commit together in the caller session."""

    def __init__(self, session: Session):
        self.session = session

    def audit(
        self,
        case_id: str,
        principal: Principal,
        action: AuditAction,
        now: datetime,
        **details: str | int,
    ) -> None:
        self.session.add(
            AuditEvent(
                event_id=str(uuid4()),
                case_id=case_id,
                actor=principal.subject,
                action=action.value,
                occurred_at=now,
                details=details,
            )
        )

    def create_case(self, *, title: str, description: str, principal: Principal) -> Case:
        now = utcnow()
        case = Case(
            case_id=str(uuid4()),
            title=title,
            description=description,
            state=CaseState.NEEDS_EVIDENCE.value,
            reason=SECURITY_ENGINE_NOT_IMPLEMENTED,
            created_by=principal.subject,
            created_at=now,
            updated_at=now,
        )
        self.session.add(case)
        self.session.flush()
        self.audit(
            case.case_id,
            principal,
            AuditAction.CASE_CREATED,
            now,
            state=case.state,
            reason=case.reason,
        )
        return case

    def get_case(self, case_id: str) -> Case:
        case = self.session.get(Case, case_id)
        if case is None:
            raise APIError(404, "CASE_NOT_FOUND", "Case not found.")
        return case

    def list_cases(self, *, limit: int, offset: int) -> list[Case]:
        return list(
            self.session.scalars(
                select(Case)
                .order_by(Case.created_at.desc(), Case.case_id)
                .limit(limit)
                .offset(offset)
            )
        )

    def timeline(self, case_id: str, *, after: int, limit: int) -> list[AuditEvent]:
        self.get_case(case_id)
        return list(
            self.session.scalars(
                select(AuditEvent)
                .where(
                    AuditEvent.case_id == case_id,
                    AuditEvent.sequence > after,
                )
                .order_by(AuditEvent.sequence)
                .limit(limit)
            )
        )

    def investigate(
        self, case_id: str, *, principal: Principal, idempotency_key: str
    ) -> tuple[Job, bool]:
        self.get_case(case_id)
        key_hash = hashlib.sha256(idempotency_key.encode()).hexdigest()
        fingerprint = hashlib.sha256(f"INVESTIGATION:{case_id}".encode()).hexdigest()
        lookup = select(Job).where(
            Job.requested_by == principal.subject, Job.idempotency_key_hash == key_hash
        )
        existing = self.session.scalar(lookup)
        if existing is not None:
            return self._replay(existing, fingerprint), False
        now = utcnow()
        job = Job(
            job_id=str(uuid4()),
            case_id=case_id,
            kind="INVESTIGATION",
            status=JobStatus.QUEUED.value,
            reason=SECURITY_ENGINE_NOT_IMPLEMENTED,
            requested_by=principal.subject,
            idempotency_key_hash=key_hash,
            request_fingerprint=fingerprint,
            created_at=now,
            updated_at=now,
            attempts=0,
        )
        try:
            # PostgreSQL concurrent inserts race on the unique key; a savepoint
            # lets the losing request read the committed winner at READ COMMITTED.
            with self.session.begin_nested():
                self.session.add(job)
                self.session.flush()
        except IntegrityError:
            existing = self.session.scalar(lookup)
            if existing is None:
                raise
            return self._replay(existing, fingerprint), False
        self.session.execute(update(Case).where(Case.case_id == case_id).values(updated_at=now))
        self.audit(
            case_id,
            principal,
            AuditAction.INVESTIGATION_REQUESTED,
            now,
            job_id=job.job_id,
            state=CaseState.NEEDS_EVIDENCE.value,
            reason=SECURITY_ENGINE_NOT_IMPLEMENTED,
        )
        return job, True

    @staticmethod
    def _replay(job: Job, fingerprint: str) -> Job:
        if job.request_fingerprint != fingerprint:
            raise APIError(
                409, "IDEMPOTENCY_CONFLICT", "Idempotency key was used for a different request."
            )
        return job

    @staticmethod
    def _worker(principal: Principal) -> str:
        if principal.role is not Role.WORKER or principal.token_id is None:
            raise APIError(403, "FORBIDDEN", "A worker token is required.")
        return principal.token_id

    def claim(
        self, *, principal: Principal, lease_seconds: int, now: datetime | None = None
    ) -> Job | None:
        owner = self._worker(principal)
        now = now or utcnow()
        eligible = or_(
            Job.status == JobStatus.QUEUED.value,
            and_(
                Job.status == JobStatus.LEASED.value,
                Job.lease_expires_at <= now,
            ),
        )
        candidate_query = (
            select(Job.job_id).where(eligible).order_by(Job.created_at, Job.job_id).limit(1)
        )
        # SKIP LOCKED allows PostgreSQL workers to claim distinct jobs. SQLite
        # serializes its transaction and uses the same atomic eligible update.
        candidate = candidate_query.with_for_update(skip_locked=True).scalar_subquery()
        job = self.session.scalars(
            update(Job)
            .where(Job.job_id == candidate, eligible)
            .values(
                status=JobStatus.LEASED.value,
                lease_id=str(uuid4()),
                lease_owner_token_id=owner,
                lease_expires_at=now + timedelta(seconds=lease_seconds),
                updated_at=now,
                attempts=Job.attempts + 1,
            )
            .returning(Job),
            execution_options={"synchronize_session": False, "populate_existing": True},
        ).first()
        if job is not None:
            self.audit(
                job.case_id,
                principal,
                AuditAction.JOB_CLAIMED,
                now,
                job_id=job.job_id,
                attempt=job.attempts,
            )
        return job

    def _lease_predicate(
        self, job_id: str, principal: Principal, lease_id: str, now: datetime
    ) -> ColumnElement[bool]:
        return and_(
            Job.job_id == job_id,
            Job.status == JobStatus.LEASED.value,
            Job.lease_owner_token_id == self._worker(principal),
            Job.lease_id == lease_id,
            Job.lease_expires_at > now,
        )

    def _lease_failure(self, job_id: str, principal: Principal) -> NoReturn:
        job = self.session.get(Job, job_id, populate_existing=True)
        if job is None:
            raise APIError(404, "JOB_NOT_FOUND", "Job not found.")
        if job.lease_owner_token_id != principal.token_id:
            raise APIError(403, "NOT_LEASE_OWNER", "The token does not own this lease.")
        raise APIError(409, "LEASE_CONFLICT", "Lease is expired, superseded, or no longer active.")

    def heartbeat(
        self,
        job_id: str,
        *,
        principal: Principal,
        lease_id: str,
        lease_seconds: int,
        now: datetime | None = None,
    ) -> Job:
        now = now or utcnow()
        job = self.session.scalars(
            update(Job)
            .where(
                self._lease_predicate(job_id, principal, lease_id, now),
            )
            .values(lease_expires_at=now + timedelta(seconds=lease_seconds), updated_at=now)
            .returning(Job),
            execution_options={"synchronize_session": False, "populate_existing": True},
        ).first()
        if job is None:
            self._lease_failure(job_id, principal)
        self.audit(job.case_id, principal, AuditAction.JOB_HEARTBEAT, now, job_id=job_id)
        return job

    def complete(
        self, job_id: str, *, principal: Principal, lease_id: str, now: datetime | None = None
    ) -> Job:
        now = now or utcnow()
        job = self.session.scalars(
            update(Job)
            .where(
                self._lease_predicate(job_id, principal, lease_id, now),
            )
            .values(
                status=JobStatus.COMPLETED.value,
                completed_at=now,
                updated_at=now,
                lease_expires_at=None,
                outcome="UNSUPPORTED",
            )
            .returning(Job),
            execution_options={"synchronize_session": False, "populate_existing": True},
        ).first()
        if job is None:
            # A retry of the same owner's completed lease returns its receipt,
            # without an additional event or a claim of successful investigation.
            prior = self.session.get(Job, job_id, populate_existing=True)
            if (
                prior is not None
                and prior.status == JobStatus.COMPLETED.value
                and prior.lease_owner_token_id == principal.token_id
                and prior.lease_id == lease_id
            ):
                return prior
            self._lease_failure(job_id, principal)
        self.audit(
            job.case_id,
            principal,
            AuditAction.JOB_COMPLETED,
            now,
            job_id=job_id,
            outcome="UNSUPPORTED",
            reason=SECURITY_ENGINE_NOT_IMPLEMENTED,
        )
        return job
