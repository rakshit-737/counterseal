"""Portable Phase 1 control-plane tables. No source credentials or evidence."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    DDL,
    JSON,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    event,
)
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, UTCDateTime


class User(Base):
    """Local identity; role scopes live on its individually revocable tokens."""

    __tablename__ = "users"

    subject: Mapped[str] = mapped_column(String(256), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    disabled_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class AuthToken(Base):
    """Token metadata; the clear bearer token is never a database column."""

    __tablename__ = "auth_tokens"
    __table_args__ = (
        Index("ix_auth_tokens_token_hash", "token_hash", unique=True),
        CheckConstraint(
            "role IN ('viewer', 'analyst', 'approver', 'admin', 'worker')",
            name="ck_auth_tokens_role",
        ),
        CheckConstraint("expires_at > issued_at", name="ck_auth_tokens_expiry"),
    )

    token_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    subject: Mapped[str] = mapped_column(
        String(256),
        ForeignKey("users.subject", name="fk_auth_tokens_subject_users"),
        nullable=False,
    )
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class Case(Base):
    __tablename__ = "cases"
    __table_args__ = (
        CheckConstraint("state = 'NEEDS_EVIDENCE'", name="ck_cases_state"),
        CheckConstraint("reason = 'SECURITY_ENGINE_NOT_IMPLEMENTED'", name="ck_cases_reason"),
        Index("ix_cases_created_at", "created_at", "case_id"),
    )

    case_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.subject"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)


class Job(Base):
    __tablename__ = "jobs"
    __table_args__ = (
        UniqueConstraint("requested_by", "idempotency_key_hash", name="uq_jobs_request_key"),
        CheckConstraint("kind = 'INVESTIGATION'", name="ck_jobs_kind"),
        CheckConstraint("status IN ('QUEUED', 'LEASED', 'COMPLETED')", name="ck_jobs_status"),
        CheckConstraint("attempts >= 0", name="ck_jobs_attempts"),
        CheckConstraint("reason = 'SECURITY_ENGINE_NOT_IMPLEMENTED'", name="ck_jobs_reason"),
        CheckConstraint(
            "status != 'LEASED' OR (lease_id IS NOT NULL AND lease_owner_token_id IS NOT NULL AND lease_expires_at IS NOT NULL)",
            name="ck_jobs_active_lease",
        ),
        CheckConstraint(
            "(status = 'COMPLETED' AND completed_at IS NOT NULL AND outcome IS NOT NULL AND outcome = 'UNSUPPORTED') OR "
            "(status != 'COMPLETED' AND completed_at IS NULL AND outcome IS NULL)",
            name="ck_jobs_completion",
        ),
        Index("ix_jobs_claim", "status", "lease_expires_at", "created_at"),
    )

    job_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.case_id"), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str] = mapped_column(String(64), nullable=False)
    requested_by: Mapped[str] = mapped_column(ForeignKey("users.subject"), nullable=False)
    idempotency_key_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    request_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    lease_id: Mapped[str | None] = mapped_column(String(36))
    lease_owner_token_id: Mapped[str | None] = mapped_column(ForeignKey("auth_tokens.token_id"))
    lease_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    outcome: Mapped[str | None] = mapped_column(String(32))


class AuditEvent(Base):
    """System-authored metadata, protected from UPDATE/DELETE by DB triggers."""

    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_events_case_sequence", "case_id", "sequence"),)

    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(36), nullable=False, unique=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.case_id"), nullable=False)
    actor: Mapped[str] = mapped_column(ForeignKey("users.subject"), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    details: Mapped[dict] = mapped_column(JSON, nullable=False)


# create_all is useful for isolated tests. Alembic installs the same guards for
# durable databases. A database owner can still bypass triggers; this is not a
# cryptographic or independently administered audit service.
for operation in ("UPDATE", "DELETE"):
    event.listen(
        AuditEvent.__table__,
        "after_create",
        DDL(
            f"CREATE TRIGGER audit_events_no_{operation.lower()} BEFORE {operation} ON audit_events "
            "BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END"
        ).execute_if(dialect="sqlite"),
    )

event.listen(
    AuditEvent.__table__,
    "after_create",
    DDL(
        "CREATE FUNCTION counterseal_audit_append_only() RETURNS trigger LANGUAGE plpgsql AS $$ "
        "BEGIN RAISE EXCEPTION 'audit events are append-only'; END; $$"
    ).execute_if(dialect="postgresql"),
)
event.listen(
    AuditEvent.__table__,
    "after_create",
    DDL(
        "CREATE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE OR TRUNCATE "
        "ON audit_events FOR EACH STATEMENT EXECUTE FUNCTION counterseal_audit_append_only()"
    ).execute_if(dialect="postgresql"),
)
event.listen(
    AuditEvent.__table__,
    "after_drop",
    DDL("DROP FUNCTION counterseal_audit_append_only()").execute_if(dialect="postgresql"),
)


__all__ = ["AuditEvent", "AuthToken", "Case", "Job", "User"]
