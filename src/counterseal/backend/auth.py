"""Hash-only bearer token primitives for the local-development foundation.

The API uses the SQLAlchemy TokenRepository. LocalTokenStore remains a small
in-memory utility for isolated callers; it is not an API authentication source.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from threading import RLock


class Role(StrEnum):
    """Human roles are ordered; workers have a separate authorization boundary."""

    VIEWER = "viewer"
    ANALYST = "analyst"
    OPERATOR = "analyst"  # Compatibility name for the initial local utility.
    APPROVER = "approver"
    ADMIN = "admin"
    WORKER = "worker"


_ROLE_RANK: dict[Role, int] = {
    Role.VIEWER: 10,
    Role.ANALYST: 20,
    Role.APPROVER: 30,
    Role.ADMIN: 40,
}


@dataclass(frozen=True, slots=True)
class Principal:
    """Authenticated identity attached to a verified token."""

    subject: str
    role: Role
    token_id: str | None = None

    def has_role(self, required: Role) -> bool:
        """Return whether this principal meets the required role level."""

        if self.role is Role.WORKER or required is Role.WORKER:
            return self.role is required
        return _ROLE_RANK[self.role] >= _ROLE_RANK[required]


@dataclass(frozen=True, slots=True)
class TokenRecord:
    """Persistable token metadata; deliberately contains no clear token."""

    token_hash: str
    subject: str
    role: Role
    issued_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None

    def principal(self) -> Principal:
        return Principal(subject=self.subject, role=self.role)


@dataclass(frozen=True, slots=True)
class IssuedToken:
    """One-time delivery value returned by token issuance."""

    token: str = field(repr=False)
    record: TokenRecord


class AuthenticationError(ValueError):
    """Raised when a bearer token is missing, unknown, expired, or revoked."""


def hash_token(token: str, *, secret: str | bytes | object | None = None) -> str:
    """Hash a bearer token without retaining the token itself.

    A configured secret uses HMAC-SHA-256; the no-secret form remains useful
    for local tests and backwards-compatible deterministic hashing.
    """

    if not isinstance(token, str) or not token:
        raise ValueError("token must be a non-empty string")
    token_bytes = token.encode("utf-8")
    if secret is None:
        return hashlib.sha256(token_bytes).hexdigest()
    if hasattr(secret, "get_secret_value"):
        secret = secret.get_secret_value()
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    if not isinstance(secret, bytes) or not secret:
        raise ValueError("token hash secret must be non-empty")
    return hmac.new(secret, token_bytes, hashlib.sha256).hexdigest()


class LocalTokenStore:
    """Thread-safe in-memory token store for local development and tests."""

    def __init__(
        self,
        *,
        token_ttl: timedelta = timedelta(hours=1),
        hash_secret: str | bytes | object | None = None,
    ) -> None:
        if token_ttl <= timedelta(0):
            raise ValueError("token_ttl must be positive")
        self._token_ttl = token_ttl
        self._hash_secret = hash_secret
        self._records: dict[str, TokenRecord] = {}
        self._lock = RLock()

    def issue(
        self,
        *,
        subject: str,
        role: Role,
        now: datetime | None = None,
    ) -> IssuedToken:
        """Create a random token and retain only its hash and metadata."""

        if not subject or not subject.strip():
            raise ValueError("subject must be a non-empty string")
        if not isinstance(role, Role):
            role = Role(role)
        issued_at = _as_utc(now or datetime.now(UTC))
        token = secrets.token_urlsafe(32)
        record = TokenRecord(
            token_hash=hash_token(token, secret=self._hash_secret),
            subject=subject,
            role=role,
            issued_at=issued_at,
            expires_at=issued_at + self._token_ttl,
        )
        with self._lock:
            self._records[record.token_hash] = record
        return IssuedToken(token=token, record=record)

    def authenticate(
        self,
        token: str,
        *,
        now: datetime | None = None,
    ) -> Principal:
        """Verify a token and return its principal without exposing metadata."""

        try:
            candidate_hash = hash_token(token, secret=self._hash_secret)
        except ValueError as exc:
            raise AuthenticationError("invalid bearer token") from exc

        current_time = _as_utc(now or datetime.now(UTC))
        with self._lock:
            record = next(
                (
                    candidate
                    for candidate in self._records.values()
                    if hmac.compare_digest(candidate.token_hash, candidate_hash)
                ),
                None,
            )
            if record is None or record.revoked_at is not None or record.expires_at <= current_time:
                raise AuthenticationError("invalid bearer token")
            return record.principal()

    def revoke(self, token: str, *, now: datetime | None = None) -> None:
        """Revoke a known token; unknown tokens fail closed without disclosure."""

        try:
            candidate_hash = hash_token(token, secret=self._hash_secret)
        except ValueError as exc:
            raise AuthenticationError("invalid bearer token") from exc
        current_time = _as_utc(now or datetime.now(UTC))
        with self._lock:
            for token_hash, record in self._records.items():
                if hmac.compare_digest(token_hash, candidate_hash):
                    self._records[token_hash] = TokenRecord(
                        token_hash=record.token_hash,
                        subject=record.subject,
                        role=record.role,
                        issued_at=record.issued_at,
                        expires_at=record.expires_at,
                        revoked_at=current_time,
                    )
                    return
        raise AuthenticationError("invalid bearer token")

    @property
    def stored_token_hashes(self) -> frozenset[str]:
        """Expose hashes for diagnostics/tests, never clear tokens."""

        with self._lock:
            return frozenset(self._records)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must include an explicit UTC offset")
    return value.astimezone(UTC)


__all__ = [
    "AuthenticationError",
    "IssuedToken",
    "LocalTokenStore",
    "Principal",
    "Role",
    "TokenRecord",
    "hash_token",
]
