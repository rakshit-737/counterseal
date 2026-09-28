"""Authenticated principals and separate human/worker authorization checks."""

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .auth import AuthenticationError, Principal, Role
from .db.repositories import TokenRepository
from .db.session import get_session
from .errors import APIError

bearer = HTTPBearer(auto_error=False)
DatabaseSession = Annotated[Session, Depends(get_session)]


def current_principal(
    request: Request,
    session: DatabaseSession,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> Principal:
    if credentials is None or len(request.headers.getlist("authorization")) != 1:
        raise APIError(401, "UNAUTHENTICATED", "A valid bearer token is required.")
    try:
        return TokenRepository(
            session, hash_secret=request.app.state.settings.token_hash_secret
        ).authenticate(
            credentials.credentials,
        )
    except AuthenticationError as exc:
        raise APIError(401, "UNAUTHENTICATED", "A valid bearer token is required.") from exc


Authenticated = Annotated[Principal, Depends(current_principal)]


def require_role(required: Role) -> Callable[[Principal], Principal]:
    def authorize(principal: Authenticated) -> Principal:
        if not principal.has_role(required):
            raise APIError(403, "FORBIDDEN", "The token role does not permit this operation.")
        return principal

    return authorize


Reader = Annotated[Principal, Depends(require_role(Role.VIEWER))]
Analyst = Annotated[Principal, Depends(require_role(Role.ANALYST))]
Worker = Annotated[Principal, Depends(require_role(Role.WORKER))]
