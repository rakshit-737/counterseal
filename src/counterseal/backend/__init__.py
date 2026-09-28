"""Counterseal's transport and application foundation.

The backend package is deliberately separate from :mod:`counterseal.domain`:
the domain models remain side-effect-free, while this package owns HTTP,
configuration, authentication, observability, and persistence bootstrap.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .auth import (
    AuthenticationError,
    IssuedToken,
    LocalTokenStore,
    Principal,
    Role,
    TokenRecord,
    hash_token,
)
from .settings import Settings, get_settings

if TYPE_CHECKING:
    from fastapi import FastAPI


def create_app(settings: Settings | None = None) -> FastAPI:
    """Lazily import and create the FastAPI application.

    Keeping this wrapper lazy prevents importing a settings singleton as a
    side effect of importing the database or migration modules.
    """

    from .app import create_app as _create_app

    return _create_app(settings)


__all__ = [
    "AuthenticationError",
    "IssuedToken",
    "LocalTokenStore",
    "Principal",
    "Role",
    "Settings",
    "TokenRecord",
    "create_app",
    "get_settings",
    "hash_token",
]
