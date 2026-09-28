"""RFC 8785 content integrity, not authenticity or permission to execute."""

from collections.abc import Mapping
from datetime import UTC, datetime
from enum import Enum
from hashlib import sha256
from hmac import compare_digest
from typing import Any
from uuid import UUID

import rfc8785
from pydantic import BaseModel


class CanonicalizationError(ValueError):
    """Input is outside the bounded I-JSON/domain value vocabulary."""


def _json_value(value: Any, depth: int = 0) -> Any:
    if depth > 32:
        raise CanonicalizationError("canonical input exceeds depth limit")
    if isinstance(value, BaseModel):
        return _json_value(value.model_dump(mode="python"), depth + 1)
    if isinstance(value, Enum):
        return _json_value(value.value, depth + 1)
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise CanonicalizationError("timestamps must be timezone-aware")
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, UUID):
        return str(value)
    if value is None or type(value) in (str, bool, int, float):
        return value
    if isinstance(value, Mapping):
        if len(value) > 16384 or any(type(key) is not str for key in value):
            raise CanonicalizationError("objects require bounded string keys")
        return {key: _json_value(item, depth + 1) for key, item in value.items()}
    if isinstance(value, (list, tuple)) and len(value) <= 16384:
        return [_json_value(item, depth + 1) for item in value]
    raise CanonicalizationError(f"unsupported canonical input: {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    """Use the maintained RFC 8785 implementation, including number formatting."""
    try:
        result = rfc8785.dumps(_json_value(value))
        if len(result) > 8 * 1024 * 1024:
            raise CanonicalizationError("canonical input exceeds byte limit")
        return result
    except (ValueError, TypeError, OverflowError, UnicodeError, RecursionError) as exc:
        raise CanonicalizationError(str(exc)) from exc


def canonical_json(value: Any) -> str:
    return canonical_bytes(value).decode("utf-8")


def canonical_digest(value: Any) -> str:
    return "sha256:" + sha256(canonical_bytes(value)).hexdigest()


def verify_digest(value: Any, expected: str) -> bool:
    if not isinstance(expected, str) or len(expected) != 71:
        return False
    if not expected.startswith("sha256:") or any(c not in "0123456789abcdef" for c in expected[7:]):
        return False
    return compare_digest(canonical_digest(value), expected)
