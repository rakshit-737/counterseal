from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from counterseal.backend.auth import (
    AuthenticationError,
    LocalTokenStore,
    Role,
    hash_token,
)

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def test_hash_is_deterministic_and_store_retains_only_hash() -> None:
    store = LocalTokenStore(token_ttl=timedelta(minutes=5))
    issued = store.issue(subject="operator-1", role=Role.OPERATOR, now=NOW)

    assert hash_token(issued.token) == issued.record.token_hash
    assert issued.token not in issued.record.token_hash
    assert issued.token not in store.stored_token_hashes
    assert store.authenticate(issued.token, now=NOW).has_role(Role.VIEWER)
    assert store.authenticate(issued.token, now=NOW).role is Role.OPERATOR


def test_configured_hash_secret_is_used_without_being_stored() -> None:
    store = LocalTokenStore(hash_secret="local-test-secret")
    issued = store.issue(subject="operator-1", role=Role.OPERATOR, now=NOW)

    assert issued.record.token_hash == hash_token(issued.token, secret="local-test-secret")
    assert issued.record.token_hash != hash_token(issued.token)
    assert store.authenticate(issued.token, now=NOW).subject == "operator-1"


def test_expiry_and_revoke_fail_closed() -> None:
    store = LocalTokenStore(token_ttl=timedelta(minutes=5))
    issued = store.issue(subject="operator-1", role=Role.OPERATOR, now=NOW)

    with pytest.raises(AuthenticationError):
        store.authenticate(issued.token, now=NOW + timedelta(minutes=5))

    issued = store.issue(subject="operator-2", role=Role.APPROVER, now=NOW)
    store.revoke(issued.token, now=NOW)
    with pytest.raises(AuthenticationError):
        store.authenticate(issued.token, now=NOW)

    with pytest.raises(AuthenticationError) as error:
        store.authenticate("wrong-token", now=NOW)
    assert "wrong-token" not in str(error.value)
