from __future__ import annotations

import pytest
from pydantic import ValidationError

from counterseal.backend.settings import Settings


def test_settings_read_typed_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COUNTERSEAL_PORT", "8123")
    monkeypatch.setenv("COUNTERSEAL_ENVIRONMENT", "test")
    monkeypatch.setenv("COUNTERSEAL_DATABASE_URL", "sqlite:///./test.db")

    settings = Settings()

    assert settings.port == 8123
    assert settings.environment == "test"
    assert settings.database_url == "sqlite:///./test.db"


def test_settings_reject_invalid_port() -> None:
    with pytest.raises(ValidationError):
        Settings(port=0)


def test_production_requires_hash_secret() -> None:
    with pytest.raises(ValidationError):
        Settings(environment="production")

    settings = Settings(environment="production", token_hash_secret="configured")
    assert settings.token_hash_secret is not None
