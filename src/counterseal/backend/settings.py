"""Typed environment configuration for the Phase 1 backend."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "staging", "production"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


class Settings(BaseSettings):
    """Application settings read from ``COUNTERSEAL_*`` environment variables.

    The local SQLite URL keeps the Phase 1 app runnable without a database
    service.  Deployments can provide a PostgreSQL SQLAlchemy URL through
    ``COUNTERSEAL_DATABASE_URL``; migrations use the same setting.
    """

    model_config = SettingsConfigDict(
        env_prefix="COUNTERSEAL_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = Field(default="counterseal-backend", min_length=1, max_length=128)
    environment: Environment = "development"
    host: str = Field(default="127.0.0.1", min_length=1, max_length=253)
    port: int = Field(default=8000, ge=1, le=65535)
    log_level: LogLevel = "INFO"
    database_url: str = Field(default="sqlite:///./counterseal.db", min_length=1, repr=False)
    auth_token_ttl_seconds: int = Field(default=3600, ge=1, le=31_536_000)
    token_hash_secret: SecretStr | None = None

    @field_validator("database_url")
    @classmethod
    def _database_url_must_not_contain_whitespace(cls, value: str) -> str:
        if value.strip() != value or any(character.isspace() for character in value):
            raise ValueError("database_url must not contain whitespace")
        return value

    @model_validator(mode="after")
    def _production_requires_token_hash_secret(self) -> Settings:
        if self.environment == "production" and self.token_hash_secret is None:
            raise ValueError("COUNTERSEAL_TOKEN_HASH_SECRET is required in production")
        if (
            self.token_hash_secret is not None
            and not self.token_hash_secret.get_secret_value().strip()
        ):
            raise ValueError("token_hash_secret must not be blank")
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-level settings instance."""

    return Settings()


__all__ = ["Environment", "LogLevel", "Settings", "get_settings"]
