"""Create local Compose secrets and initialize the disposable Phase 1 stack.

The script intentionally never prints credential contents. It refuses to
overwrite any existing generated secret so reruns cannot silently replace a
user's local identity. Generated files live below ``.local/``, which is
ignored by the repository.
"""

from __future__ import annotations

import os
import re
import secrets
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / ".local"
DB_PASSWORD_FILE = LOCAL / "db_password"
COMPOSE_ENV_FILE = LOCAL / "compose.env"
API_TOKEN_FILE = LOCAL / "api.token"
WORKER_TOKEN_FILE = LOCAL / "worker.token"
API_SUBJECT = "local-operator"
WORKER_SUBJECT = "local-workflow-worker"


class BootstrapError(RuntimeError):
    """A sanitized, user-actionable bootstrap failure."""


def _windows_secure_writer_available() -> None:
    """Fail before a secret write if Windows ACL tooling is unavailable."""

    if os.name != "nt":
        return
    if shutil.which("icacls") is None or not os.environ.get("USERNAME"):
        raise BootstrapError("secure secret writing requires icacls and a Windows user identity")


def _ensure_local_directory() -> None:
    if LOCAL.is_symlink() or (hasattr(LOCAL, "is_junction") and LOCAL.is_junction()):
        raise BootstrapError(".local must not be a symbolic link or junction")
    if LOCAL.exists() and not LOCAL.is_dir():
        raise BootstrapError(".local exists but is not a directory")
    LOCAL.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt":
        try:
            os.chmod(LOCAL, 0o700)
        except OSError as exc:
            raise BootstrapError("could not secure the .local directory") from exc
    else:
        _apply_windows_acl(LOCAL, directory=True)


def _write_secret(path: Path, value: str) -> None:
    """Write one new secret with exclusive creation and restrictive ACLs."""

    if path.exists() or path.is_symlink():
        raise BootstrapError(f"refusing to overwrite existing secret: {path.relative_to(ROOT)}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if os.name != "nt" and hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise BootstrapError(f"could not create secret file: {path.relative_to(ROOT)}") from exc

    try:
        if os.name == "nt":
            # Create an empty file first, apply ACLs, then write the secret.
            # This ensures an ACL failure happens before secret bytes exist.
            _apply_windows_acl(path)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            descriptor = -1
            stream.write(value)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            os.chmod(path, 0o600)
    except (OSError, UnicodeError, BootstrapError) as exc:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            path.unlink()
        except OSError:
            pass
        if isinstance(exc, BootstrapError):
            raise
        raise BootstrapError(f"could not write secret file: {path.relative_to(ROOT)}") from exc


def _apply_windows_acl(path: Path, *, directory: bool = False) -> None:
    username = os.environ.get("USERNAME")
    if not username:
        raise BootstrapError("secure secret writing requires a Windows user identity")
    domain = os.environ.get("USERDOMAIN")
    account = f"{domain}\\{username}" if domain else username
    grant = f"{account}:(OI)(CI)F" if directory else f"{account}:F"
    result = subprocess.run(
        ["icacls", str(path), "/inheritance:r", "/grant:r", grant],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0:
        raise BootstrapError("could not apply a restrictive Windows ACL before writing a secret")


def _compose(
    env_file: Path, *arguments: str, capture: bool = True
) -> subprocess.CompletedProcess[str]:
    command = ["docker", "compose", "--env-file", str(env_file.relative_to(ROOT)), *arguments]
    try:
        return subprocess.run(
            command,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise BootstrapError("Docker Compose is required for local bootstrap") from exc


def _run_compose(env_file: Path, *arguments: str, stage: str) -> None:
    result = _compose(env_file, *arguments)
    if result.returncode != 0:
        # Do not relay command output: it can contain interpolated connection
        # strings or environment details. The stage name is reported by main.
        raise BootstrapError(
            f"Docker Compose failed during {stage}; existing secrets were preserved"
        )


def _issue_token(env_file: Path, subject: str, role: str) -> str:
    result = _compose(
        env_file,
        "run",
        "--rm",
        "--no-deps",
        "api",
        "counterseal",
        "init-token",
        "--subject",
        subject,
        "--role",
        role,
    )
    if result.returncode != 0:
        raise BootstrapError("token initialization failed")
    candidates = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
    if len(candidates) != 1 or not re.fullmatch(r"[A-Za-z0-9_-]{32,512}", candidates[0]):
        raise BootstrapError("token initialization returned an unexpected result")
    return candidates[0]


def _generated_env(db_password: str, token_hash_secret: str) -> str:
    database_url = (
        f"postgresql+psycopg://counterseal:{quote(db_password, safe='')}@db:5432/counterseal"
    )
    return "\n".join(
        [
            "POSTGRES_DB=counterseal",
            "POSTGRES_USER=counterseal",
            f"COUNTERSEAL_DATABASE_URL={database_url}",
            "COUNTERSEAL_ENVIRONMENT=development",
            "COUNTERSEAL_LOG_LEVEL=INFO",
            f"COUNTERSEAL_TOKEN_HASH_SECRET={token_hash_secret}",
            "COUNTERSEAL_DB_PASSWORD_FILE=.local/db_password",
            "COUNTERSEAL_WORKER_TOKEN_FILE=.local/worker.token",
            f"COUNTERSEAL_WORKER_UID={os.getuid() if os.name != 'nt' else 10001}",
            f"COUNTERSEAL_WORKER_GID={os.getgid() if os.name != 'nt' else 10001}",
            f"COUNTERSEAL_WORKER_EXPECTED_SUBJECT={WORKER_SUBJECT}",
            "COUNTERSEAL_WORKER_POLL_SECONDS=2",
            "COUNTERSEAL_WORKER_ERROR_BACKOFF_SECONDS=5",
            "COUNTERSEAL_WORKER_LEASE_SECONDS=60",
            "COUNTERSEAL_WORKER_MAX_CONSECUTIVE_ERRORS=5",
            "",
        ]
    )


def bootstrap() -> None:
    _windows_secure_writer_available()
    _ensure_local_directory()
    targets = (DB_PASSWORD_FILE, COMPOSE_ENV_FILE, API_TOKEN_FILE, WORKER_TOKEN_FILE)
    existing = [path for path in targets if path.exists() or path.is_symlink()]
    if existing:
        names = ", ".join(str(path.relative_to(ROOT)) for path in existing)
        raise BootstrapError(f"refusing to overwrite existing local secret files: {names}")

    db_password = secrets.token_urlsafe(32)
    token_hash_secret = secrets.token_urlsafe(32)
    _write_secret(DB_PASSWORD_FILE, db_password)
    _write_secret(COMPOSE_ENV_FILE, _generated_env(db_password, token_hash_secret))

    _run_compose(COMPOSE_ENV_FILE, "build", "api", "frontend", stage="image build")
    _run_compose(COMPOSE_ENV_FILE, "up", "-d", "--wait", "db", stage="database startup")
    _run_compose(COMPOSE_ENV_FILE, "run", "--rm", "--no-deps", "migration", stage="migration")
    api_token = _issue_token(COMPOSE_ENV_FILE, API_SUBJECT, "analyst")
    worker_token = _issue_token(COMPOSE_ENV_FILE, WORKER_SUBJECT, "worker")
    _write_secret(API_TOKEN_FILE, api_token)
    _write_secret(WORKER_TOKEN_FILE, worker_token)
    _run_compose(
        COMPOSE_ENV_FILE,
        "up",
        "-d",
        "--wait",
        "api",
        "worker",
        "frontend",
        stage="application startup",
    )


def main() -> int:
    try:
        bootstrap()
    except BootstrapError as exc:
        print(f"Bootstrap failed: {exc}", file=sys.stderr)
        return 1
    print("Local Counterseal stack initialized.")
    print("Open: http://127.0.0.1:8080")
    print("Operator token file: .local/api.token")
    print("Worker token file: .local/worker.token")
    print("Compose environment: .local/compose.env (use with --env-file; do not commit)")
    print(
        "Optional test database: docker compose --env-file .local/compose.env -f compose.yaml -f infra/compose.test.yaml up -d db"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["BootstrapError", "bootstrap", "main"]
