# The image references below are repository digests resolved from the
# published tags on 2026-09-28. Keep the tag in the reference for readability;
# the digest is the reproducibility control.
FROM ghcr.io/astral-sh/uv:0.8.22@sha256:9874eb7afe5ca16c363fe80b294fe700e460df29a55532bbfea234a0f12eddb1 AS uv
FROM docker.io/library/python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PATH="/app/.venv/bin:/usr/local/bin:${PATH}"

WORKDIR /app

COPY --from=uv /uv /uvx /usr/local/bin/
COPY pyproject.toml uv.lock ./

# Resolve locked runtime dependencies before copying source for better cache
# reuse. The second sync installs the local project after its source is present.
RUN uv sync --frozen --no-dev --no-install-project

COPY alembic.ini ./
COPY alembic ./alembic
COPY src ./src

RUN uv sync --frozen --no-dev \
    && groupadd --system --gid 10001 counterseal \
    && useradd --system --uid 10001 --gid 10001 --no-create-home counterseal \
    && chown -R 10001:10001 /app

USER 10001:10001

CMD ["uvicorn", "counterseal.backend.app:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
