PYTHON ?= python
COMPOSE_ENV ?= .local/compose.env
COMPOSE = docker compose --env-file $(COMPOSE_ENV)

.PHONY: bootstrap dev test security docs-check demo test-kind verify-bundle eval-offline down compose-config

bootstrap:
	$(PYTHON) scripts/bootstrap.py

dev:
	$(COMPOSE) up --build

test:
	uv run --locked --extra test pytest

security:
	uv run --locked --extra test ruff check src/counterseal/backend/worker.py tests/test_worker.py scripts
	uv run --locked --extra test pip-audit --skip-editable

docs-check:
	$(PYTHON) -c "from pathlib import Path; import sys; required = ['README.md', 'CLAUDE.md', 'docs/STATUS.md', 'docs/IMPLEMENTATION_PLAN.md', 'docs/threat-model/THREAT_MODEL.md']; missing = [p for p in required if not Path(p).is_file()]; print('Missing documentation: ' + ', '.join(missing)) if missing else None; sys.exit(1 if missing else 0)"

compose-config:
	$(COMPOSE) config --quiet

down:
	$(COMPOSE) down

demo:
	$(PYTHON) scripts/phase-command.py demo

test-kind:
	$(PYTHON) scripts/phase-command.py test-kind

verify-bundle:
	$(PYTHON) scripts/phase-command.py verify-bundle

eval-offline:
	$(PYTHON) scripts/phase-command.py eval-offline
