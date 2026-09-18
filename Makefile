PYTHON ?= python3

.PHONY: install format format-check lint typecheck test migrations fixtures evaluations dependencies security check container-smoke

install:
	$(PYTHON) -m pip install -e '.[dev]'

format:
	$(PYTHON) -m ruff format src tests scripts migrations

format-check:
	$(PYTHON) -m ruff format --check src tests scripts migrations

lint:
	$(PYTHON) -m ruff check src tests scripts migrations

typecheck:
	$(PYTHON) -m mypy

test:
	$(PYTHON) -m pytest

migrations:
	$(PYTHON) -m alembic upgrade head --sql >/dev/null

fixtures:
	PYTHONPATH=src $(PYTHON) scripts/verify_fixtures.py fixtures/v1

evaluations:
	PYTHONPATH=src $(PYTHON) scripts/verify_evaluations.py evaluations/v1/manifest.json fixtures/v1

dependencies:
	$(PYTHON) -m pip check

security:
	$(PYTHON) -m bandit -c pyproject.toml -r src
	$(PYTHON) -m detect_secrets.pre_commit_hook --baseline .secrets.baseline $$(git ls-files --cached --others --exclude-standard)

check: format-check lint typecheck test migrations fixtures evaluations dependencies security

container-smoke:
	docker compose build app
	docker compose run --rm --no-deps app --check
