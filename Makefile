PYTHON ?= python3

.PHONY: install format format-check lint typecheck test dependencies security check container-smoke

install:
	$(PYTHON) -m pip install -e '.[dev]'

format:
	$(PYTHON) -m ruff format src tests

format-check:
	$(PYTHON) -m ruff format --check src tests

lint:
	$(PYTHON) -m ruff check src tests

typecheck:
	$(PYTHON) -m mypy src tests

test:
	$(PYTHON) -m pytest

dependencies:
	$(PYTHON) -m pip check

security:
	$(PYTHON) -m bandit -c pyproject.toml -r src
	$(PYTHON) -m detect_secrets.pre_commit_hook --baseline .secrets.baseline $$(git ls-files --cached --others --exclude-standard)

check: format-check lint typecheck test dependencies security

container-smoke:
	docker compose build app
	docker compose run --rm --no-deps app --check
