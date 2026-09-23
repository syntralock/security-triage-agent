# Development guide

## Environment

Use Python 3.12 and a normal virtual environment:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.lock
python -m pip install --no-deps -e .
```

The lock is the reproducible path; `make install` intentionally resolves the compatibility ranges
from `pyproject.toml`. A previously observed cached runtime did not process editable metadata
normally, which is why release verification always uses a fresh standard environment.

## Database and server

```bash
python -m alembic upgrade head
uvicorn security_triage_agent.bootstrap:create_default_app --factory --reload
```

Application startup never mutates the schema. Local configuration may be placed in the ignored
`.env.local`; never commit credentials.

## Verification

```bash
make check
make release-smoke
make container-smoke
```

`make check` runs formatting, Ruff, strict mypy, the full offline pytest suite with its coverage
gate, migration rendering, fixture/evaluation validation, dependency checks, Bandit, and secret
scanning. OpenAI adapter tests are mocked and make no provider request.

After applying migrations, run the deterministic evaluation with:

```bash
python -m security_triage_agent.evaluation
python -m security_triage_agent.evaluation --json
```

Do not run live model evaluations as part of ordinary contribution verification. Read
[CONTRIBUTING.md](../CONTRIBUTING.md), [dependency locking](dependency-locking.md), and the
[security invariants](security-invariants.md) before changing trust boundaries.
