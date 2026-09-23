# Local self-hosting

This guide covers the current local/demo deployment. It is not a production reference architecture.

## Docker Compose

```bash
cp .env.example .env
docker compose up --build
```

Open <http://127.0.0.1:8000>. Compose binds only to loopback, applies Alembic migrations before
startup, runs as an unprivileged user with a read-only root filesystem and dropped capabilities,
and stores the SQLite database in the `sta-data` named volume.

The default `demo` reasoner is deterministic and offline. It requires no OpenAI key. All evidence
is synthetic and every action executor is simulation-only.

## Configuration and secrets

Copy `.env.example` to the ignored `.env` for Compose. Prompt, model, database, and reasoner
selection are trusted operator configuration; HTTP requests cannot select them. To opt into the
experimental OpenAI reasoner, set `STA_REASONER_PROVIDER=openai` and provide `OPENAI_API_KEY` in
the local `.env`. Never commit that file or bake credentials into an image.

OpenAI mode sends synthetic alert/evidence context to the configured provider. It remains advisory
and does not gain approval or execution authority. `openai-l1-v1` is the frozen baseline;
`openai-l1-v2` is experimental.

## Data, backup, and reset

List the volume with `docker volume ls`. For a local backup, stop the service and copy/export the
SQLite file from the named volume using operator-controlled Docker tooling. Validate backups before
relying on them. There is no automated retention or backup policy.

Resetting removes all local demo records:

```bash
docker compose down --volumes
```

This operation is destructive. The bundled fixtures remain in the source checkout.

## Current limitations

- Fixed development identity; no production authentication or tenant isolation
- SQLite and local process operation only
- No TLS, rate limiting, production monitoring, or external audit storage
- No real provider telemetry and no remediation adapter
- No production backup, recovery, retention, or migration operations model

Production mode intentionally refuses startup until required identity controls exist.
