# Security Triage Agent

A portfolio demonstration intended for a future open-source release of a bounded, auditable Level 1 security alert triage agent. The project is designed for synthetic Microsoft Sentinel-, Defender-, and Entra-style alerts and keeps deterministic policy, authorization, approval, and action execution outside AI reasoning.

## Project status

Milestones 0–9 are complete through a small FastAPI transport, human approval boundary, and deterministic simulated-action workflow. The local application uses a deterministic demo reasoner, synthetic fixture tools, deterministic policy, immutable approval facts, and durable audit records. Real provider integrations, production authentication, and real remediation have not been implemented.

For local SQLite persistence, set `STA_DATABASE_URL` if the default is unsuitable and apply the schema with:

```bash
.venv/bin/python -m alembic upgrade head
```

Application startup never creates or mutates the schema automatically.

Start the local development server after applying migrations:

```bash
.venv/bin/uvicorn security_triage_agent.bootstrap:create_default_app --factory --reload
```

The configured principal is the fixed synthetic `development-reviewer`. It is selected by trusted composition, not HTTP input, and production configuration fails closed. This is not production authentication or tenant authorization.

- [Proposed architecture](docs/architecture.md)
- [Proposed repository structure](docs/repository-structure.md)
- [Threat model](docs/threat-model.md)
- [Implementation plan](docs/implementation-plan.md)
- [Engineering and security rules](AGENTS.md)

## Safety scope

- Use synthetic data only. Do not submit real alerts, identities, credentials, domains, or infrastructure data.
- The eventual agent may investigate and recommend but will not authorize or directly execute privileged changes.
- Initial remediation will be simulated only.
- This repository is not production-ready and is not a replacement for SOC policy or analyst judgment.

## Requirements

- Python 3.12 or later
- Docker with Compose (optional, for the container smoke check)
- No OpenAI or external service credentials

## Development setup

Create and activate a Python 3.12 virtual environment, then install the package and development tools:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
make install
```

Local settings use `STA_`-prefixed environment variables. Defaults are safe for development; copy `.env.example` only when overrides are needed:

```bash
cp .env.example .env
```

Run the foundation startup/configuration check:

```bash
python -m security_triage_agent --check
```

## Verification

Run all local checks:

```bash
make check
```

Or run checks separately:

```bash
make format-check
make lint
make typecheck
make test
make fixtures
make security
```

Build and run the hardened baseline container:

```bash
make container-smoke
```

The test and check workflow is offline after dependencies are installed and does not require paid API access.

## Local synthetic demo

The JSON API is intentionally small:

- `GET /health` and `GET /ready`
- `POST /api/alerts`, `GET /api/alerts`, and `GET /api/alerts/{alert_id}`
- `POST /api/alerts/{alert_id}/triage`
- `GET /api/executions/{execution_id}` plus `/tools` and `/audit`

Review pages are available at `/`, `/alerts/{alert_id}`, `/executions/{execution_id}`, and `/actions/{action_id}`. Only the action page has state-changing forms, and those forms require a reviewer-authorized principal plus a session-bound CSRF token.

With the server running, ingest a bundled synthetic alert and run triage:

```bash
jq '.[1]' fixtures/v1/alerts/alerts.json | \
  curl -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: demo-ingest-1' --data-binary @- \
  http://127.0.0.1:8000/api/alerts
```

The fixture file is an array, while the endpoint accepts one alert object. Then run:

```bash
curl -X POST -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: demo-triage-1' --data '{}' \
  http://127.0.0.1:8000/api/alerts/alert-riley-risk/triage
```

Open the returned execution URL and follow its action link. Alert, evidence, rationale, reviewer reason, and audit text are untrusted and autoescaped. Errors use sanitized `{code, message}` objects.

The demo reasoner has no model, prompt, network, or OpenAI dependency. It requests only the allowlisted synthetic user-risk tool, always escalates for review, and may propose a cataloged approval-gated action for high-severity demo alerts.

The authority chain is deliberately explicit:

> Reasoner recommends. Policy permits and classifies. Human reviewer authorizes the exact action. Executor revalidates. Simulation executes. Audit records the result.

The fixed development reviewer is synthetic and is not production authentication. Approvals bind the action ID and digest, target/parameters, policy version, reviewer, decision time, and a server-selected 15-minute expiry. Rejected decisions have no expiry. Execution reloads all authoritative state, rejects stale or expired approval, and is idempotent after success.

Action API routes are narrowly scoped:

- `GET /api/actions/{action_id}`
- `POST /api/actions/{action_id}/approve`
- `POST /api/actions/{action_id}/reject`
- `POST /api/actions/{action_id}/execute`

JSON APIs use the configured principal and do not use browser cookies. Browser forms use an unpredictable session cookie plus an HMAC-bound CSRF token; missing or invalid tokens fail. Every executor result is labeled `SIMULATED` / `SIMULATED_SUCCESS`, and no adapter can contact a provider or perform remediation.

## Contributing

1. Read `AGENTS.md`, the architecture, threat model, and current milestone acceptance criteria.
2. Keep changes within one approved milestone and preserve module dependency direction.
3. Add tests, including a negative/security case for behavior changes.
4. Run `make check`; run `make container-smoke` when container or packaging behavior changes.
5. Update documentation or add an ADR when changing a trust boundary or public contract.
6. Never commit `.env`, credentials, real security data, generated databases, or tool output containing sensitive values.

Report vulnerabilities privately according to [SECURITY.md](SECURITY.md).

## License

No license has been selected yet. Licensing will be decided during the Milestone 12 public-release review. Until then, no license grant should be inferred from the repository's availability.
