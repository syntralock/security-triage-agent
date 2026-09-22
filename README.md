# Security Triage Agent

A portfolio demonstration intended for a future open-source release of a bounded, auditable Level 1 security alert triage agent. The project is designed for synthetic Microsoft Sentinel-, Defender-, and Entra-style alerts and keeps deterministic policy, authorization, approval, and action execution outside AI reasoning.

## Project status

Milestones 0–11, M12A hardening, and M12B experimental reasoning work are complete. M12C provides a coherent local analyst workflow for portfolio review. The safe default remains the deterministic demo reasoner. Both reasoner paths use synthetic fixture tools, deterministic policy, immutable approval facts, simulated actions, durable audit records, and versioned scenario scoring. Production authentication, tenant isolation, and real remediation have not been implemented.

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
- [M12A hardening review](docs/hardening-review.md)
- [Security invariants](docs/security-invariants.md)
- [Secret management](docs/secret-management.md)
- [Implementation plan](docs/implementation-plan.md)
- [Evaluation framework](docs/evaluation.md)
- [Engineering and security rules](AGENTS.md)

## Safety scope

- Use synthetic data only. Do not submit real alerts, identities, credentials, domains, or infrastructure data.
- The eventual agent may investigate and recommend but will not authorize or directly execute privileged changes.
- Initial remediation will be simulated only.
- This repository is not production-ready and is not a replacement for SOC policy or analyst judgment.

## Requirements

- Python 3.12 or later
- Docker with Compose (optional, for the container smoke check)
- No OpenAI or external service credentials for the default offline path

## Development setup

Create and activate a Python 3.12 virtual environment, then install the package and development tools:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
make install
```

Local settings use `STA_`-prefixed environment variables. Defaults are safe for development; copy `.env.example` to the explicitly ignored `.env.local` only when overrides are needed, and restrict it to the local user (`chmod 600 .env.local`):

```bash
cp .env.example .env.local
chmod 600 .env.local
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

Run the deterministic evaluation baseline after applying migrations:

```bash
python -m security_triage_agent.evaluation
python -m security_triage_agent.evaluation --json
```

The baseline deliberately reports the demo reasoner’s limitations. Ground truth is never included in reasoner context, scoring is component-based rather than opaque, and evaluation never approves or executes an action. Model-reported confidence is not a calibrated probability.

## Local synthetic demo

The JSON API is intentionally small:

- `GET /health` and `GET /ready`
- `POST /api/alerts`, `GET /api/alerts`, and `GET /api/alerts/{alert_id}`
- `POST /api/alerts/{alert_id}/triage`
- `GET /api/executions/{execution_id}` plus `/tools` and `/audit`

The local analyst workflow is:

> Alert queue → source alert → triage → investigation → deterministic policy → assessment → evidence review → action recommendation → human decision → simulated execution → audit history

Review pages are available at `/`, `/alerts/{alert_id}`, `/executions/{execution_id}`, and `/actions/{action_id}`. The alert page can start triage for an analyst-authorized principal. Action pages support approval, rejection, and authorized simulation. Every browser mutation requires server-side authorization and a session-bound CSRF token.

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

Open <http://127.0.0.1:8000/>. The dashboard is derived from persisted state; select the alert, review the source/assessed severity distinction, and use the action link to inspect the exact approval binding. Approve or reject with a reason. An approved action can enter only the simulator, and its outcome and actor appear in the audit timeline. Alert, evidence, rationale, reviewer reason, and audit text are untrusted and autoescaped. Errors use sanitized `{code, message}` objects.

### Recommended repeatable demo

Use the default deterministic reasoner so the presentation requires no network or API key:

1. Apply migrations and start the server as shown above.
2. Ingest fixture alert index `0` to show the benign-resolved source narrative; the deliberately
   conservative demo reasoner still returns an advisory review result rather than auto-closing it.
3. Ingest fixture alert index `1` (`alert-riley-risk`) to show a high-impact investigation and approval-gated recommendation.
4. Start triage from the alert detail page and inspect the evidence chronology, deterministic policy, assessment, and audit timeline.
5. Open the recommended action. Verify the trusted risk, exact target/parameters, digest, policy version, and `SIMULATED_ONLY` support.
6. Record a rejection to demonstrate a terminal human decision, or use a fresh triage execution and approve the exact action.
7. Run the approved simulation and inspect its durable `SIMULATED_SUCCESS` record and action timeline.
8. Run `python -m security_triage_agent.evaluation --scenario typed-not-found-evidence` separately to demonstrate deterministic `NEEDS_REVIEW` behavior without changing the product database.

The fixture/evaluation harness contains overlapping contract scenarios rather than a curated product seed system. No second demo-data source has been added.

The demo reasoner has no model, prompt, network, or OpenAI dependency. It requests only the allowlisted synthetic user-risk tool, always escalates for review, and may propose a cataloged approval-gated action for high-severity demo alerts.

### Optional OpenAI reasoner

The OpenAI model is a reasoning component, not a security authority. The adapter uses the official Python SDK Responses API with strict Pydantic structured output. It does not enable SDK tool execution or pass application callables: a model tool request is typed data that the existing `ToolGateway` validates and executes. Deterministic policy remains authoritative, and all state-changing actions retain their approval requirements.

Configuration is trusted and environment-only:

```text
STA_REASONER_PROVIDER=openai
OPENAI_API_KEY=<local secret>
STA_OPENAI_MODEL=gpt-5.6-luna
STA_OPENAI_REQUEST_TIMEOUT_SECONDS=25
STA_OPENAI_MAX_OUTPUT_TOKENS=1500
STA_OPENAI_PROMPT_VERSION=openai-l1-v1
```

The default `openai-l1-v1` contract remains frozen for baseline reproducibility. Trusted local
configuration may instead select `openai-l1-v2`, which remains **experimental and advisory** and
is not approved as a default. Request data cannot select a prompt. M12B found useful scope,
anti-leakage, and stopping improvements, but also inconsistent BENIGN/NEEDS_REVIEW semantics and
deadline behavior. Selecting V2 never changes gateway, policy, approval, or execution authority.
See [the controlled M12B experiment record](docs/evaluations/m12b-terra-v1-v2-experiment.md).

No reasoner output closes or suppresses an alert. BENIGN remains advisory; SUSPICIOUS does not
trigger an external escalation; MALICIOUS does not authorize containment; and NEEDS_REVIEW
requires analyst attention. Model confidence is uncalibrated advisory metadata.

## Screenshots

Screenshots may be added during public-release packaging after the UI and release wording are
approved. Do not use screenshots containing real alerts, identities, infrastructure, or secrets.

The default provider is `demo`. Enabling `openai` without a key fails closed; there is no silent fallback. SDK retries are disabled, requests set `store=False`, output is bounded, and provider errors become sanitized reasoner failures that orchestration durably resolves to `NEEDS_REVIEW` when possible.

An optional live synthetic evaluation is developer-invoked only and never part of CI:

```bash
STA_REASONER_PROVIDER=openai python -m security_triage_agent.evaluation --scenario typed-not-found-evidence
```

It records provider, model, prompt version, suite, fixture, and policy identity. It creates no approval and performs no action execution. A full ten-scenario run can make up to the configured orchestration limit per scenario; with current defaults that is at most 80 provider requests, although normal successful cases generally use fewer. Token use depends on bounded alert/evidence context and the 1,500-token output ceiling per request.

The authority chain is deliberately explicit:

> Reasoner recommends. Policy permits and classifies. Human reviewer authorizes the exact action. Executor revalidates. Simulation executes. Audit records the result.

If a process is interrupted, an operator may explicitly fail stale non-terminal records after applying migrations:

```bash
python -m security_triage_agent --recover-stale
```

The configured thresholds are hard lower-bounded and the recovery is idempotent. It never infers success or reruns an action. It is intentionally not hidden in a read path or automatic startup hook.

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
6. Never commit `.env`, `.env.local`, credentials, real security data, generated databases, or tool output containing sensitive values.

Report vulnerabilities privately according to [SECURITY.md](SECURITY.md).

## License

No license has been selected yet. Licensing will be decided during the Milestone 12 public-release review. Until then, no license grant should be inferred from the repository's availability.
