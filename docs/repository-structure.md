# Proposed Repository Structure

Status: approved target structure. Milestones 1–3 scaffold the foundation, domain, and synthetic evidence-tool subsets; later directories remain deferred to their owning milestones.

```text
security-triage-agent/
├── AGENTS.md
├── README.md
├── SECURITY.md
├── pyproject.toml
├── .env.example
├── .gitignore
├── Dockerfile
├── compose.yaml
├── alembic.ini
├── migrations/
├── docs/
│   ├── architecture.md
│   ├── repository-structure.md
│   ├── implementation-plan.md
│   ├── threat-model.md
│   └── adr/
├── src/security_triage_agent/
│   ├── __init__.py
│   ├── domain/
│   │   ├── __init__.py
│   │   ├── _base.py
│   │   ├── alerts.py
│   │   ├── triage.py
│   │   ├── evidence.py
│   │   ├── entities.py
│   │   ├── actions.py
│   │   ├── approvals.py
│   │   ├── states.py
│   │   └── errors.py
│   ├── application/
│   │   ├── __init__.py
│   │   ├── evidence_tools.py
│   │   ├── action_catalog.py
│   │   ├── orchestration_contracts.py
│   │   ├── orchestrator.py
│   │   ├── persistence.py
│   │   ├── tool_registry.py
│   │   ├── tool_gateway.py
│   │   ├── ports/
│   │   │   ├── __init__.py
│   │   │   ├── reasoner.py
│   │   │   ├── tools.py
│   │   │   ├── repositories.py
│   │   │   ├── clock.py
│   │   │   └── executors.py
│   │   ├── triage_service.py
│   │   ├── orchestrator.py
│   │   ├── policy.py
│   │   ├── approval_service.py
│   │   └── evaluation_service.py
│   ├── adapters/
│   │   ├── __init__.py
│   │   ├── api/
│   │   │   ├── app.py
│   │   │   ├── routes/
│   │   │   ├── schemas/
│   │   │   └── templates/
│   │   ├── alerts/
│   │   │   ├── sentinel.py
│   │   │   ├── defender.py
│   │   │   └── entra.py
│   │   ├── reasoners/
│   │   │   └── fake.py
│   │   ├── tools/
│   │   │   ├── __init__.py
│   │   │   ├── fixture_models.py
│   │   │   └── fixtures.py
│   │   ├── persistence/
│   │   │   ├── __init__.py
│   │   │   ├── models.py
│   │   │   ├── repositories.py
│   │   │   └── uow.py
│   │   └── actions/
│   │       └── noop.py
│   ├── bootstrap.py
│   ├── config.py
│   └── logging.py
├── fixtures/
│   ├── README.md
│   ├── v1/
│   │   ├── manifest.json
│   │   ├── alerts/
│   │   ├── identities.json
│   │   ├── user_risk.json
│   │   ├── signins.json
│   │   ├── devices.json
│   │   ├── ip_reputation.json
│   │   ├── mfa_events.json
│   │   └── related_alerts.json
├── evaluations/
│   ├── scenarios/
│   ├── schema.json
│   └── README.md
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── contract/
│   └── evaluation/
└── scripts/
    ├── run_evaluations.py
    └── verify_fixtures.py
```

## Dependency direction

`domain` has no framework or adapter dependencies. `application` depends on `domain` and declared ports. `adapters` depend inward on ports and domain types. `bootstrap.py` is the composition root and is the only place that should wire concrete adapters together.

Tests mirror these boundaries:

- `unit`: pure domain, policy, state-machine, and orchestration tests with fakes.
- `integration`: FastAPI, SQLAlchemy, transaction, migration, and audit-completeness tests.
- `contract`: every tool/reasoner/action adapter against its port contract.
- `evaluation`: scenario loading, scoring, and deterministic end-to-end cases.

Keep fixtures outside package code so their versions and licensing/synthetic status are obvious. Avoid a broad `utils.py`; place behavior with the concept that owns it.

The repository intentionally has no license file during internal development. A license and any corresponding repository metadata will be selected during the Milestone 12 public-release review.
