# Security Triage Agent

A portfolio demonstration intended for a future open-source release of a bounded, auditable Level 1 security alert triage agent. The project is designed for synthetic Microsoft Sentinel-, Defender-, and Entra-style alerts and keeps deterministic policy, authorization, approval, and action execution outside AI reasoning.

## Project status

Milestones 0–7 are complete through the deterministic synthetic evidence environment, closed tool gateway, transactional persistence, versioned policy/action catalog, and bounded offline orchestration with a fake reasoner. API/UI ingestion, real provider integrations, approval services, and remediation behavior have not been implemented.

For local SQLite persistence, set `STA_DATABASE_URL` if the default is unsuitable and apply the schema with:

```bash
.venv/bin/python -m alembic upgrade head
```

Application startup never creates or mutates the schema automatically.

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
