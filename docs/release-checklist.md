# v1.0.0-demo release checklist

The reviewer records evidence for every checked item. Do not tag or distribute from an unclean or
unreviewed tree.

## Source

- [ ] Git state is clean; the proposed release commit is reviewed; the existing
  `v1.0.0-demo` tag is confirmed unchanged; and the public snapshot version is decided.
- [ ] Package version `1.0.0` and release-name relationship are correct.

## Security and supply chain

- [ ] Current-tree and full-history secret scans pass; `.env.local` was never tracked.
- [ ] Bandit and dependency consistency pass.
- [ ] Every GitHub Action uses a reviewed full commit SHA; workflow permissions remain read-only.
- [ ] Third-party license inventory, `THIRD_PARTY_NOTICES`, bundled license/source preservation,
  and all **HUMAN DECISION REQUIRED** items are reviewed.

## Build and database

- [ ] Runtime/development locks reproduce clean Python 3.12 environments.
- [ ] Wheel and sdist build; contents contain only intended files and no credentials/local state.
- [ ] Wheel non-editable installation and editable development installation both pass.
- [ ] Alembic offline SQL, upgrade → downgrade → upgrade, and fresh-database upgrade pass.

## Application

- [ ] Foundation check, `/health`, expected `/ready`, and dashboard HTTP 200 pass.
- [ ] Deterministic synthetic demo workflow, approval binding, simulation, and audit reconstruction pass.
- [ ] Release smoke test uses an isolated database and makes no OpenAI request.

## Tests

- [ ] Ruff formatter and lint, strict mypy, full pytest, and coverage ≥95% pass.
- [ ] Fixture and `evaluations/v1` validation plus deterministic baseline pass.
- [ ] Mocked OpenAI, API/UI, authorization, CSRF, approval/simulation, and HTML escaping tests pass.
- [ ] Docker build and hardened container startup checks pass.

## Integrity

- [ ] `openai-l1-v1` remains frozen; `openai-l1-v2` remains experimental/advisory.
- [ ] `evaluations/v1` and `fixtures/v1` are unchanged.
- [ ] No live OpenAI request, real provider integration, real remediation, or autonomous closure exists.
- [ ] Production blockers remain documented and the release is not described as production-ready.
