# Changelog

Notable project changes are documented here. This project uses human-readable release entries and
does not imply production support from a version number.

## 1.0.0-demo — 2026-09-22

First public/demo engineering baseline.

### Added

- Bounded triage orchestration with typed reasoner contracts
- Allowlisted, authorization-checked `ToolGateway` for read-only synthetic evidence
- Deterministic policy applied after untrusted reasoner output is parsed
- Human approval/rejection bound to exact high-impact action material
- Simulation-only action executor with immediate approval and authorization revalidation
- Durable normalized persistence and append-only application audit events
- Local FastAPI analyst interface and complete demonstration workflow
- Versioned deterministic evaluation framework and optional OpenAI reasoner
- Reproducible dependency locks, immutable CI Action pins, package inspection, and release smoke test
- Docker Compose local self-hosting and public security/contribution documentation

### Known limitations

- Synthetic fixtures only; no real provider telemetry
- No real remediation or autonomous alert closure
- Fixed development identity; no production authentication or tenant isolation
- `openai-l1-v2` remains experimental and advisory
- Local SQLite/audit storage is not a production operations or tamper-evident design
- Model-reported confidence is not a calibrated probability
