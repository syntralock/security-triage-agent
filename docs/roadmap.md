# Roadmap

The roadmap describes direction, not commitments or timelines. Every new trust boundary requires
design, threat modeling, tests, and human review.

## Current

- Local/self-hosted demo with synthetic evidence
- Deterministic policy and advisory reasoning
- Approval-bound, simulation-only actions
- Durable local audit history and web UI
- Reproducible Python and Docker verification

## Next

- Read-only provider telemetry behind existing ports and `ToolGateway`
- Microsoft Entra read-only integration as the first provider study
- Provider-neutral adapter contracts, cancellation-aware I/O, and authorization tests
- Stronger, independently reviewed fixtures/evaluations v2

## Later — requires security review

- Production identity and tenant isolation
- PostgreSQL production operations, backup, retention, and recovery
- External or tamper-evident audit export
- Production deployment, rate limiting, TLS, monitoring, and incident operations
- Any real remediation/write adapter; such capability is not assumed or promised
