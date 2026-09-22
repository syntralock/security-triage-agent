# M12A security and reliability hardening review

Status values: **implemented**, **accepted**, or **deferred**. No finding was assessed CRITICAL.

| ID | Severity | Component | Threat or failure and consequence | Existing control | Mitigation/status | Verification |
|---|---|---|---|---|---|---|
| HR-01 | HIGH | Lifecycle persistence | Process death can leave triage `RUNNING` or simulation `EXECUTING`, obscuring terminal state. | Durable intermediate transactions; failures normally recover inline. | Explicit threshold-based recovery to `FAILED`, atomic audit, no rerun; **implemented**. | Selective, atomic, idempotent interruption-history tests. |
| HR-02 | HIGH | Production composition | A configuration check could imply production readiness despite absent production identity. | Dependency composition rejected the development principal. | All production runtime profiles now refuse startup; **implemented**. | Settings, API composition, and CLI tests. |
| HR-03 | MEDIUM | Reporting | Immutable `mappingproxy` action parameters were not JSON serializable, impairing diagnostics. | Domain immutability correctly prevented mutation. | Explicit recursive safe serializer; **implemented**. | Nested immutable-parameter regression test. |
| HR-04 | MEDIUM | Provider observability | Provider logs lacked execution/correlation linkage; missing usage could be mistaken for zero. | Sanitized provider/model/prompt/duration/failure logs. | Add both identifiers and preserve absent tokens as null; **implemented**. Durable token accounting is **deferred** because the current reasoner port returns only a step; adding it safely requires a typed observation contract and migration. | Mocked success/failure logging tests. |
| HR-05 | MEDIUM | Audit storage | SQLite and an application append-only repository cannot prevent a DB administrator or compromised process from changing history. | Atomic state/audit writes; no update/delete audit methods. | **Accepted for local demonstration**; production posture and integrity roadmap documented. | Migration/transaction/audit tests. |
| HR-06 | MEDIUM | API deployment | No production IdP, tenant isolation, or application rate limiter. Exposure could enable unauthorized access or exhaustion. | Strict validation, body limit, scoped authorization port, CSRF for browser mutations; production refusal. | **Deferred** to deployment/IdP work; reverse-proxy request and rate limits are mandatory before exposure. | API security tests and production refusal. |
| HR-07 | MEDIUM | Supply chain | Version ranges and tagged GitHub Actions are less reproducible than a reviewed lock and SHA pins. | Exact runtime/development locks, immutable reviewed Action SHAs with version comments, read-only workflow permissions, disabled checkout credential persistence, digest-pinned base image, `pip check`, Bandit, and secret scan. | **Implemented for M12D.** Dependency refreshes still require explicit lock and license review. | Clean locked install, CI, dependency consistency, and release checklist. |
| HR-08 | LOW | Test dependencies | Two Starlette/httpx deprecation warnings add noise. | Tests pass and warnings originate in dependency compatibility paths. | **Accepted/deferred**; broad upgrade or warning suppression is unjustified. Reassess with a reviewed dependency update. | Full pytest warning provenance. |
| HR-09 | LOW | Container runtime | PID exhaustion and child reaping were not explicitly constrained. | Non-root, read-only root, all capabilities dropped, no-new-privileges, bounded tmpfs, digest-pinned base, excluded env files. | Add init, PID limit, and noexec/nosuid/nodev tmpfs; **implemented**. | Compose inspection and runtime checks. |
| HR-10 | LOW | Prompt identity | Version constant alone did not detect an in-place instruction edit. | Literal prompt version persisted/logged. | Stable digest checked in adapter construction and regression test; **implemented**. | Prompt digest test. |

## Database and audit posture

SQLite is supported for local synthetic development, not as production-grade immutable audit storage. Foreign keys are enabled, important identities and idempotency keys are unique, query paths are indexed by the migration, repositories use parameterized SQLAlchemy expressions, and the Unit of Work owns commits. PostgreSQL remains the intended production database after dedicated integration, concurrency, backup/restore, least-privilege role, TLS, retention, and migration testing.

Current audit integrity is application-level append-only plus transactional consistency. That detects application workflow facts but neither prevents nor cryptographically proves administrator tampering. A staged future design may add hash chaining (tamper evidence, not prevention), signed exports, immutable object storage, an external SIEM copy/outbox, restrictive database roles, and an explicit retention/legal-hold policy.

## Deployment and API posture

Health and readiness disclose only coarse state. JSON inputs are strict and size-limited; mutation uses POST; browser mutation requires CSRF; templates autoescape; errors are sanitized; generic CRUD is absent. A production gateway must add TLS, authentication, tenant scoping, request/concurrency rate limits, and operational monitoring. The application deliberately refuses production startup until real identity exists.

## Supply-chain and build posture

The Python project retains bounded compatibility declarations and now has exact Python 3.12
runtime and development locks for the local/demo release. CI installs the development lock and
uses reviewed immutable Action SHAs. The container base remains digest-pinned. Locks do not replace
review: regeneration is an intentional dependency update, and platform-specific wheels may differ
while package versions remain fixed.
