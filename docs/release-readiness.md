# Local/demo release readiness

Status: M12C implementation review, 2026-09-22.

## Release scope

This assessment covers a local portfolio demonstration using synthetic fixture data, the fixed
development identity, deterministic policy, optional advisory reasoning, human approval, and
simulation-only actions. It does not approve production deployment or real remediation.

## Findings

| Severity | Area | Finding | Disposition |
|---|---|---|---|
| Blocker | Public release | No software license has been selected. Repository availability does not grant reuse rights. | Select and review a license before public release. |
| High | Production security | Production identity, tenant isolation, and authorization do not exist; production mode correctly fails closed. | Required before any production deployment. |
| High | Production operations | SQLite/local process operation lacks production database controls, rate limiting, TLS/deployment policy, retention enforcement, backups, and external tamper-evident audit storage. | Required before production. |
| High | Provider integrations | Evidence adapters are synthetic and action execution is simulated. Real provider and remediation adapters require independent security reviews before enablement. | Explicitly out of M12C scope. |
| Medium | Reasoning quality | `openai-l1-v2` remains experimental/advisory after inconsistent BENIGN/NEEDS_REVIEW and deadline behavior in targeted validation. | Do not freeze or select as a production default. |
| Medium | Supply chain | A reviewed cross-platform lock strategy and immutable CI action SHA pins remain deferred. | Public-release gate from the M12A hardening review. |
| Medium | Audit integrity | Local audit events are append-only through the application but are not externally immutable or cryptographically tamper evident. | Acceptable for local demo; not production. |
| Low | Usability | The demo uses API/fixture ingestion rather than an upload form, preserving one ingestion mechanism but requiring a documented command. | Acceptable for the local portfolio workflow. |
| Low | Accessibility | Semantic structure, labels, focus indicators, contrast, table headings, text status, responsive layouts, and keyboard-operable controls are present; no formal assistive-technology audit has been performed. | Conduct a dedicated audit before broad public claims. |

## Functional readiness

The local workflow supports persisted alert queue metrics, alert detail, authorized triage,
evidence and tool chronology, deterministic-policy review, advisory assessment, trusted action
metadata, exact approval/rejection, simulated execution, and chronological audit reconstruction.
Empty, untriaged, running, review, no-evidence, no-action, rejected, expired, and failed-simulation
states have explicit safe presentation.

The default deterministic reasoner makes the principal demo repeatable and offline. The optional
OpenAI path remains configuration-selected and credential-gated; no request data can select the
provider, model, or prompt.

## Security posture

Strict request schemas, request-size limits, authorization, CSRF, autoescaping, sanitized errors,
ToolGateway scope, application-controlled identities, evidence provenance, deterministic policy,
approval digest/expiry binding, executor revalidation, append-only audit APIs, transactional
writes, stale recovery, production fail-closed composition, secret handling, and prompt-integrity
checks remain in force.

All UI mutations call existing application services. The presentation does not expose raw model
responses, private reasoning, SQL, provider authorization, credentials, or raw exceptions.

## Recommendation

**Local/portfolio release: conditionally ready after public-release blockers are resolved.** The
application is coherent and repeatable for local demonstration, but license selection and the
existing supply-chain release gates must be completed before publishing it as open source.

**Production release: not ready.** At minimum, production requires an IdP, tenant isolation,
production database and operational controls, rate limiting, TLS/deployment controls, enforced
retention, external/tamper-evident audit strategy, and separate reviews of real evidence and
remediation adapters. No production system should infer readiness from the local recommendation.
