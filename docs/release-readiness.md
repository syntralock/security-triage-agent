# Release readiness

Status: M12E open-source release preparation, 2026-09-22.

## Local/portfolio demo release

The existing `v1.0.0-demo` Git tag points to the M12D engineering checkpoint. Python package
version: `1.0.0`. M12E changes intentionally do not move, replace, or create a tag. A human must
decide how the eventual public source snapshot will be versioned after reviewing these changes.
Artifact distribution requires separate human approval.

The release candidate is evaluated for reproducibility, clean installability, the complete local
workflow, bounded security controls, documentation, repeatability, and known limitations. It is a
synthetic-data portfolio demonstration, not a production security service.

Resolved release gates include an Apache-2.0 project license, exact Python 3.12
runtime and development locks, reviewed immutable GitHub Action pins, packaged templates, typing
metadata, and migrations, a clean wheel-install application smoke test, and a release checklist.
Third-party license metadata is inventoried separately.

Remaining local/demo decisions:

- **HUMAN DECISION REQUIRED:** confirm final Apache-2.0 adoption and the
  `THIRD_PARTY_NOTICES`/MPL license-and-source preservation plan documented in
  `docs/third-party-licenses.md`, particularly before distributing a Docker image.
- **HUMAN DECISION REQUIRED:** approve the release commit and artifact distribution channel, and
  decide how to version the public source snapshot because the existing `v1.0.0-demo` tag predates
  M12E. Do not move or replace that tag as part of this milestone.
- A formal assistive-technology audit has not been performed.
- The demonstration uses synthetic fixture ingestion and a fixed local reviewer identity.
- `openai-l1-v2` remains experimental/advisory; the deterministic reasoner is the repeatable default.

Recommendation: **ready for human release review once all automated M12E verification passes;
do not commit, tag, publish, or distribute until the human decisions above are recorded.**

## Production release

Recommendation: **not ready**. The local/demo result must not be interpreted as production
approval. Production blockers remain:

- production identity provider and tenant isolation;
- production database access, migration, availability, backup, and recovery controls;
- rate limiting, TLS termination, deployment hardening, and secrets operations;
- enforceable retention and external/tamper-evident audit storage;
- real provider adapter and data-governance review;
- real remediation design, authorization, approval, and executor review;
- production monitoring, alerting, incident response, and operational ownership.

No current adapter performs real remediation or autonomous alert closure. Advisory AI cannot
authorize tools, policy, approvals, execution, or final disposition enforcement.
