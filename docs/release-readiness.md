# Release readiness

Status: M12D release-candidate review, 2026-09-22.

## Local/portfolio demo release

Target release name and Git tag: `v1.0.0-demo`. Python package version: `1.0.0`. The tag uses a
human-readable demo suffix; package metadata uses the stable PEP 440 version. Tagging and artifact
distribution require separate human approval.

The release candidate is evaluated for reproducibility, clean installability, the complete local
workflow, bounded security controls, documentation, repeatability, and known limitations. It is a
synthetic-data portfolio demonstration, not a production security service.

Resolved M12D gates include an explicit proprietary/all-rights-reserved notice, exact Python 3.12
runtime and development locks, reviewed immutable GitHub Action pins, packaged templates, typing
metadata, and migrations, a clean wheel-install application smoke test, and a release checklist.
Third-party license metadata is inventoried separately.

Remaining local/demo decisions:

- **HUMAN DECISION REQUIRED:** approve the proprietary public-distribution posture and the
  `THIRD_PARTY_NOTICES`/MPL license-and-source preservation plan documented in
  `docs/third-party-licenses.md`, particularly before distributing a Docker image.
- **HUMAN DECISION REQUIRED:** approve the release commit, artifact distribution channel, and
  creation of the `v1.0.0-demo` tag.
- A formal assistive-technology audit has not been performed.
- The demonstration uses synthetic fixture ingestion and a fixed local reviewer identity.
- `openai-l1-v2` remains experimental/advisory; the deterministic reasoner is the repeatable default.

Recommendation: **ready for human release review once all automated M12D verification passes;
do not tag or distribute until the human decisions above are recorded.**

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
