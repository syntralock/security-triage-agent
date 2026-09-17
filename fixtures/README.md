# Synthetic Fixture Data

All records in this directory are intentionally fabricated for public security demonstrations. They are not copied, sampled, or transformed from production events. Names explicitly say “Synthetic,” principal names use the reserved `.test` domain, and network addresses use the documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, and `2001:db8::/32`.

## Versioning

Each top-level `vN` directory is an immutable fixture contract version. Files within one version share the manifest's `fixture_version` and `schema_version`. Correcting a typo that does not change identifiers or expected behavior may remain in the current version before release; any change to record identity, relationships, schemas, deterministic reference time, or expected lookup results requires a new version directory.

Adapters receive an explicit fixture directory. They never silently select a newer version. Evaluation scenarios should record the fixture version they used.

## Determinism

`manifest.json` owns the reference time and recent-sign-in window. The `get_recent_signins` adapter never reads the wall clock. Records returned by collection tools use stable ordering defined by the adapter contract, so identical validated input and fixture version produce identical semantically relevant output.

## Referential integrity

The validator requires:

- unique identifiers within every record type;
- supported fixture and schema versions;
- valid, timezone-aware timestamps and normalized IP addresses;
- identity-to-device ownership to agree in both directions;
- sign-ins to reference existing users, devices, and IP reputation records;
- MFA events to reference existing users and sign-ins for the same user;
- user-risk records to reference existing users;
- related-alert mappings to reference existing users and alerts;
- normalized alert entity references to resolve to fixture users, devices, and IPs.

Run validation with:

```bash
PYTHONPATH=src python scripts/verify_fixtures.py fixtures/v1
```

Descriptive strings are inert evidence. One record deliberately contains prompt-injection-like text to verify that fixture loading never treats evidence as instructions.
