# Dependency locking

`pyproject.toml` is the authoritative compatibility declaration. `requirements.lock` captures the
complete runtime graph and `requirements-dev.lock` captures runtime plus test/review tooling for
the `v1.0.0-demo` Python 3.12 release candidate. Separating them avoids shipping development tools
while making CI reproducible.

Install the release runtime dependencies and local package:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.lock
python -m pip install --no-deps .
python -m pip check
```

For editable development, substitute `requirements-dev.lock` and `python -m pip install --no-deps
-e .`. `--no-deps` is intentional: it prevents the project install from changing the resolved lock.

Regenerate both files from the declared graph with:

```bash
bash scripts/regenerate_locks.sh
```

Regeneration resolves versions available at that time. Treat every resulting change as a
dependency update: review the diff, package licenses, changelogs/security advisories, full tests,
and clean-install smoke result before acceptance. The current locks combine clean Python 3.12.10
verification with the Linux/Python 3.12 graph used by CI and release containers, not the damaged
Codex-managed `.venv` investigated after M12C. Regeneration requires Docker so Linux-conditional
dependencies such as `greenlet` are included; the exact result is then verified locally.

The locks use exact versions but not hashes. A portable hash lock would need hashes for every
accepted wheel/sdist across supported platforms and a controlled artifact policy; adding only the
current macOS ARM hashes would falsely imply cross-platform reproducibility and break Linux CI.
Exact versions plus package-index TLS are the intentionally minimal first-demo strategy.

**HUMAN DECISION REQUIRED:** before distributing beyond the local/portfolio demo, decide whether
to maintain a reviewed cross-platform hash set or an internal immutable package mirror.
