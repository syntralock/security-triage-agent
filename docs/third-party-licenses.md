# Third-party dependency license inventory

Release candidate: `v1.0.0-demo`. Inventory source: installed Python package metadata from the
Python 3.12.10 development lock resolved on 2026-09-22. This is a release-review aid, not legal
advice. Dependencies remain governed by their own license texts and upstream terms.

## Direct dependencies

| Scope | Package | Locked version | Declared license metadata |
|---|---|---:|---|
| Runtime | alembic | 1.20.0 | MIT |
| Runtime | fastapi | 0.141.1 | MIT |
| Runtime | Jinja2 | 3.1.6 | BSD License |
| Runtime | openai | 2.54.0 | Apache-2.0 |
| Runtime | pydantic-settings | 2.15.0 | MIT |
| Runtime | SQLAlchemy | 2.0.54 | MIT |
| Runtime | uvicorn | 0.53.0 | BSD-3-Clause |
| Development | bandit | 1.9.4 | Apache-2.0 |
| Development | detect-secrets | 1.5.0 | `UNKNOWN` in installed metadata |
| Development | httpx | 0.28.1 | BSD-3-Clause |
| Development | mypy | 1.20.2 | MIT |
| Development | pytest | 8.4.2 | MIT |
| Development | pytest-cov | 6.3.0 | MIT |
| Development | ruff | 0.16.8 | MIT |

## Locked transitive dependencies

| Package | Locked version | Declared license metadata |
|---|---:|---|
| annotated-doc | 0.0.5 | MIT |
| annotated-types | 0.8.0 | MIT |
| anyio | 4.15.1 | MIT |
| certifi | 2026.7.22 | MPL-2.0 |
| charset-normalizer | 3.5.1 | MIT |
| click | 8.5.0 | BSD-3-Clause |
| coverage | 7.16.1 | Apache-2.0 |
| distro | 1.9.0 | Apache License 2.0 |
| greenlet | 3.5.6 | MIT |
| h11 | 0.16.0 | MIT |
| httpcore | 1.0.9 | BSD-3-Clause |
| idna | 3.20 | BSD-3-Clause |
| iniconfig | 2.3.0 | MIT |
| jiter | 0.17.0 | MIT |
| librt | 0.15.0 | MIT |
| Mako | 1.4.1 | MIT |
| markdown-it-py | 4.2.0 | MIT License |
| MarkupSafe | 3.0.3 | BSD-3-Clause |
| mdurl | 0.1.2 | MIT License |
| mypy_extensions | 1.1.0 | MIT |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause |
| pathspec | 1.1.1 | MPL-2.0 |
| pluggy | 1.6.0 | MIT |
| pydantic | 2.13.5 | MIT |
| pydantic_core | 2.46.5 | MIT |
| Pygments | 2.21.0 | BSD-2-Clause |
| python-dotenv | 1.2.3 | BSD-3-Clause |
| PyYAML | 6.0.3 | MIT |
| requests | 2.34.2 | Apache-2.0 |
| rich | 15.0.0 | MIT |
| sniffio | 1.3.1 | MIT OR Apache-2.0 |
| starlette | 1.6.0 | BSD-3-Clause |
| stevedore | 5.9.1 | Apache-2.0 |
| tqdm | 4.70.1 | MPL-2.0 AND MIT |
| typing-inspection | 0.4.4 | MIT |
| typing_extensions | 4.16.0 | PSF-2.0 |
| urllib3 | 2.8.0 | MIT |

## Review flags

- **HUMAN DECISION REQUIRED:** `detect-secrets==1.5.0` reports `UNKNOWN` in its installed package
  metadata. Confirm its authoritative upstream license before distributing a development bundle.
- **HUMAN DECISION REQUIRED:** review the notice/source-distribution obligations for MPL-licensed
  `certifi`, `pathspec`, and `tqdm` before distributing application artifacts.
- **HUMAN DECISION REQUIRED:** the project owner should approve public distribution under the
  repository's proprietary/all-rights-reserved posture. This inventory does not establish that
  the distribution plan satisfies every third-party obligation.

Regenerate both locks, then rebuild this report from the resolved environment whenever a locked
version changes. Do not infer a license from package name, repository popularity, or memory when
metadata is absent.
