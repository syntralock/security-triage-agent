# Third-party dependency license inventory

Release candidate: `v1.0.0-demo`. Inventory source: the exact runtime/development locks, installed
package metadata, and authoritative license files at the upstream tags listed below, reviewed on
2026-09-22. This is a technical release-review aid, not legal advice. Dependencies remain governed
by their own license texts and upstream terms.

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
| Development | detect-secrets | 1.5.0 | Apache-2.0 |
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

- **HUMAN DECISION REQUIRED:** the project owner should approve public distribution under the
  repository's Apache-2.0 posture and the proposed notice/source-availability
  treatment for a Docker image. This inventory does not establish legal compliance.

## Authoritative verification

| Package | Exact upstream tag and commit | Verified license fact |
|---|---|---|
| detect-secrets 1.5.0 | [`v1.5.0`](https://github.com/Yelp/detect-secrets/tree/v1.5.0), `01886c8a910c64595c47f186ca1ffc0b77fa5458` | Root `LICENSE` contains Apache License 2.0 and the Yelp copyright/license notice. The package is development-only here. |
| certifi 2026.7.22 | [`2026.07.22`](https://github.com/certifi/python-certifi/tree/2026.07.22), `f4bc676bc101fe2235846e37044e8c693d6cbaf4` | Root `LICENSE` applies MPL-2.0 to the modified Mozilla CA certificate bundle; upstream packaging metadata also declares MPL-2.0. |
| pathspec 1.1.1 | [`v1.1.1`](https://github.com/cpburnz/python-pathspec/tree/v1.1.1), `ecf71a99ca739479d450b9830f43416ea0c519c7` | Root `LICENSE` is the complete MPL-2.0 text; upstream metadata declares MPL-2.0. The package is development-only here. |
| tqdm 4.70.1 | [`v4.70.1`](https://github.com/tqdm/tqdm/tree/v4.70.1), `9cf5a12b1f955468a17f0ba3c59092b23e4258ac` | Root `LICENCE` and `pyproject.toml` declare `MPL-2.0 AND MIT`. MPL-2.0 applies generally; identified historical files/portions retain MIT notices. This is not an either/or downstream choice. |
| packaging 26.3 | [`26.3`](https://github.com/pypa/packaging/tree/26.3), `929fd4b1410ac7ef61ef3f45b2f5d7e87711a9b5` | Root `LICENSE` permits use under either Apache-2.0 or BSD-2-Clause. |
| sniffio 1.3.1 | [`v1.3.1`](https://github.com/python-trio/sniffio/tree/v1.3.1), `ae020e13b98d276a6558ffc25e82509fd4c288f0` | Root `LICENSE` permits use under either Apache-2.0 or MIT. |

## Release-review categories

These categories describe license structure; they do not determine legal compatibility.

- **A — permissive:** alembic, annotated-doc, annotated-types, anyio, bandit, charset-normalizer,
  click, coverage, detect-secrets, distro, fastapi, greenlet, h11, httpcore, httpx, idna,
  iniconfig, Jinja2, jiter, librt, Mako, markdown-it-py, MarkupSafe, mdurl, mypy,
  mypy_extensions, openai, pluggy, pydantic, pydantic-settings, pydantic_core, Pygments, pytest,
  pytest-cov, python-dotenv, PyYAML, requests, rich, ruff, SQLAlchemy, starlette, stevedore,
  typing-inspection, urllib3, and uvicorn.
- **B — weak copyleft:** certifi and pathspec under MPL-2.0; the MPL-covered portions of tqdm.
- **C — strong copyleft:** none identified in the locked inventory.
- **D — PSF/other:** typing_extensions (PSF-2.0).
- **E — dual or multi-licensed:** packaging (Apache-2.0 OR BSD-2-Clause), sniffio (MIT OR
  Apache-2.0), and tqdm (`MPL-2.0 AND MIT`, applying to different identified material rather than
  offering one license choice for the package as a whole).
- **F — unknown/requires review:** none after exact-tag verification. Distribution decisions and
  compliance implementation still require human review.

## Distribution facts and apparent obligations

- **Private repository/local use:** no public source, wheel, sdist, or image distribution occurs.
  Use alone is distinct from distribution; this review identified no unresolved artifact-delivery
  obligation for that mode.
- **Public Apache-2.0 source repository:** the repository contains dependency declarations and
  lock entries, not dependency source. The project `NOTICE` remains limited to project-owned code.
  `THIRD_PARTY_NOTICES` is advisable for transparency but does not replace upstream licenses.
- **Application wheel:** the wheel contains only this project's code/assets and project `NOTICE`.
  It declares dependencies but does not bundle detect-secrets, certifi, pathspec, or tqdm. A package
  installer may separately obtain runtime dependencies under their own licenses.
- **Application sdist:** the sdist contains dependency names/versions in lock files, but not their
  source. It does not distribute the four reviewed packages themselves.
- **Docker image:** the image installs certifi and tqdm, including their Python source and their
  authoritative `dist-info/licenses/LICENSE` or `LICENCE` files. It does not install detect-secrets
  or pathspec. Distribution should preserve those files and provide recipients a practical notice
  pointing to the included licenses/source. Certifi's MPL-covered CA bundle and tqdm's MPL-covered
  files must remain available in Source Code Form under MPL-2.0; the current image contains their
  installed `.py`/data files and license files. **HUMAN DECISION REQUIRED:** approve this treatment
  before distributing the image and re-review it if images are flattened or license/source files
  are removed.
- **Hosted service:** users receive network responses, not the Python dependencies or image. The
  reviewed licenses contain no network-use source provision; this technical review identified no
  distribution-triggered source obligation for service-only access.

The MPL is file-level weak copyleft, not strong copyleft. Based on the reviewed text, it permits an
MPL-covered component to be part of a larger work under different terms while preserving MPL terms
for Covered Software. The project does not modify certifi, pathspec, or tqdm. This is a technical
reading of the license text, not a legal compatibility conclusion.

`THIRD_PARTY_NOTICES` is recommended for `v1.0.0-demo`, especially if a Docker image is distributed.
It is an index, not a substitute for full license texts. The installed distributions currently
carry their own full license files; preserve them in any redistributed runtime image.

Regenerate both locks, then rebuild this report from the resolved environment whenever a locked
version changes. Do not infer a license from package name, repository popularity, or memory when
metadata is absent.
