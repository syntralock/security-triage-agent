#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
generate_lock() {
  local extras="$1"
  local output="$2"
  {
    echo "# Generated on Linux/Python 3.12 from the project dependency graph; do not edit by hand."
    docker run --rm --volume "$repo_root:/workspace:ro" python:3.12-slim \
      /bin/sh -c "python -m pip install '/workspace$extras' >/dev/null && python -m pip check >/dev/null && python -m pip freeze --all" \
      | grep -Ev '^(pip==|security-triage-agent(==| @ ))'
  } >"$repo_root/$output"
}

generate_lock "" requirements.lock
generate_lock "[dev]" requirements-dev.lock
echo "Review both lock diffs and the third-party license report before accepting updates."
