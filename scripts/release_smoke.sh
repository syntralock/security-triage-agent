#!/usr/bin/env bash
set -euo pipefail

if [[ "$(python3.12 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')" != "3.12" ]]; then
  echo "release smoke test requires Python 3.12" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work_dir="$(mktemp -d /tmp/security-triage-release.XXXXXX)"
server_pid=""
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$work_dir"
}
trap cleanup EXIT INT TERM

python3.12 -m venv "$work_dir/venv"
python="$work_dir/venv/bin/python"
"$python" -m pip install -r "$repo_root/requirements.lock"
"$python" -m pip wheel --no-deps --wheel-dir "$work_dir/dist" "$repo_root"
"$python" -m pip install --no-deps "$work_dir"/dist/security_triage_agent-*.whl
"$python" -m pip check

"$python" -c "import security_triage_agent"
"$work_dir/venv/bin/security-triage-agent" --version
"$work_dir/venv/bin/security-triage-evaluate" --help >/dev/null
"$python" -m security_triage_agent --check

package_dir="$("$python" -c 'import pathlib, security_triage_agent; print(pathlib.Path(security_triage_agent.__file__).parent)')"
export STA_DATABASE_URL="sqlite:///$work_dir/release-smoke.sqlite3"
export STA_ENVIRONMENT=development
export STA_REASONER_PROVIDER=demo
unset OPENAI_API_KEY || true

"$python" -m alembic -c "$package_dir/alembic.ini" current
"$python" -m alembic -c "$package_dir/alembic.ini" upgrade head
"$python" -m alembic -c "$package_dir/alembic.ini" current | grep -q '0004_openai_evaluation_identity (head)'

port="${STA_RELEASE_SMOKE_PORT:-8765}"
"$work_dir/venv/bin/uvicorn" security_triage_agent.bootstrap:create_default_app \
  --factory --host 127.0.0.1 --port "$port" >"$work_dir/server.log" 2>&1 &
server_pid="$!"

"$python" - "$port" <<'PY'
import json
import sys
import time
import urllib.error
import urllib.request

port = sys.argv[1]
base = f"http://127.0.0.1:{port}"
for attempt in range(50):
    try:
        with urllib.request.urlopen(f"{base}/health", timeout=1) as response:
            assert response.status == 200
            assert json.load(response) == {"status": "ok"}
        break
    except (OSError, AssertionError, urllib.error.URLError):
        if attempt == 49:
            raise
        time.sleep(0.2)

with urllib.request.urlopen(f"{base}/ready", timeout=2) as response:
    assert response.status == 200
    assert json.load(response) == {"status": "ready"}
with urllib.request.urlopen(base, timeout=2) as response:
    body = response.read().decode("utf-8")
    assert response.status == 200
    assert "Security Triage Agent" in body
PY

echo "release smoke test passed"
