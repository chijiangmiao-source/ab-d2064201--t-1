#!/usr/bin/env bash
# Unified acceptance entrypoint: build check + code tests + API/HTTP smoke.
# Exits non-zero if any acceptance step fails. Used directly and by the
# docker compose `verify` service.
set -euo pipefail

cd "$(dirname "$0")/.."

PORT="${PORT:-8080}"
HOST="${HOST:-127.0.0.1}"
export PORT HOST
export AUDIT_FILE="${AUDIT_FILE:-$(pwd)/data/audits.verify.json}"

echo "== [1/4] syntax/build check =="
npm run check

echo "== [2/4] unit + protocol + audit tests =="
npm test

echo "== [3/4] HTTP/API smoke test =="
bash scripts/smoke.sh

echo "== [4/4] summary =="
echo "ACCEPTANCE PASSED: build check, tests and API/HTTP smoke all succeeded"
