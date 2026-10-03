#!/usr/bin/env bash
# API/HTTP smoke test against the real server:
#   * configurable PORT / HOST
#   * /health
#   * legal retransmission scenario frozen through the API
#   * identical retransmission returns the original frozen result
#   * changed block conflicts (409) while original stays readable
#   * illegal WTX answer is frozen as a rejection
#   * static page is served
set -euo pipefail

cd "$(dirname "$0")/.."

PORT="${PORT:-8080}"
HOST="${HOST:-127.0.0.1}"
export PORT HOST
export AUDIT_FILE="${AUDIT_FILE:-$(pwd)/data/audits.smoke.json}"
BASE="http://${HOST}:${PORT}"

rm -f "$AUDIT_FILE"

node src/server.js > /tmp/t1-smoke-server.log 2>&1 &
SRV_PID=$!
cleanup() { kill "$SRV_PID" 2>/dev/null || true; wait "$SRV_PID" 2>/dev/null || true; }
trap cleanup EXIT

# wait for readiness (max ~10s)
for _ in $(seq 1 100); do
  if curl -sf "$BASE/health" >/dev/null 2>&1; then break; fi
  sleep 0.1
done

fail() { echo "SMOKE FAIL: $*" >&2; cat /tmp/t1-smoke-server.log >&2 || true; exit 1; }

# Build the captures with the same framing primitives the verifier uses,
# so LRC bytes are guaranteed correct (only the HTTP layer is under test).
node > /tmp/smoke-payloads.json <<'NODE'
const { encodeI, encodeR, encodeS } = require('./src/protocol');
const h = (d, bs) => ({ direction: d, hex: bs.map((x) => x.toString(16).padStart(2, '0')).join('') });
const cmd = [0x00, 0xa4, 0x04, 0x00, 0x02, 0x3f, 0x00];
const legal = {
  reviewer: 'smoke',
  blocks: [
    h('reader', encodeI(0, cmd)),
    h('card', encodeR(0, true)),        // NAK requests retransmission
    h('reader', encodeI(0, cmd)),       // legal duplicate, must not double-concatenate
    h('card', encodeS('WTX', false, [3])),
    h('reader', encodeS('WTX', true, [3])),
    h('card', encodeR(1)),              // then the duplicate is acknowledged
    h('card', encodeI(0, [0x90, 0x00])),
    h('reader', encodeR(1)),
  ],
};
const changed = {
  blocks: legal.blocks.map((blk) =>
    blk === legal.blocks[0] || blk === legal.blocks[2]
      ? h('reader', encodeI(0, [0x00, 0xa4, 0x04, 0x00, 0x02, 0x3f, 0x01]))
      : blk,
  ),
};
const badWtx = {
  blocks: [
    h('card', encodeI(0, [0x01])),
    h('reader', encodeS('WTX', false, [3])),
    h('card', encodeS('WTX', true, [9])), // multiplier mismatch
  ],
};
process.stdout.write(JSON.stringify({ legal, changed, badWtx }));
NODE

LEGAL=$(node -e 'process.stdout.write(JSON.stringify(require("/tmp/smoke-payloads.json").legal))')
CHANGED=$(node -e 'process.stdout.write(JSON.stringify(require("/tmp/smoke-payloads.json").changed))')
BADWTX=$(node -e 'process.stdout.write(JSON.stringify(require("/tmp/smoke-payloads.json").badWtx))')

curl -sf "$BASE/health" | grep -q '"status":"ok"' || fail "health check"
echo "  ok /health"

RESP=$(curl -sf -X PUT "$BASE/api/audits/SMOKE-LEGAL" -H 'content-type: application/json' -d "$LEGAL")
echo "$RESP" | grep -q '"accepted":true' || fail "legal capture not accepted: $RESP"
echo "$RESP" | grep -q '"chained":false' || true
# APDU must contain the command exactly once (duplicate not concatenated again)
APDU_COUNT=$(echo "$RESP" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const j=JSON.parse(s);const a=j.record.verdict.apdus.find(x=>x.direction==="reader");if(!a)process.exit(1);process.stdout.write(String((a.hex.match(/00A40400023F00/g)||[]).length))})')
[ "$APDU_COUNT" = "1" ] || fail "command APDU assembled $APDU_COUNT != 1 times"
echo "  ok freeze legal capture; retransmitted I-block concatenated exactly once"

# identical retransmission -> 200 replayed original
CODE=$(curl -s -o /tmp/smoke-replay.json -w '%{http_code}' -X PUT "$BASE/api/audits/SMOKE-LEGAL" -H 'content-type: application/json' -d "$LEGAL")
[ "$CODE" = "200" ] || fail "expected 200 on identical replay, got $CODE"
grep -q '"replayed":true' /tmp/smoke-replay.json || fail "replay not marked replayed"
echo "  ok identical replay returns the original frozen result"

# changed block -> 409 conflict, original still readable
CODE=$(curl -s -o /tmp/smoke-conflict.json -w '%{http_code}' -X PUT "$BASE/api/audits/SMOKE-LEGAL" -H 'content-type: application/json' -d "$CHANGED")
[ "$CODE" = "409" ] || fail "expected 409 on changed block, got $CODE"
grep -q 'AUDIT_CONFLICT' /tmp/smoke-conflict.json || fail "conflict body missing code"
echo "  ok changing any block conflicts with 409"

ORIG_FROZEN=$(curl -sf "$BASE/api/audits/SMOKE-LEGAL")
echo "$ORIG_FROZEN" | grep -q '00A40400023F00' || fail "original frozen result altered"
echo "  ok original frozen result still readable and unchanged"

# illegal WTX: multiplier mismatch response frozen as rejection at block 3
CODE=$(curl -s -o /tmp/smoke-badwtx.json -w '%{http_code}' -X PUT "$BASE/api/audits/SMOKE-BAD-WTX" -H 'content-type: application/json' -d "$BADWTX")
[ "$CODE" = "201" ] || fail "rejection should still freeze (201), got $CODE"
grep -q '"accepted":false' /tmp/smoke-badwtx.json || fail "bad WTX not rejected"
grep -q 'WTX_MULTIPLIER_MISMATCH' /tmp/smoke-badwtx.json || fail "bad WTX error code"
grep -q '"errorBlock":3' /tmp/smoke-badwtx.json || fail "bad WTX not pinned at block 3"
echo "  ok illegal WTX frozen as rejection at first offending raw block"

# list + page
curl -sf "$BASE/api/audits" | grep -q 'SMOKE-LEGAL' || fail "audit list"
curl -sf "$BASE/" | grep -q 'T=1' || fail "page not served"
echo "  ok audit list and review page served"

echo "SMOKE PASSED"
