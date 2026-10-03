'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  verifyCapture,
  encodeI,
  encodeR,
  encodeS,
  lrcFor,
  toHex,
  parseHex,
  MAX_BLOCKS,
  ERROR_CODES,
} = require('../src/protocol');
const { AuditStore, ConflictError } = require('../src/store');

const R = 'reader';
const C = 'card';
const b = (direction, bytes) => ({ direction, bytes });

function corruptLrc(bytes) {
  const out = [...bytes];
  out[out.length - 1] ^= 0xff;
  return out;
}

// ---------- baseline legal exchanges ----------

test('single command/response exchange verifies and assembles APDUs', () => {
  const cmd = [0x00, 0xa4, 0x04, 0x00, 0x02, 0x3f, 0x00];
  const rsp = [0x90, 0x00];
  const cap = [
    b(R, encodeI(0, cmd)),
    b(C, encodeR(1)),
    b(C, encodeI(0, rsp)),
    b(R, encodeR(1)),
  ];
  const v = verifyCapture(cap);
  assert.equal(v.accepted, true, JSON.stringify(v));
  assert.equal(v.apdus.length, 2);
  assert.equal(v.apdus[0].direction, R);
  assert.equal(v.apdus[0].hex, toHex(cmd));
  assert.deepEqual(v.apdus[0].blocks, [1]);
  assert.equal(v.apdus[1].hex, toHex(rsp));
  assert.deepEqual(v.finalSnapshot.reader.sendSeq, 1);
  assert.deepEqual(v.finalSnapshot.card.sendSeq, 1);
});

test('chained I-blocks are assembled into one complete APDU', () => {
  const p1 = [0x00, 0x82];
  const p2 = [0x00, 0x00, 0x0a];
  const p3 = Array.from({ length: 10 }, (_, k) => k + 1);
  const cap = [
    b(R, encodeI(0, p1, true)),
    b(C, encodeR(1)),
    b(R, encodeI(1, p2, true)),
    b(C, encodeR(0)),
    b(R, encodeI(0, p3, false)),
    b(C, encodeR(1)),
  ];
  const v = verifyCapture(cap);
  assert.equal(v.accepted, true, JSON.stringify(v));
  assert.equal(v.apdus.length, 1);
  assert.equal(v.apdus[0].chained, true);
  assert.equal(v.apdus[0].hex, toHex([...p1, ...p2, ...p3]));
  assert.deepEqual(v.apdus[0].blocks, [1, 3, 5]);
});

// ---------- legal retransmission: no duplicate concatenation ----------

test('legal duplicate of latest unacked I-block after NAK passes and is concatenated once', () => {
  const cmd = [0x00, 0xa4, 0x04, 0x00, 0x02, 0x3f, 0x00];
  const cap = [
    b(R, encodeI(0, cmd)),
    b(C, encodeR(0, true)), // NAK for N(S)=0
    b(R, encodeI(0, cmd)), // legal retransmission
    b(C, encodeR(1)), // then confirmed
    b(C, encodeI(0, [0x90, 0x00])),
    b(R, encodeR(1)),
  ];
  const v = verifyCapture(cap);
  assert.equal(v.accepted, true, JSON.stringify(v));
  assert.equal(v.apdus.length, 2);
  assert.equal(v.apdus[0].hex, toHex(cmd)); // not twice
  const dupSteps = v.steps.filter((s) => s.duplicate === true);
  assert.equal(dupSteps.length, 1);
  assert.equal(dupSteps[0].retransmitBasis.startsWith('I-DUP'), true);
  assert.equal(v.stats.retransmissions, 2); // NAK + duplicate marker
});

test('spontaneous legal duplicate without preceding NAK still passes and is not duplicated', () => {
  const cmd = [0x10, 0x20];
  const cap = [
    b(R, encodeI(0, cmd)),
    b(R, encodeI(0, cmd)), // identical re-send while unacked
    b(C, encodeR(1)),
  ];
  const v = verifyCapture(cap);
  assert.equal(v.accepted, true, JSON.stringify(v));
  assert.equal(v.apdus[0].hex, toHex(cmd));
});

test('retransmission of a non-latest block is rejected at the duplicate block', () => {
  // I0 acked, I1 unacked; replay of I0 must fail at the replay block.
  const cap = [
    b(R, encodeI(0, [0x01], true)),
    b(C, encodeR(1)),
    b(R, encodeI(1, [0x02], false)),
    b(R, encodeI(0, [0x01], true)), // stale duplicate, N(S) mismatch vs latest unacked N(S)=1
  ];
  const v = verifyCapture(cap);
  assert.equal(v.accepted, false);
  assert.equal(v.errorCode, ERROR_CODES.IMPOSSIBLE_SEQ);
  assert.equal(v.errorBlock, 4);
});

test('replay of an already acknowledged block fails as a stale duplicate', () => {
  const cap = [
    b(R, encodeI(0, [0x01])),
    b(C, encodeR(1)),
    b(R, encodeI(0, [0x01])), // vS is now 1: this is not the recent unacked block
  ];
  const v = verifyCapture(cap);
  assert.equal(v.accepted, false);
  assert.equal(v.errorCode, ERROR_CODES.STALE_DUP);
  assert.equal(v.errorBlock, 3);
});

test('duplicate N(S) with altered payload is rejected', () => {
  const cap = [
    b(R, encodeI(0, [0x01])),
    b(C, encodeR(0, true)),
    b(R, encodeI(0, [0x02])), // same N(S), different INF
  ];
  const v = verifyCapture(cap);
  assert.equal(v.accepted, false);
  assert.equal(v.errorCode, ERROR_CODES.DUP_MISMATCH);
  assert.equal(v.errorBlock, 3);
});

// ---------- R-block rules ----------

test('R-block with wrong N(R) for ACK is rejected at that R-block', () => {
  const cap = [
    b(R, encodeI(0, [0x01])),
    b(C, encodeR(0)), // ACK must echo next-expected N(R)=1
  ];
  const v = verifyCapture(cap);
  assert.equal(v.accepted, false);
  assert.equal(v.errorCode, ERROR_CODES.BAD_R_SEQ);
  assert.equal(v.errorBlock, 2);
});

test('R-block with wrong N(R) for NAK is rejected', () => {
  const cap = [
    b(R, encodeI(0, [0x01])),
    b(C, encodeR(1, true)), // NAK must reference outstanding N(S)=0
  ];
  const v = verifyCapture(cap);
  assert.equal(v.accepted, false);
  assert.equal(v.errorCode, ERROR_CODES.BAD_R_SEQ);
  assert.equal(v.errorBlock, 2);
});

test('R-block with no outstanding I-block is rejected', () => {
  const cap = [b(C, encodeR(1))];
  const v = verifyCapture(cap);
  assert.equal(v.accepted, false);
  assert.equal(v.errorCode, ERROR_CODES.R_WITHOUT_I);
  assert.equal(v.errorBlock, 1);
});

test('R-block with INF payload is rejected', () => {
  const cap = [
    b(R, encodeI(0, [0x01])),
    b(C, [0x12, 0x81, 0x01, 0x00, lrcFor([0x12, 0x81, 0x01, 0x00])]),
  ];
  const v = verifyCapture(cap);
  assert.equal(v.accepted, false);
  assert.equal(v.errorCode, ERROR_CODES.R_BAD_LENGTH);
  assert.equal(v.errorBlock, 2);
});

// ---------- layer-1 validation ----------

test('bad LRC is pinpointed at the offending raw block', () => {
  const cap = [
    b(R, encodeI(0, [0x01])),
    b(C, corruptLrc(encodeR(1))),
  ];
  const v = verifyCapture(cap);
  assert.equal(v.accepted, false);
  assert.equal(v.errorCode, ERROR_CODES.BAD_LRC);
  assert.equal(v.errorBlock, 2);
});

test('first LRC error is located even when a later block is also bad', () => {
  const cap = [
    b(R, encodeI(0, [0x01])),
    b(C, corruptLrc(encodeR(1))),
    b(R, corruptLrc(encodeI(1, [0x02]))),
  ];
  const v = verifyCapture(cap);
  assert.equal(v.errorCode, ERROR_CODES.BAD_LRC);
  assert.equal(v.errorBlock, 2);
});

test('short block is rejected at its index', () => {
  const v = verifyCapture([b(R, [0x12, 0x00])]);
  assert.equal(v.accepted, false);
  assert.equal(v.errorCode, ERROR_CODES.SHORT_BLOCK);
  assert.equal(v.errorBlock, 1);
});

test('reserved NAD and LEN are rejected', () => {
  let v = verifyCapture([b(R, [0xff, 0x00, 0x00, 0xff])]);
  assert.equal(v.errorCode, ERROR_CODES.NAD_OUT_OF_RANGE);
  assert.equal(v.errorBlock, 1);
  v = verifyCapture([b(R, [0x12, 0x00, 0xff, 0xed])]);
  assert.equal(v.errorCode, ERROR_CODES.LEN_RESERVED);
  assert.equal(v.errorBlock, 1);
});

test('INF span exceeding declared LEN is rejected', () => {
  // LEN says 1 INF byte but two are present before LRC
  const raw = [0x12, 0x00, 0x01, 0xaa, 0xbb, lrcFor([0x12, 0x00, 0x01, 0xaa, 0xbb])];
  const v = verifyCapture([b(R, raw)]);
  assert.equal(v.errorCode, ERROR_CODES.INF_OUT_OF_RANGE);
  assert.equal(v.errorBlock, 1);
});

test('malformed PCB reserved bits are rejected', () => {
  // I-block PCB 0x10 sets a reserved low bit; LRC is recomputed so the
  // failure is attributable to the PCB, not to a stale checksum.
  const raw = [0x12, 0x10, 0x00, lrcFor([0x12, 0x10, 0x00])];
  const v = verifyCapture([b(R, raw)]);
  assert.equal(v.accepted, false);
  assert.equal(v.errorCode, ERROR_CODES.I_RESERVED_BITS);
  assert.equal(v.errorBlock, 1);
});

// ---------- S-block: WTX / IFS ----------

test('matching WTX round trip allows subsequent blocks to proceed', () => {
  const cmd = [0x00, 0x84, 0x00, 0x00, 0x04];
  const cap = [
    b(C, encodeI(0, cmd)),
    b(R, encodeS('WTX', false, [5])),
    b(C, encodeS('WTX', true, [5])),
    b(R, encodeR(1)),
    b(R, encodeI(0, [0x90, 0x00])),
    b(C, encodeR(1)),
  ];
  const v = verifyCapture(cap);
  assert.equal(v.accepted, true, JSON.stringify(v));
  assert.equal(v.stats.wtxRoundTrips, 1);
  assert.equal(v.apdus.length, 2);
});

test('WTX response type mismatch (IFS answers WTX) is rejected', () => {
  const cap = [
    b(C, encodeI(0, [0x01])),
    b(R, encodeS('WTX', false, [3])),
    b(C, encodeS('IFS', true, [])), // wrong response type
  ];
  const v = verifyCapture(cap);
  assert.equal(v.accepted, false);
  assert.equal(v.errorCode, ERROR_CODES.S_TYPE_MISMATCH);
  assert.equal(v.errorBlock, 3);
});

test('WTX response multiplier mismatch is rejected at the response block', () => {
  const cap = [
    b(C, encodeI(0, [0x01])),
    b(R, encodeS('WTX', false, [3])),
    b(C, encodeS('WTX', true, [4])),
  ];
  const v = verifyCapture(cap);
  assert.equal(v.accepted, false);
  assert.equal(v.errorCode, ERROR_CODES.WTX_MULTIPLIER_MISMATCH);
  assert.equal(v.errorBlock, 3);
});

test('WTX response from the same direction is rejected', () => {
  const cap = [
    b(C, encodeI(0, [0x01])),
    b(R, encodeS('WTX', false, [3])),
    b(R, encodeS('WTX', true, [3])), // reader answers its own request
  ];
  const v = verifyCapture(cap);
  assert.equal(v.accepted, false);
  assert.equal(v.errorCode, ERROR_CODES.S_DIRECTION_MISMATCH);
  assert.equal(v.errorBlock, 3);
});

test('unsolicited WTX response is rejected', () => {
  const cap = [b(C, encodeS('WTX', true, [2]))];
  const v = verifyCapture(cap);
  assert.equal(v.errorCode, ERROR_CODES.S_UNSOLICITED_RESPONSE);
  assert.equal(v.errorBlock, 1);
});

test('WTX multiplier 0 is rejected', () => {
  const cap = [b(R, encodeS('WTX', false, [0]))];
  const v = verifyCapture(cap);
  assert.equal(v.errorCode, ERROR_CODES.BAD_WTX_MULTIPLIER);
  assert.equal(v.errorBlock, 1);
});

test('block while S request is pending is rejected', () => {
  const cap = [
    b(C, encodeI(0, [0x01])),
    b(R, encodeS('WTX', false, [3])),
    b(C, encodeI(1, [0x02])), // illegal: WTX unanswered
  ];
  const v = verifyCapture(cap);
  assert.equal(v.errorCode, ERROR_CODES.WTX_PENDING);
  assert.equal(v.errorBlock, 3);
});

test('R-block during a pending S exchange is rejected at the R-block', () => {
  const cap = [
    b(C, encodeI(0, [0x01])),
    b(R, encodeS('WTX', false, [3])),
    b(R, encodeR(1)), // illegal: WTX unanswered
  ];
  const v = verifyCapture(cap);
  assert.equal(v.accepted, false);
  assert.equal(v.errorCode, ERROR_CODES.WTX_PENDING);
  assert.equal(v.errorBlock, 3);
});

test('unanswered S request at capture end pins the request block', () => {
  const cap = [
    b(C, encodeI(0, [0x01])),
    b(R, encodeS('WTX', false, [3])),
    b(R, encodeR(1)),
  ];
  // First the pending violation at block 3 must surface; verify the
  // end-of-capture rule independently with only the request trailing.
  let v = verifyCapture(cap);
  assert.equal(v.errorBlock, 3);
  v = verifyCapture([b(R, encodeS('WTX', false, [3]))]);
  assert.equal(v.accepted, false);
  assert.equal(v.errorCode, ERROR_CODES.UNANSWERED_S_REQUEST);
  assert.equal(v.errorBlock, 1);
});

test('IFS request/response round trip passes', () => {
  const cap = [
    b(R, encodeS('IFS', false, [0xfe])),
    b(C, encodeS('IFS', true, [])),
    b(R, encodeI(0, [0x01])),
    b(C, encodeR(1)),
  ];
  const v = verifyCapture(cap);
  assert.equal(v.accepted, true, JSON.stringify(v));
  assert.equal(v.stats.ifsRoundTrips, 1);
  assert.equal(v.ifs.reader, 0xfe);
});

// ---------- impossible sequence advancement ----------

test('new I-block before acknowledgement is impossible advancement', () => {
  const cap = [
    b(R, encodeI(0, [0x01])),
    b(R, encodeI(1, [0x02])), // never ACKed
  ];
  const v = verifyCapture(cap);
  assert.equal(v.accepted, false);
  assert.equal(v.errorCode, ERROR_CODES.IMPOSSIBLE_SEQ);
  assert.equal(v.errorBlock, 2);
});

test('unacknowledged I-block at capture end pins that I-block', () => {
  const cap = [b(R, encodeI(0, [0x01]))];
  const v = verifyCapture(cap);
  assert.equal(v.accepted, false);
  assert.equal(v.errorCode, ERROR_CODES.UNACKED_I);
  assert.equal(v.errorBlock, 1);
});

test('capture size is capped at 64 blocks', () => {
  const tooMany = Array.from({ length: MAX_BLOCKS + 1 }, (_, k) =>
    b(k % 2 ? C : R, k % 2 ? encodeR(1) : encodeI(0, [1])),
  );
  const v = verifyCapture(tooMany);
  assert.equal(v.accepted, false);
  assert.equal(v.errorCode, 'TOO_MANY_BLOCKS');
});

// ---------- hex helpers ----------

test('parseHex accepts spaced hex and rejects odd/non-hex', () => {
  assert.deepEqual(parseHex('12 00 05'), [0x12, 0x00, 0x05]);
  assert.throws(() => parseHex('abc'));
  assert.throws(() => parseHex('zz'));
});

// ---------- frozen audit store ----------

function tmpStore() {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 't1-audit-')), 'audits.json');
  return new AuditStore({ file });
}

test('same audit id with same capture returns the original frozen verdict', () => {
  const store = tmpStore();
  const cap = [b(R, encodeI(0, [0x01])), b(C, encodeR(1))];
  const first = store.submit('AUDIT-1', cap, { reviewer: 'r1' });
  assert.equal(first.replayed, false);
  const frozenAt = first.record.frozenAt;
  const second = store.submit('AUDIT-1', cap.map((x) => ({ direction: x.direction, bytes: [...x.bytes] })));
  assert.equal(second.replayed, true);
  assert.equal(second.record, first.record);
  assert.equal(second.record.frozenAt, frozenAt);
});

test('changed block under same audit id conflicts and the original stays readable', () => {
  const store = tmpStore();
  const good = [b(R, encodeI(0, [0x01])), b(C, encodeR(1))];
  store.submit('AUDIT-2', good);
  const bad = [b(R, encodeI(0, [0x02])), b(C, encodeR(1))];
  assert.throws(() => store.submit('AUDIT-2', bad), ConflictError);
  const rec = store.get('AUDIT-2');
  assert.equal(rec.verdict.accepted, true);
  assert.equal(rec.capture.blocks[0].hex, toHex(encodeI(0, [0x01])));
});

test('invalid capture is still frozen as a rejection verdict', () => {
  const store = tmpStore();
  const { record } = store.submit('AUDIT-3', [b(R, corruptLrc(encodeI(0, [0x01]))) ]);
  assert.equal(record.verdict.accepted, false);
  assert.equal(record.verdict.errorCode, ERROR_CODES.BAD_LRC);
  // resubmit identical -> same frozen rejection
  const again = store.submit('AUDIT-3', [b(R, corruptLrc(encodeI(0, [0x01])))]);
  assert.equal(again.replayed, true);
});

test('frozen records survive a store reload from disk', () => {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 't1-audit-')), 'audits.json');
  const store1 = new AuditStore({ file });
  store1.submit('AUDIT-4', [b(R, encodeI(0, [0x77])), b(C, encodeR(1))]);
  const store2 = new AuditStore({ file });
  const rec = store2.get('AUDIT-4');
  assert.ok(rec);
  assert.equal(rec.verdict.accepted, true);
});

test('store enforces the 64 block cap and validates directions', () => {
  const store = tmpStore();
  assert.throws(() => store.submit('X', []));
  assert.throws(() => store.submit('X', [{ direction: 'bogus', hex: '12000012' }]));
  assert.throws(() => store.submit('X', [{ direction: 'reader', hex: 'zzz' }]));
});
