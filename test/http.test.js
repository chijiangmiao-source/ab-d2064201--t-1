'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');

const { createServer } = require('../src/server');
const { AuditStore } = require('../src/store');
const { encodeI, encodeR, encodeS } = require('../src/protocol');

let server;
let base;

function rb(direction, bytes) {
  return { direction, hex: bytes.map((x) => x.toString(16).padStart(2, '0').toUpperCase()).join('') };
}

before(async () => {
  server = createServer({ store: new AuditStore({}) });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
});

test('GET /health reports ok', async () => {
  const res = await fetch(`${base}/health`);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.status, 'ok');
  assert.equal(typeof body.frozenAudits, 'number');
});

test('page is served and loads the API client', async () => {
  const res = await fetch(`${base}/`);
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.match(html, /T=1/);
  const js = await fetch(`${base}/app.js`);
  assert.equal(js.status, 200);
});

test('freeze, replay, conflict and original-still-readable cycle', async () => {
  const good = [
    rb('reader', encodeI(0, [0x00, 0xa4, 0x04, 0x00, 0x02, 0x3f, 0x00])),
    rb('card', encodeR(1)),
  ];
  let res = await fetch(`${base}/api/audits/HTTP-1`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ reviewer: 'tester', blocks: good }),
  });
  assert.equal(res.status, 201);
  const first = await res.json();
  assert.equal(first.record.verdict.accepted, true);
  assert.equal(first.record.verdict.apdus.length, 1);

  // identical retransmission -> original frozen result
  res = await fetch(`${base}/api/audits/HTTP-1`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ blocks: good }),
  });
  assert.equal(res.status, 200);
  const replay = await res.json();
  assert.equal(replay.replayed, true);
  assert.equal(replay.record.frozenAt, first.record.frozenAt);

  // changed block -> conflict
  const changed = [
    rb('reader', encodeI(0, [0x00, 0xa4, 0x04, 0x00, 0x02, 0x3f, 0x01])),
    rb('card', encodeR(1)),
  ];
  res = await fetch(`${base}/api/audits/HTTP-1`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ blocks: changed }),
  });
  assert.equal(res.status, 409);
  const conflict = await res.json();
  assert.equal(conflict.error, 'AUDIT_CONFLICT');
  assert.equal(conflict.existing.capture.blocks[0].hex, good[0].hex);

  // original result still readable, untouched
  res = await fetch(`${base}/api/audits/HTTP-1`);
  assert.equal(res.status, 200);
  const stored = await res.json();
  assert.equal(stored.capture.blocks[0].hex, good[0].hex);
  assert.equal(stored.frozenAt, first.record.frozenAt);
});

test('illegal WTX answer is frozen as a rejection pinned at the response block', async () => {
  const cap = [
    rb('card', encodeI(0, [0x01])),
    rb('reader', encodeS('WTX', false, [3])),
    rb('card', encodeS('WTX', true, [9])), // multiplier mismatch
  ];
  const res = await fetch(`${base}/api/audits/HTTP-BAD-WTX`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ blocks: cap }),
  });
  assert.equal(res.status, 201); // rejection is still frozen, not an HTTP error
  const { record } = await res.json();
  assert.equal(record.verdict.accepted, false);
  assert.equal(record.verdict.errorCode, 'WTX_MULTIPLIER_MISMATCH');
  assert.equal(record.verdict.errorBlock, 3);
});

test('bad request shapes return 400 and unknown audit returns 404', async () => {
  let res = await fetch(`${base}/api/audits/HTTP-X`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ blocks: [] }),
  });
  assert.equal(res.status, 400);

  res = await fetch(`${base}/api/audits/HTTP-X`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ blocks: [{ direction: 'reader', hex: 'zz' }] }),
  });
  assert.equal(res.status, 400);

  res = await fetch(`${base}/api/audits/does-not-exist`);
  assert.equal(res.status, 404);

  res = await fetch(`${base}/api/audits`);
  assert.equal(res.status, 200);
  const list = await res.json();
  assert.ok(Array.isArray(list.audits));
});
