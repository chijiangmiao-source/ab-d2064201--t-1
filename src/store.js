'use strict';

// Frozen audit store.
//
// Rule set:
//   * Same audit id + identical capture  -> the original frozen verdict is
//     returned (idempotent retransmission of a review submission).
//   * Same audit id + any changed block   -> 409-style conflict; the original
//     frozen verdict stays readable and is never overwritten.
//   * Verdicts are immutable once frozen and are persisted to disk so the
//     process can be restarted without losing audit evidence.

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { verifyCapture, parseHex, MAX_BLOCKS } = require('./protocol');

class ConflictError extends Error {
  constructor(existing) {
    super(`audit id conflict: capture differs from the frozen submission`);
    this.code = 'AUDIT_CONFLICT';
    this.existing = existing;
  }
}

function canonicalCaptureHash(blocks) {
  const h = crypto.createHash('sha256');
  h.update(`v1|${blocks.length}\n`);
  for (const b of blocks) {
    h.update(`${b.direction}:`);
    h.update(Buffer.from(b.bytes));
    h.update('\n');
  }
  return h.digest('hex');
}

function normalizeBlocks(input) {
  if (!Array.isArray(input)) {
    const err = new Error('blocks must be an array of {direction, hex|bytes}');
    err.code = 'BAD_REQUEST';
    throw err;
  }
  if (input.length === 0) {
    const err = new Error('capture contains no blocks');
    err.code = 'BAD_REQUEST';
    throw err;
  }
  if (input.length > MAX_BLOCKS) {
    const err = new Error(`at most ${MAX_BLOCKS} blocks may be recorded`);
    err.code = 'BAD_REQUEST';
    throw err;
  }
  return input.map((raw, idx) => {
    if (!raw || (raw.direction !== 'reader' && raw.direction !== 'card')) {
      const err = new Error(`block #${idx + 1}: direction must be "reader" or "card"`);
      err.code = 'BAD_REQUEST';
      throw err;
    }
    let bytes;
    if (Array.isArray(raw.bytes)) {
      if (raw.bytes.some((v) => !Number.isInteger(v) || v < 0 || v > 255)) {
        const err = new Error(`block #${idx + 1}: bytes must be integers 0..255`);
        err.code = 'BAD_REQUEST';
        throw err;
      }
      bytes = [...raw.bytes];
    } else if (typeof raw.hex === 'string') {
      try {
        bytes = parseHex(raw.hex);
      } catch (e) {
        const err = new Error(`block #${idx + 1}: ${e.message}`);
        err.code = 'BAD_REQUEST';
        throw err;
      }
    } else {
      const err = new Error(`block #${idx + 1}: provide hex string or byte array`);
      err.code = 'BAD_REQUEST';
      throw err;
    }
    return { direction: raw.direction, bytes };
  });
}

class AuditStore {
  constructor({ file } = {}) {
    this.file = file || null;
    this.records = new Map();
    if (this.file) this._load();
  }

  _load() {
    try {
      const txt = fs.readFileSync(this.file, 'utf8');
      const doc = JSON.parse(txt);
      for (const rec of doc.records || []) this.records.set(rec.auditId, rec);
    } catch (e) {
      if (e.code !== 'ENOENT') throw e;
    }
  }

  _persist() {
    if (!this.file) return;
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    const tmp = `${this.file}.tmp-${process.pid}`;
    fs.writeFileSync(tmp, JSON.stringify({ version: 1, records: [...this.records.values()] }, null, 2));
    fs.renameSync(tmp, this.file);
  }

  has(auditId) {
    return this.records.has(auditId);
  }

  get(auditId) {
    return this.records.get(auditId) || null;
  }

  list() {
    return [...this.records.values()].map((r) => ({
      auditId: r.auditId,
      frozenAt: r.frozenAt,
      accepted: r.verdict.accepted,
      errorCode: r.verdict.errorCode,
      errorBlock: r.verdict.errorBlock,
      blockCount: r.capture.blocks.length,
      captureHash: r.capture.hash,
    }));
  }

  // Freeze a review submission. Idempotent for identical re-submission;
  // throws ConflictError when any raw block differs.
  submit(auditId, rawBlocks, meta = {}) {
    if (typeof auditId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(auditId)) {
      const err = new Error('auditId is required (1..64 chars: letters, digits, . _ -)');
      err.code = 'BAD_REQUEST';
      throw err;
    }
    const blocks = normalizeBlocks(rawBlocks);
    const hash = canonicalCaptureHash(blocks);
    const existing = this.records.get(auditId);
    if (existing) {
      if (existing.capture.hash === hash) {
        return { record: existing, replayed: true };
      }
      throw new ConflictError(existing);
    }

    const verdict = verifyCapture(blocks);
    const record = {
      auditId,
      frozenAt: new Date().toISOString(),
      reviewer: meta.reviewer || null,
      capture: {
        hash,
        blocks: blocks.map((b) => ({ direction: b.direction, hex: bytesToHex(b.bytes) })),
      },
      verdict,
    };
    this.records.set(auditId, record);
    this._persist();
    return { record, replayed: false };
  }
}

function bytesToHex(bytes) {
  return bytes.map((b) => b.toString(16).padStart(2, '0').toUpperCase()).join('');
}

module.exports = { AuditStore, ConflictError, canonicalCaptureHash, normalizeBlocks };
