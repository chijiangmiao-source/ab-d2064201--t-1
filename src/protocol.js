'use strict';

// ISO/IEC 7816-3 T=1 block verification core.
//
// A captured raw block has the shape:
//   { direction: 'reader' | 'card', bytes: number[] }
// Wire layout of one block: NAD | PCB | LEN | INF(LEN bytes) | LRC
// LRC is the XOR of every byte from NAD through the last INF byte.
//
// PCB byte values / masks (matching ISO/IEC 7816-3 and e.g. OpenSC framing):
//   I-block: class bits 00; N(S) mask 0x40; chaining M mask 0x20; low 5 zero
//   R-block: 0x80 class; fixed-zero mask 0x20; N(R) mask 0x10;
//            low bits 0x0E reserved zero; error/NAK bit 0x01
//   S-block: 0xC0 class; response mask 0x20 (request/response);
//            0x10 reserved zero; type low nibble: 0x1=IFS, 0x3=WTX

const ERROR_CODES = Object.freeze({
  SHORT_BLOCK: 'SHORT_BLOCK',
  NAD_OUT_OF_RANGE: 'NAD_OUT_OF_RANGE',
  LEN_RESERVED: 'LEN_RESERVED',
  INF_OUT_OF_RANGE: 'INF_OUT_OF_RANGE',
  BAD_LRC: 'BAD_LRC',
  BAD_PCB: 'BAD_PCB',
  I_RESERVED_BITS: 'I_RESERVED_BITS',
  R_BAD_LENGTH: 'R_BAD_LENGTH',
  R_RESERVED_BITS: 'R_RESERVED_BITS',
  S_BAD_LENGTH: 'S_BAD_LENGTH',
  S_RESERVED_BITS: 'S_RESERVED_BITS',
  S_UNKNOWN_TYPE: 'S_UNKNOWN_TYPE',
  STALE_DUP: 'STALE_DUP',
  DUP_MISMATCH: 'DUP_MISMATCH',
  IMPOSSIBLE_SEQ: 'IMPOSSIBLE_SEQ',
  BAD_R_SEQ: 'BAD_R_SEQ',
  R_WITHOUT_I: 'R_WITHOUT_I',
  WTX_PENDING: 'WTX_PENDING',
  BAD_WTX_MULTIPLIER: 'BAD_WTX_MULTIPLIER',
  BAD_IFS_VALUE: 'BAD_IFS_VALUE',
  S_UNSOLICITED_RESPONSE: 'S_UNSOLICITED_RESPONSE',
  S_DIRECTION_MISMATCH: 'S_DIRECTION_MISMATCH',
  S_TYPE_MISMATCH: 'S_TYPE_MISMATCH',
  WTX_MULTIPLIER_MISMATCH: 'WTX_MULTIPLIER_MISMATCH',
  UNANSWERED_S_REQUEST: 'UNANSWERED_S_REQUEST',
  UNACKED_I: 'UNACKED_I',
});

const DIRS = ['reader', 'card'];
const MAX_BLOCKS = 64;

function lrcFor(bytes) {
  let lrc = 0;
  for (const b of bytes) lrc ^= b;
  return lrc & 0xff;
}

function parseHex(line) {
  if (typeof line !== 'string') {
    const err = new Error('hex payload must be a string');
    err.code = 'BAD_HEX';
    throw err;
  }
  const clean = line.replace(/\s+/g, '').toUpperCase();
  if (clean.length === 0 || clean.length % 2 !== 0 || /[^0-9A-F]/.test(clean)) {
    const err = new Error(`invalid hexadecimal block: "${line}"`);
    err.code = 'BAD_HEX';
    throw err;
  }
  const out = [];
  for (let i = 0; i < clean.length; i += 2) out.push(parseInt(clean.slice(i, i + 2), 16));
  return out;
}

function decodePcb(pcb) {
  if ((pcb & 0x80) === 0x00) {
    // I-block: b8=0; N(S) mask 0x40; chaining M mask 0x20; low 5 bits zero
    if (pcb & 0x1f) return { kind: 'I', error: ERROR_CODES.I_RESERVED_BITS };
    return { kind: 'I', ns: (pcb >> 6) & 1, chained: !!(pcb & 0x20) };
  }
  if ((pcb & 0xc0) === 0x80) {
    // R-block: b8=1,b7=0; fixed-zero mask 0x20; N(R) mask 0x10;
    // low bits 0x0E reserved zero; error/NAK bit 0x01
    if (pcb & 0x2e) return { kind: 'R', error: ERROR_CODES.R_RESERVED_BITS };
    return { kind: 'R', nr: (pcb >> 4) & 1, nak: !!(pcb & 0x01) };
  }
  // S-block: b8=1,b7=1; response mask 0x20; 0x10 reserved zero;
  // type low nibble: 0x1=IFS, 0x3=WTX
  if (pcb & 0x10) return { kind: 'S', error: ERROR_CODES.S_RESERVED_BITS };
  const response = !!(pcb & 0x20);
  const t = pcb & 0x0f;
  if (t !== 0x01 && t !== 0x03) return { kind: 'S', error: ERROR_CODES.S_UNKNOWN_TYPE };
  return { kind: 'S', response, sType: t === 0x03 ? 'WTX' : 'IFS' };
}

// ---- frame builders (used by tests and by tooling; keep LRC canonical) ----
function frame(nad, pcb, inf = []) {
  const body = [nad, pcb, inf.length, ...inf];
  return [...body, lrcFor(body)];
}
const encodeI = (ns, inf, chained = false, nad = 0x12) =>
  frame(nad, ((ns & 1) << 6) | (chained ? 0x20 : 0x00), inf);
const encodeR = (nr, nak = false, nad = 0x12) =>
  frame(nad, 0x80 | ((nr & 1) << 4) | (nak ? 0x01 : 0x00));
const encodeS = (sType, response, inf, nad = 0x12) => {
  const t = sType === 'WTX' ? 0x03 : 0x01;
  return frame(nad, 0xc0 | (response ? 0x20 : 0x00) | t, inf);
};
const toHex = (bytes) => bytes.map((b) => b.toString(16).padStart(2, '0').toUpperCase()).join('');

function newSide() {
  return {
    vS: 0, // N(S) of the next NEW I-block (flips each time a fresh I-block is sent)
    unack: null, // { ns, chained, lastInf } latest unacknowledged I-block
    chain: null, // { start, infs:[bytes], blockSeqs:[number] } chain in progress
  };
}

function snapshotOf(sides, pending, step) {
  const snap = { step, pending: null, reader: {}, card: {} };
  for (const d of DIRS) {
    const s = sides[d];
    snap[d] = {
      sendSeq: s.vS,
      unackedNs: s.unack ? s.unack.ns : null,
      chained: s.chain ? s.chain.infs.length : 0,
      waitingExtension: pending ? pending.from === d : false,
    };
  }
  if (pending) {
    snap.pending = {
      type: pending.type,
      from: pending.from,
      multiplier: pending.type === 'WTX' ? pending.inf[0] : null,
      ifs: pending.type === 'IFS' ? pending.inf[0] : null,
      sinceBlock: pending.at,
    };
  }
  return snap;
}

function fail(index, code, reason, block, steps, sides, pending) {
  return {
    accepted: false,
    errorCode: code,
    errorReason: reason,
    errorBlock: index + 1, // 1-based index of the first offending raw block
    errorBlockHex: block ? toHex(block.bytes) : null,
    apdus: [],
    steps,
    finalSnapshot: snapshotOf(sides, pending, steps.length),
  };
}

/**
 * Verify an ordered capture of directional T=1 raw blocks.
 * Returns a frozen verdict-shaped object; every rejection pinpoints the first
 * raw block (1-based `errorBlock`) responsible for the failure.
 */
function verifyCapture(blocks) {
  const sides = { reader: newSide(), card: newSide() };
  const steps = [];
  const apdus = [];
  let pending = null; // outstanding S request { type, from, inf, at }
  let ifsReader = null;
  let ifsCard = null;

  if (!Array.isArray(blocks)) throw new TypeError('blocks must be an array');
  if (blocks.length === 0) {
    return {
      accepted: false,
      errorCode: 'EMPTY_CAPTURE',
      errorReason: 'capture contains no blocks',
      errorBlock: 0,
      errorBlockHex: null,
      apdus: [],
      steps: [],
      finalSnapshot: snapshotOf(sides, null, 0),
    };
  }
  if (blocks.length > MAX_BLOCKS) {
    return {
      accepted: false,
      errorCode: 'TOO_MANY_BLOCKS',
      errorReason: `capture exceeds ${MAX_BLOCKS} blocks`,
      errorBlock: 0,
      errorBlockHex: null,
      apdus: [],
      steps: [],
      finalSnapshot: snapshotOf(sides, null, 0),
    };
  }

  for (let i = 0; i < blocks.length; i += 1) {
    const b = blocks[i];
    const dir = b.direction;
    const peer = sides[dir === 'reader' ? 'card' : 'reader'];
    const side = sides[dir];
    const bytes = b.bytes;
    const baseStep = {
      seq: i + 1,
      direction: dir,
      raw: toHex(bytes),
      retransmitBasis: null,
      note: '',
    };

    // ---- layer-1 framing validation: NAD, LEN, INF span, LRC ----
    if (bytes.length < 4) {
      steps.push({ ...baseStep, kind: 'INVALID', detail: 'block shorter than NAD/PCB/LEN/LRC' });
      return fail(i, ERROR_CODES.SHORT_BLOCK, 'block shorter than 4 bytes', b, steps, sides, pending);
    }
    const [nad, pcb, len, ...rest] = bytes;
    if (nad > 0xfe) {
      steps.push({ ...baseStep, kind: 'INVALID', detail: `NAD=0x${nad.toString(16)}` });
      return fail(i, ERROR_CODES.NAD_OUT_OF_RANGE, `NAD 0x${toHex([nad])} is reserved`, b, steps, sides, pending);
    }
    if (len > 0xfe) {
      steps.push({ ...baseStep, kind: 'INVALID', detail: `LEN=0x${len.toString(16)}` });
      return fail(i, ERROR_CODES.LEN_RESERVED, 'LEN byte 0xFF is reserved', b, steps, sides, pending);
    }
    if (rest.length !== len + 1) {
      steps.push({
        ...baseStep,
        kind: 'INVALID',
        detail: `declared LEN=${len}, present INF+LRC=${rest.length}, need ${len + 1}`,
      });
      return fail(
        i,
        ERROR_CODES.INF_OUT_OF_RANGE,
        `INF length out of range: declared ${len}, present ${rest.length - 1}`,
        b,
        steps,
        sides,
        pending,
      );
    }
    const inf = rest.slice(0, len);
    const lrc = rest[len];
    if (lrcFor([nad, pcb, len, ...inf]) !== lrc) {
      steps.push({
        ...baseStep,
        kind: 'INVALID',
        detail: `LRC mismatch: carried 0x${toHex([lrc])}, computed 0x${toHex([lrcFor([nad, pcb, len, ...inf])])}`,
      });
      return fail(i, ERROR_CODES.BAD_LRC, 'longitudinal redundancy check failed', b, steps, sides, pending);
    }

    const pcbInfo = decodePcb(pcb);
    if (pcbInfo.error) {
      steps.push({ ...baseStep, kind: 'INVALID', pcb: toHex([pcb]), detail: pcbInfo.error });
      return fail(i, pcbInfo.error, `PCB 0x${toHex([pcb])} violates reserved bit rules`, b, steps, sides, pending);
    }

    if (pcbInfo.kind === 'I') {
      if (pending) {
        steps.push({ ...baseStep, kind: 'I', detail: 'I-block while S request unanswered' });
        return fail(
          i,
          ERROR_CODES.WTX_PENDING,
          `${pending.type} request from ${pending.from} is waiting for its response`,
          b,
          steps,
          sides,
          pending,
        );
      }
      const { ns, chained } = pcbInfo;
      let duplicate = false;
      if (side.unack && side.unack.ns === ns) {
        // Retransmission of the most recent unacknowledged I-block (typically
        // requested by a preceding R-NAK). The payload must be identical and
        // it must NOT be concatenated into the APDU a second time.
        if (
          side.unack.chained !== chained ||
          side.unack.lastInf.length !== inf.length ||
          side.unack.lastInf.some((v, k) => v !== inf[k])
        ) {
          steps.push({ ...baseStep, kind: 'I', ns, chained, detail: 'same N(S) reused with different payload' });
          return fail(
            i,
            ERROR_CODES.DUP_MISMATCH,
            `N(S)=${ns} retransmission carries different data than the outstanding block`,
            b,
            steps,
            sides,
            pending,
          );
        }
        duplicate = true;
      } else if (side.unack) {
        steps.push({
          ...baseStep,
          kind: 'I',
          ns,
          chained,
          detail: `new N(S)=${ns} while N(S)=${side.unack.ns} is still unacknowledged`,
        });
        return fail(
          i,
          ERROR_CODES.IMPOSSIBLE_SEQ,
          `impossible sequence advancement: N(S)=${ns} sent before N(S)=${side.unack.ns} was acknowledged`,
          b,
          steps,
          sides,
          pending,
        );
      } else if (ns !== side.vS) {
        steps.push({ ...baseStep, kind: 'I', ns, chained, detail: `expected N(S)=${side.vS}` });
        return fail(
          i,
          ERROR_CODES.STALE_DUP,
          `unexpected N(S)=${ns}, expected ${side.vS}: duplicate of a block that is not the recent unacknowledged one`,
          b,
          steps,
          sides,
          pending,
        );
      }

      if (!duplicate) {
        if (!side.chain) side.chain = { start: i, infs: [], seqs: [] };
        side.chain.infs.push(inf);
        side.chain.seqs.push(i + 1);
        side.unack = { ns, chained, lastInf: inf };
        side.vS ^= 1; // V(S) advances when a fresh I-block is sent
      }

      steps.push({
        ...baseStep,
        kind: 'I',
        ns,
        chained,
        duplicate,
        retransmitBasis: duplicate ? 'I-DUP (retransmission of latest unacknowledged I-block)' : null,
        detail: duplicate
          ? `legal duplicate N(S)=${ns}, payload not concatenated again`
          : `I-block N(S)=${ns}${chained ? ' (chained, more follows)' : ''}`,
        snapshot: snapshotOf(sides, pending, i + 1),
      });
    } else if (pcbInfo.kind === 'R') {
      if (len !== 0) {
        steps.push({ ...baseStep, kind: 'R', detail: 'R-block must carry no INF' });
        return fail(i, ERROR_CODES.R_BAD_LENGTH, 'R-block INF length must be 0', b, steps, sides, pending);
      }
      if (pending) {
        steps.push({ ...baseStep, kind: 'R', detail: 'R-block while S request unanswered' });
        return fail(
          i,
          ERROR_CODES.WTX_PENDING,
          `${pending.type} request from ${pending.from} is waiting for its response`,
          b,
          steps,
          sides,
          pending,
        );
      }
      const { nr, nak } = pcbInfo;
      if (!peer.unack) {
        steps.push({ ...baseStep, kind: 'R', nr, nak, detail: 'R-block with no outstanding I-block' });
        return fail(i, ERROR_CODES.R_WITHOUT_I, `R-block N(R)=${nr} acknowledges nothing`, b, steps, sides, pending);
      }
      const expected = nak ? peer.unack.ns : peer.vS;
      if (nr !== expected) {
        steps.push({ ...baseStep, kind: 'R', nr, nak, detail: `expected N(R)=${expected}` });
        return fail(
          i,
          ERROR_CODES.BAD_R_SEQ,
          `R-block carries N(R)=${nr}, expected ${expected} for ${nak ? 'retransmission (NAK)' : 'acknowledgement'}`,
          b,
          steps,
          sides,
          pending,
        );
      }

      if (nak) {
        steps.push({
          ...baseStep,
          kind: 'R',
          nr,
          nak: true,
          retransmitBasis: `R-NAK N(R)=${nr} requests retransmission of N(S)=${nr}`,
          detail: `error retransmission request for the latest unacknowledged N(S)=${nr}; send state retained`,
          snapshot: snapshotOf(sides, pending, i + 1),
        });
      } else {
        const acked = peer.unack;
        if (!acked.chained) {
          // M=0 closes the chain (single block or last chained block): APDU complete.
          const infs = peer.chain ? peer.chain.infs : [acked.lastInf];
          const seqs = peer.chain ? peer.chain.seqs : [i];
          apdus.push({
            direction: dir === 'reader' ? 'card' : 'reader',
            hex: toHex(infs.flat()),
            blocks: seqs, // 1-based raw-block seqs carrying this APDU
            chained: infs.length > 1,
          });
          peer.chain = null;
        }
        peer.unack = null;
        steps.push({
          ...baseStep,
          kind: 'R',
          nr,
          nak: false,
          retransmitBasis: null,
          detail: acked.chained
            ? `acknowledges chained N(S)=${nr}; chain continues (next fresh N(S)=${peer.vS})`
            : `acknowledges final N(S)=${nr}; APDU assembled; next fresh N(S)=${peer.vS}`,
          snapshot: snapshotOf(sides, pending, i + 1),
        });
      }
    } else {
      // S-block (IFS / WTX request and response)
      const { response, sType } = pcbInfo;
      if (sType === 'WTX' && len !== 1) {
        steps.push({ ...baseStep, kind: 'S', sType, response, detail: 'WTX requires exactly one INF byte' });
        return fail(i, ERROR_CODES.S_BAD_LENGTH, 'WTX S-block INF length must be 1', b, steps, sides, pending);
      }
      if (sType === 'IFS' && len !== (response ? 0 : 1)) {
        steps.push({ ...baseStep, kind: 'S', sType, response, detail: 'IFS request LEN=1, response LEN=0' });
        return fail(i, ERROR_CODES.S_BAD_LENGTH, 'IFS S-block has illegal length', b, steps, sides, pending);
      }

      if (!response) {
        if (pending) {
          steps.push({ ...baseStep, kind: 'S', sType, response, detail: 'request while another S request is pending' });
          return fail(
            i,
            ERROR_CODES.WTX_PENDING,
            `${pending.type} request from ${pending.from} has not been answered yet`,
            b,
            steps,
            sides,
            pending,
          );
        }
        if (sType === 'WTX' && (inf[0] < 1 || inf[0] > 255)) {
          steps.push({ ...baseStep, kind: 'S', sType, response, detail: `multiplier=${inf[0]}` });
          return fail(i, ERROR_CODES.BAD_WTX_MULTIPLIER, 'WTX multiplier must be in 1..255', b, steps, sides, pending);
        }
        if (sType === 'IFS' && (inf[0] < 1 || inf[0] > 254)) {
          steps.push({ ...baseStep, kind: 'S', sType, response, detail: `IFS=${inf[0]}` });
          return fail(i, ERROR_CODES.BAD_IFS_VALUE, 'IFS value must be in 1..254', b, steps, sides, pending);
        }
        pending = { type: sType, from: dir, inf, at: i };
        steps.push({
          ...baseStep,
          kind: 'S',
          sType,
          response: false,
          detail:
            sType === 'WTX'
              ? `WTX request, multiplier=${inf[0]}; waiting for response`
              : `IFS request, IFSC=${inf[0]}; waiting for response`,
          snapshot: snapshotOf(sides, pending, i + 1),
        });
      } else {
        if (!pending) {
          steps.push({ ...baseStep, kind: 'S', sType, response: true, detail: 'response without request' });
          return fail(i, ERROR_CODES.S_UNSOLICITED_RESPONSE, `${sType} response has no matching request`, b, steps, sides, pending);
        }
        if (pending.from === dir) {
          steps.push({ ...baseStep, kind: 'S', sType, response: true, detail: 'response came from the requesting direction' });
          return fail(i, ERROR_CODES.S_DIRECTION_MISMATCH, 'S response must come from the opposite direction', b, steps, sides, pending);
        }
        const expectedDir = pending.from === 'reader' ? 'card' : 'reader';
        if (dir !== expectedDir) {
          steps.push({ ...baseStep, kind: 'S', sType, response: true, detail: `expected from ${expectedDir}` });
          return fail(i, ERROR_CODES.S_DIRECTION_MISMATCH, `S response direction mismatch`, b, steps, sides, pending);
        }
        if (pending.type !== sType) {
          steps.push({
            ...baseStep,
            kind: 'S',
            sType,
            response: true,
            detail: `request was ${pending.type}`,
          });
          return fail(i, ERROR_CODES.S_TYPE_MISMATCH, `${pending.type} request answered with ${sType} response`, b, steps, sides, pending);
        }
        if (sType === 'WTX' && inf[0] !== pending.inf[0]) {
          steps.push({
            ...baseStep,
            kind: 'S',
            sType,
            response: true,
            detail: `multiplier reply=${inf[0]}, request=${pending.inf[0]}`,
          });
          return fail(i, ERROR_CODES.WTX_MULTIPLIER_MISMATCH, 'WTX response multiplier does not match the request', b, steps, sides, pending);
        }
        if (sType === 'IFS') {
          if (pending.from === 'card') ifsCard = pending.inf[0];
          else ifsReader = pending.inf[0];
        }
        const completed = pending;
        pending = null;
        steps.push({
          ...baseStep,
          kind: 'S',
          sType,
          response: true,
          detail:
            sType === 'WTX'
              ? `WTX response multiplier=${inf[0]} matches; processing may continue`
              : `IFS response confirms IFSC=${completed.inf[0]}; processing may continue`,
          snapshot: snapshotOf(sides, pending, i + 1),
        });
      }
    }
  }

  if (pending) {
    return fail(
      pending.at,
      ERROR_CODES.UNANSWERED_S_REQUEST,
      `${pending.type} request from ${pending.from} never received its response`,
      blocks[pending.at],
      steps,
      sides,
      pending,
    );
  }
  for (const d of DIRS) {
    if (sides[d].unack) {
      const idx = findLastOutstandingIndex(blocks, d, sides[d].unack.ns);
      return fail(
        idx,
        ERROR_CODES.UNACKED_I,
        `${d} I-block N(S)=${sides[d].unack.ns} was never acknowledged`,
        blocks[idx],
        steps,
        sides,
        pending,
      );
    }
  }

  return {
    accepted: true,
    errorCode: null,
    errorReason: null,
    errorBlock: null,
    errorBlockHex: null,
    apdus,
    steps,
    ifs: { reader: ifsReader, card: ifsCard },
    finalSnapshot: snapshotOf(sides, null, blocks.length),
    stats: {
      blocks: blocks.length,
      completeApdus: apdus.length,
      retransmissions: steps.filter((s) => s.retransmitBasis).length,
      wtxRoundTrips: steps.filter((s) => s.kind === 'S' && s.sType === 'WTX' && s.response === true).length,
      ifsRoundTrips: steps.filter((s) => s.kind === 'S' && s.sType === 'IFS' && s.response === true).length,
    },
  };
}

function findLastOutstandingIndex(blocks, dir, ns) {
  for (let k = blocks.length - 1; k >= 0; k -= 1) {
    const b = blocks[k];
    if (b.direction !== dir || b.bytes.length < 3) continue;
    const info = decodePcb(b.bytes[1]);
    if (info.kind === 'I' && info.ns === ns) return k;
  }
  return blocks.length - 1;
}

module.exports = {
  MAX_BLOCKS,
  ERROR_CODES,
  DIRS,
  lrcFor,
  parseHex,
  decodePcb,
  encodeI,
  encodeR,
  encodeS,
  frame,
  toHex,
  verifyCapture,
};
