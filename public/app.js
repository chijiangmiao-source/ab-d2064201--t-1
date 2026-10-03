'use strict';

// Thin review-station client: inputs are collected here, but every verdict,
// APDU, per-step sequence and snapshot rendered below comes from the API.

const $ = (id) => document.getElementById(id);

function lrc(bs) { let x = 0; for (const b of bs) x ^= b; return x & 0xff; }
function frame(nad, pcb, inf = []) { const body = [nad, pcb, inf.length, ...inf]; return [...body, lrc(body)]; }
function hex(bs) { return bs.map((b) => b.toString(16).padStart(2, '0').toUpperCase()).join(''); }
function iBlock(ns, inf, m = false) { return frame(0x12, (ns << 6) | (m ? 0x20 : 0), inf); }
function rBlock(nr, nak = false) { return frame(0x12, 0x80 | (nr << 4) | (nak ? 1 : 0)); }
// explicit S encoders (keep PCB bit rules obvious)
function wtxReq(mult) { return frame(0x12, 0xc0, [mult]); }
function wtxResp(mult) { return frame(0x12, 0xe0, [mult]); }

function buildSample() {
  // Legal scenario: command I(0) -> R-NAK -> legal duplicate I(0) ->
  // card WTX round-trip -> R-ACK, then response I(0) [9000] -> R-ACK.
  const cmd = [0x00, 0xa4, 0x04, 0x00, 0x02, 0x3f, 0x00];
  const lines = [
    `reader: ${hex(iBlock(0, cmd))}`,
    `card:   ${hex(rBlock(0, true))}`,
    `reader: ${hex(iBlock(0, cmd))}`,
    `card:   ${hex(wtxReq(3))}`,
    `reader: ${hex(wtxResp(3))}`,
    `card:   ${hex(rBlock(1, false))}`,
    `card:   ${hex(iBlock(0, [0x90, 0x00]))}`,
    `reader: ${hex(rBlock(1, false))}`,
  ];
  return lines.join('\n');
}

function parseCapture(text) {
  const blocks = [];
  const errors = [];
  text.split('\n').forEach((line, idx) => {
    const s = line.trim();
    if (!s || s.startsWith('#')) return;
    const m = s.match(/^(reader|card)\s*:\s*([0-9a-fA-F\s]+)$/);
    if (!m) { errors.push(`第 ${idx + 1} 行格式非法（应为 reader|card: 十六进制）`); return; }
    const h = m[2].replace(/\s+/g, '').toUpperCase();
    if (h.length % 2 || /[^0-9A-F]/.test(h)) { errors.push(`第 ${idx + 1} 行不是偶数位十六进制`); return; }
    blocks.push({ direction: m[1], hex: h });
  });
  return { blocks, errors };
}

function setBanner(kind, msg) {
  const el = $('banner');
  el.className = kind || '';
  el.textContent = msg || '';
}

async function api(method, url, body) {
  const res = await fetch(url, {
    method,
    headers: { 'content-type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  let json = null;
  try { json = await res.json(); } catch { /* non-json */ }
  return { status: res.status, json };
}

function render(rec, { conflict = false } = {}) {
  const v = rec.verdict;
  const root = $('result');
  const acc = v.accepted;
  const tagMap = { reader: ['dir-reader', '读卡器→卡'], card: ['dir-card', '卡→读卡器'] };

  let html = '';
  html += `<div class="verdict ${acc ? 'accept' : 'reject'}">
    <span>${acc ? '✔ 裁决：通过（合法捕获，已冻结）' : '✘ 裁决：拒绝（非法捕获，已冻结）'}</span>
    <span class="frozen">冻结于 ${rec.frozenAt} · ${rec.reviewer ? '审查员 ' + escapeHtml(rec.reviewer) + ' · ' : ''}sha256 ${rec.capture.hash.slice(0, 16)}…</span>
  </div>`;

  if (!acc) {
    html += `<div class="errline">${acc ? '' : '拒绝原因：'}<b>${acc ? '' : escapeHtml(v.errorCode)}</b> — ${acc ? '' : escapeHtml(v.errorReason || '')}；首个违规原始块序号 <b>#${v.errorBlock}</b> <span class="mono">${escapeHtml(v.errorBlockHex || '')}</span></div>`;
  }

  const stats = v.stats || { blocks: v.steps.length, completeApdus: v.apdus.length, retransmissions: 0 };
  html += `<div class="cards">
    <div class="stat"><div class="k">原始块</div><div class="v">${stats.blocks}</div></div>
    <div class="stat"><div class="k">完整 APDU</div><div class="v">${v.apdus.length}</div></div>
    <div class="stat"><div class="k">重传依据条目</div><div class="v">${stats.retransmissions}</div></div>
    <div class="stat"><div class="k">WTX 往返</div><div class="v">${stats.wtxRoundTrips || 0}</div></div>
    <div class="stat"><div class="k">IFS 往返</div><div class="v">${stats.ifsRoundTrips || 0}</div></div>
  </div>`;

  html += '<h2 style="margin-top:16px">完整 APDU（I 块链式组装结果）</h2>';
  if (v.apdus.length === 0) html += '<div class="empty">无成功组装的 APDU。</div>';
  for (const a of v.apdus) {
    const [cls, label] = tagMap[a.direction];
    html += `<div class="apdu">
      <div><span class="${cls}">${label}</span> · 原始块序号 [${a.blocks.join(', ')}]${a.chained ? ' · <span class="tag I">链式</span>' : ''}</div>
      <div class="hex mono">${escapeHtml(a.hex)}</div>
    </div>`;
  }

  html += '<h2 style="margin-top:16px">逐步序号 / 重传依据 / 状态快照</h2>';
  html += `<table><thead><tr><th>#</th><th>方向</th><th>类型</th><th>序号</th><th>重传依据</th><th>判定说明</th><th>原始块 / 快照</th></tr></thead><tbody>`;
  v.steps.forEach((s, idx) => {
    const offending = !acc && v.errorBlock === s.seq;
    const [dcls, dlabel] = tagMap[s.direction];
    let seqTxt = '';
    if (s.kind === 'I') seqTxt = `N(S)=${s.ns}${s.chained ? ' M' : ''}${s.duplicate ? ' <span class="dup">重复</span>' : ''}`;
    if (s.kind === 'R') seqTxt = `N(R)=${s.nr}${s.nak ? ' <span class="dup">NAK</span>' : ' ACK'}`;
    if (s.kind === 'S') seqTxt = `${s.sType}${s.response ? ' 应答' : ' 请求'}`;
    html += `<tr${offending ? ' style="background:rgba(248,81,73,.08)"' : ''}>
      <td>${s.seq}${offending ? ' ⚠' : ''}</td>
      <td class="${dcls}">${dlabel}</td>
      <td><span class="tag ${s.kind}">${s.kind}</span></td>
      <td class="mono">${seqTxt}</td>
      <td>${s.retransmitBasis ? '<span class="dup">' + escapeHtml(s.retransmitBasis) + '</span>' : '—'}</td>
      <td>${escapeHtml(s.detail || '')}</td>
      <td class="mono" style="max-width:300px">${escapeHtml(s.raw)}
        <details><summary>状态快照</summary><pre class="snap">${escapeHtml(JSON.stringify(s.snapshot || v.finalSnapshot, null, 1))}</pre></details>
      </td></tr>`;
  });
  html += '</tbody></table>';

  html += `<details style="margin-top:12px"><summary>最终状态快照</summary><pre class="snap">${escapeHtml(JSON.stringify(v.finalSnapshot, null, 2))}</pre></details>`;
  root.innerHTML = html;
}

function escapeHtml(t) {
  return String(t == null ? '' : t).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

async function refreshList() {
  const { json } = await api('GET', '/api/audits');
  const el = $('auditList');
  if (!json || !json.audits || json.audits.length === 0) { el.innerHTML = '<span class="empty">尚无记录。</span>'; return; }
  el.innerHTML = '<table><tbody>' + json.audits.map((a) => `<tr>
    <td><a data-id="${escapeHtml(a.auditId)}">${escapeHtml(a.auditId)}</a></td>
    <td style="color:${a.accepted ? 'var(--ok)' : 'var(--bad)'}">${a.accepted ? '通过' : '拒绝' + (a.errorBlock ? ' #' + a.errorBlock : '')}</td>
    <td>${a.blockCount} 块</td></tr>`).join('') + '</tbody></table>';
  el.querySelectorAll('a').forEach((a) => a.addEventListener('click', () => load(a.dataset.id)));
}

async function load(id) {
  id = id || $('auditId').value.trim();
  if (!id) { setBanner('errorbox', '请填写审计标识后再读取。'); return; }
  const { status, json } = await api('GET', `/api/audits/${encodeURIComponent(id)}`);
  if (status === 404) { setBanner('errorbox', `未找到审计标识 ${id} 的冻结结果。`); return; }
  if (status !== 200) { setBanner('errorbox', json && json.message || '读取失败'); return; }
  setBanner('info', `已从真实 API 读取冻结结果（GET /api/audits/${id}），内容为冻结时的原始裁决。`);
  render(json);
}

async function submit() {
  const auditId = $('auditId').value.trim();
  if (!auditId) { setBanner('errorbox', '审计标识必填。'); return; }
  const { blocks, errors } = parseCapture($('capture').value);
  if (errors.length) { setBanner('errorbox', errors.join('；')); return; }
  $('parsedCount').textContent = `已解析 ${blocks.length} 条原始块`;
  if (blocks.length === 0) { setBanner('errorbox', '未录入任何块。'); return; }
  if (blocks.length > 64) { setBanner('errorbox', '最多录入 64 条原始块。'); return; }

  const { status, json } = await api('PUT', `/api/audits/${encodeURIComponent(auditId)}`, {
    reviewer: $('reviewer').value.trim() || undefined,
    blocks,
  });
  if (status === 409) {
    setBanner('conflict', '冲突：相同审计标识下捕获内容与已冻结版本不一致（任一块被改动）。下方展示的仍是原冻结结果，原结果保持可读取且未被覆盖。');
    render(json.existing, { conflict: true });
  } else if (status === 200) {
    setBanner('info', '相同审计标识 + 相同捕获：返回原冻结结果（幂等重传），未重新裁决。');
    render(json.record);
  } else if (status === 201) {
    setBanner('info', '首次提交：裁决已冻结并持久化。');
    render(json.record);
  } else {
    setBanner('errorbox', (json && json.message) || `提交失败（HTTP ${status}）`);
  }
  refreshList();
}

async function pingHealth() {
  try {
    const { json } = await api('GET', '/health');
    $('health').innerHTML = `健康检查 <b class="ok">OK</b> · 已冻结 ${json.frozenAudits} 份`;
  } catch {
    $('health').innerHTML = '<b class="bad">API 不可达</b>';
  }
}

$('submit').addEventListener('click', submit);
$('load').addEventListener('click', () => load());
$('sample').addEventListener('click', () => {
  if (!$('auditId').value.trim()) $('auditId').value = 'AUDIT-SAMPLE-01';
  $('capture').value = buildSample();
  const { blocks } = parseCapture($('capture').value);
  $('parsedCount').textContent = `已解析 ${blocks.length} 条原始块`;
});
$('capture').addEventListener('input', () => {
  const { blocks } = parseCapture($('capture').value);
  $('parsedCount').textContent = blocks.length ? `已解析 ${blocks.length} 条原始块` : '';
});

pingHealth();
setInterval(pingHealth, 5000);
refreshList();
