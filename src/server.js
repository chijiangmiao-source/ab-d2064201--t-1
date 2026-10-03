'use strict';

// Real HTTP API for the on-board maintenance review station.
// The browser page is a thin client: every result it renders is fetched
// from this API, never computed in the page.

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { URL } = require('node:url');
const { AuditStore, ConflictError } = require('./store');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const MAX_BODY_BYTES = 256 * 1024;

function createServer({ store } = {}) {
  const audits = store || new AuditStore({ file: process.env.AUDIT_FILE || null });

  function sendJson(res, status, obj) {
    const body = JSON.stringify(obj);
    res.writeHead(status, {
      'content-type': 'application/json; charset=utf-8',
      'content-length': Buffer.byteLength(body),
      'cache-control': 'no-store',
    });
    res.end(body);
  }

  function readJson(req) {
    return new Promise((resolve, reject) => {
      let size = 0;
      const chunks = [];
      req.on('data', (c) => {
        size += c.length;
        if (size > MAX_BODY_BYTES) {
          const err = new Error('request body too large');
          err.code = 'BODY_TOO_LARGE';
          reject(err);
          req.destroy();
          return;
        }
        chunks.push(c);
      });
      req.on('end', () => {
        if (chunks.length === 0) return resolve({});
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
        } catch {
          const err = new Error('request body is not valid JSON');
          err.code = 'BAD_JSON';
          reject(err);
        }
      });
      req.on('error', reject);
    });
  }

  function serveStatic(req, res, urlPath) {
    const rel = urlPath === '/' ? 'index.html' : urlPath.replace(/^\/+/, '');
    const file = path.normalize(path.join(PUBLIC_DIR, rel));
    if (!file.startsWith(PUBLIC_DIR)) {
      res.writeHead(403);
      return res.end('forbidden');
    }
    fs.readFile(file, (err, data) => {
      if (err) {
        res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
        return res.end('not found');
      }
      const type = file.endsWith('.html')
        ? 'text/html; charset=utf-8'
        : file.endsWith('.js')
          ? 'text/javascript; charset=utf-8'
          : file.endsWith('.css')
            ? 'text/css; charset=utf-8'
            : 'application/octet-stream';
      res.writeHead(200, { 'content-type': type, 'cache-control': 'no-store' });
      res.end(data);
    });
  }

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const p = url.pathname;

    try {
      if (req.method === 'GET' && (p === '/health' || p === '/healthz')) {
        return sendJson(res, 200, {
          status: 'ok',
          service: 't1-audit-station',
          frozenAudits: audits.list().length,
          time: new Date().toISOString(),
        });
      }

      if (req.method === 'GET' && p === '/api/audits') {
        return sendJson(res, 200, { audits: audits.list() });
      }

      const item = p.match(/^\/api\/audits\/([A-Za-z0-9][A-Za-z0-9._-]{0,63})$/);
      if (item) {
        const auditId = decodeURIComponent(item[1]);
        if (req.method === 'GET') {
          const rec = audits.get(auditId);
          if (!rec) return sendJson(res, 404, { error: 'NOT_FOUND', auditId });
          return sendJson(res, 200, rec);
        }
        if (req.method === 'PUT' || req.method === 'POST') {
          let body;
          try {
            body = await readJson(req);
          } catch (e) {
            return sendJson(res, 400, { error: e.code || 'BAD_REQUEST', message: e.message });
          }
          try {
            const { record, replayed } = audits.submit(auditId, body.blocks, { reviewer: body.reviewer });
            return sendJson(res, replayed ? 200 : 201, {
              replayed,
              conflict: false,
              record,
            });
          } catch (e) {
            if (e instanceof ConflictError) {
              return sendJson(res, 409, {
                error: 'AUDIT_CONFLICT',
                message: e.message,
                frozenAt: e.existing.frozenAt,
                existing: e.existing,
              });
            }
            return sendJson(res, 400, { error: e.code || 'BAD_REQUEST', message: e.message });
          }
        }
      }

      if (req.method === 'POST' && p === '/api/audits') {
        let body;
        try {
          body = await readJson(req);
        } catch (e) {
          return sendJson(res, 400, { error: e.code || 'BAD_REQUEST', message: e.message });
        }
        if (!body.auditId) return sendJson(res, 400, { error: 'BAD_REQUEST', message: 'auditId is required' });
        try {
          const { record, replayed } = audits.submit(body.auditId, body.blocks, { reviewer: body.reviewer });
          return sendJson(res, replayed ? 200 : 201, { replayed, conflict: false, record });
        } catch (e) {
          if (e instanceof ConflictError) {
            return sendJson(res, 409, {
              error: 'AUDIT_CONFLICT',
              message: e.message,
              frozenAt: e.existing.frozenAt,
              existing: e.existing,
            });
          }
          return sendJson(res, 400, { error: e.code || 'BAD_REQUEST', message: e.message });
        }
      }

      if (req.method === 'GET') return serveStatic(req, res, p);
      sendJson(res, 405, { error: 'METHOD_NOT_ALLOWED' });
    } catch (e) {
      sendJson(res, 500, { error: 'INTERNAL', message: e.message });
    }
  });

  server.store = audits;
  return server;
}

if (require.main === module) {
  const port = Number.parseInt(process.env.PORT || '8080', 10);
  const host = process.env.HOST || '0.0.0.0';
  const store = new AuditStore({ file: process.env.AUDIT_FILE || path.join(__dirname, '..', 'data', 'audits.json') });
  const server = createServer({ store });
  server.listen(port, host, () => {
    // Single structured line so the smoke harness can wait on it.
    console.log(JSON.stringify({ event: 'listening', port, host }));
  });
}

module.exports = { createServer };
