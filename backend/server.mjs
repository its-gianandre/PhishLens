import http from 'node:http';
import { explain } from './explain.mjs';

const PORT = Number(process.env.PORT ?? 8787);
const MAX_BODY_BYTES = 100 * 1024;

function sendJson(res, status, payload) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
  });
  res.end(JSON.stringify(payload));
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    sendJson(res, 204, {});
    return;
  }
  if (req.method === 'GET' && req.url === '/health') {
    sendJson(res, 200, { ok: true, mode: 'stub' });
    return;
  }
  if (req.method === 'POST' && req.url === '/explain') {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        sendJson(res, 413, { error: 'payload too large' });
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', async () => {
      if (res.writableEnded) return;
      try {
        const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        const explanation = await explain(body);
        sendJson(res, 200, explanation);
      } catch (err) {
        sendJson(res, 400, { error: String(err?.message ?? err) });
      }
    });
    return;
  }
  sendJson(res, 404, { error: 'not found' });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`PhishLens explanation backend (stub mode) on http://127.0.0.1:${PORT}`);
  console.log('POST /explain with an ExplainRequest JSON body; GET /health for status.');
});
