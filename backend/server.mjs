import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { explain } from './explain.mjs';
import { getThreatIntelService, initializeThreatIntel } from './threat-intel/index.mjs';
import { normalizeUrl } from './threat-intel/normalize-url.mjs';

const PORT = Number(process.env.PORT ?? 8787);
const HOST = process.env.HOST ?? '127.0.0.1';
const MAX_BODY_BYTES = 100 * 1024;
const MAX_URL_LENGTH = 4096;
const MAX_BATCH_URLS = 100;

function allowedOrigin(origin) {
  if (!origin) return null;
  try {
    const url = new URL(origin);
    if (
      url.protocol === 'chrome-extension:' &&
      /^[a-p]{32}$/.test(url.hostname) &&
      (!url.pathname || url.pathname === '/')
    ) {
      return origin;
    }
    if (
      (url.protocol === 'http:' || url.protocol === 'https:') &&
      (url.hostname === '127.0.0.1' || url.hostname === 'localhost') &&
      url.pathname === '/'
    ) {
      return origin;
    }
  } catch {
    // Invalid origins are not allowed.
  }
  return null;
}

function sendJson(req, res, status, payload) {
  const headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
    'Cache-Control': 'no-store',
    Vary: 'Origin',
  };
  const origin = allowedOrigin(req.headers.origin);
  if (origin) headers['Access-Control-Allow-Origin'] = origin;
  res.writeHead(status, headers);
  res.end(JSON.stringify(payload));
}

function hasJsonContentType(req) {
  const contentType = req.headers['content-type'];
  return typeof contentType === 'string' &&
    contentType.split(';', 1)[0].trim().toLowerCase() === 'application/json';
}

function readJsonBody(req, res) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(Object.assign(new Error('payload too large'), { status: 413 }));
        return;
      }
      if (size <= MAX_BODY_BYTES) chunks.push(chunk);
    });
    req.on('error', reject);
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(Object.assign(new Error('body must be valid JSON'), { status: 400 }));
      }
    });
  });
}

export function createBackendServer() {
  return http.createServer(async (req, res) => {
    const origin = req.headers.origin;
    if (origin && !allowedOrigin(origin)) {
      sendJson(req, res, 403, { error: 'origin not allowed' });
      return;
    }

    if (req.method === 'OPTIONS') {
      sendJson(req, res, 204, {});
      return;
    }

    if (req.method === 'GET' && req.url === '/health') {
      sendJson(req, res, 200, {
        ok: true,
        mode: 'local',
        threatIntel: getThreatIntelService().health(),
        ollama: { configured: Boolean(process.env.OLLAMA_URL) },
      });
      return;
    }

    if (req.method === 'POST' && req.url === '/explain') {
      if (!hasJsonContentType(req)) {
        sendJson(req, res, 415, { error: 'content type must be application/json' });
        return;
      }
      try {
        const body = await readJsonBody(req, res);
        const explanation = await explain(body);
        sendJson(req, res, 200, explanation);
      } catch (error) {
        sendJson(req, res, error?.status ?? 400, {
          error: String(error?.message ?? error),
        });
      }
      return;
    }

    if (req.method === 'POST' && req.url === '/threat-intel') {
      if (!hasJsonContentType(req)) {
        sendJson(req, res, 415, { error: 'content type must be application/json' });
        return;
      }
      try {
        const body = await readJsonBody(req, res);
        if (typeof body?.url !== 'string') throw new Error('url must be a string');
        if (body.url.length > MAX_URL_LENGTH) throw new Error('url exceeds 4096 characters');
        normalizeUrl(body.url);
        sendJson(req, res, 200, getThreatIntelService().lookup(body.url));
      } catch (error) {
        sendJson(req, res, error?.status ?? 400, {
          error: String(error?.message ?? error),
        });
      }
      return;
    }

    if (req.method === 'POST' && req.url === '/threat-intel/batch') {
      if (!hasJsonContentType(req)) {
        sendJson(req, res, 415, { error: 'content type must be application/json' });
        return;
      }
      try {
        const body = await readJsonBody(req, res);
        if (!Array.isArray(body?.urls)) throw new Error('urls must be an array');
        if (body.urls.length > MAX_BATCH_URLS) throw new Error('batch exceeds 100 URLs');
        for (const url of body.urls) {
          if (typeof url !== 'string') throw new Error('every URL must be a string');
          if (url.length > MAX_URL_LENGTH) throw new Error('url exceeds 4096 characters');
          normalizeUrl(url);
        }
        sendJson(req, res, 200, {
          results: body.urls.map((url) => getThreatIntelService().lookup(url)),
        });
      } catch (error) {
        sendJson(req, res, error?.status ?? 400, {
          error: String(error?.message ?? error),
        });
      }
      return;
    }

    sendJson(req, res, 404, { error: 'not found' });
  });
}

export async function startBackend(port = PORT, threatIntelOptions = { includeDemoFixtures: true }) {
  const threatIntel = await initializeThreatIntel(threatIntelOptions);
  const server = createBackendServer();
  await new Promise((resolve) => server.listen(port, HOST, resolve));
  console.log(`PhishLens local backend on http://${HOST}:${port}`);
  const readyProviders = Object.entries(threatIntel.providers)
    .filter(([, provider]) => provider.available)
    .map(([name, provider]) => `${name}: ${provider.records} URLs`);
  console.log(readyProviders.length
    ? `Threat intelligence ready (${readyProviders.join(', ')}).`
    : 'Threat intelligence unavailable; local analysis and explanations remain active.');
  for (const [name, provider] of Object.entries(threatIntel.providers)) {
    if (!provider.available && provider.error) {
      console.log(`${name} unavailable: ${provider.error}`);
    }
  }
  return server;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  await startBackend();
}
