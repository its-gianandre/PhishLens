import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { gzip } from 'node:zlib';
import { promisify } from 'node:util';
import { afterEach, describe, expect, it } from 'vitest';
// @ts-expect-error plain-JS module without type declarations
import { normalizeUrl } from '../backend/threat-intel/normalize-url.mjs';
// @ts-expect-error plain-JS module without type declarations
import { buildPhishTankIndex, loadPhishTankFeed } from '../backend/threat-intel/parser.mjs';
// @ts-expect-error plain-JS module without type declarations
import { createPhishTankProvider, unavailablePhishTankFinding } from '../backend/threat-intel/providers/phishtank.mjs';
// @ts-expect-error plain-JS module without type declarations
import { initializeThreatIntel, getThreatIntelService, resetThreatIntelForTests } from '../backend/threat-intel/index.mjs';
// @ts-expect-error plain-JS module without type declarations
import { createBackendServer } from '../backend/server.mjs';

const gzipAsync = promisify(gzip);
const fixtureUrl = new URL('./fixtures/phishtank-small.json', import.meta.url);
const temporaryFiles: string[] = [];
const phishtankOnly = {
  urlhausAuthKey: '',
  urlhausFeedPath: 'missing-urlhaus-test-cache.csv',
  includeOpenPhish: false,
};

afterEach(async () => {
  const { unlink } = await import('node:fs/promises');
  await Promise.all(temporaryFiles.splice(0).map((file) => unlink(file).catch(() => undefined)));
  resetThreatIntelForTests();
});

async function writeGzipFixture(suffix: string): Promise<string> {
  const json = await readFile(fixtureUrl);
  const path = `${fileURLToPath(fixtureUrl)}.${process.pid}.${suffix}.json.gz`;
  temporaryFiles.push(path);
  await writeFile(path, await gzipAsync(json));
  return path;
}

describe('threat-intel URL normalization', () => {
  it('removes fragments, lowercases hosts, removes default ports, and preserves queries', () => {
    expect(normalizeUrl('HTTPS://Example.COM:443/login?q=One#section'))
      .toBe('https://example.com/login?q=One');
    expect(normalizeUrl('http://Example.COM:80')).toBe('http://example.com/');
  });

  it('rejects unsupported and malformed URLs', () => {
    expect(() => normalizeUrl('ftp://example.com/file')).toThrow(/HTTP or HTTPS/);
    expect(() => normalizeUrl('not a url')).toThrow(/malformed/);
  });
});

describe('PhishTank parser and indexes', () => {
  it('filters records and ignores malformed individual entries', async () => {
    const records = JSON.parse(await readFile(fixtureUrl, 'utf8'));
    const index = buildPhishTankIndex(records);
    expect(index.rawRecordCount).toBe(5);
    expect(index.acceptedRecordCount).toBe(2);
    expect(index.exactUrlCount).toBe(2);
    expect(index.hostnameCount).toBe(1);
  });

  it('loads and decompresses a gzip JSON feed', async () => {
    const path = await writeGzipFixture('parser');
    const index = await loadPhishTankFeed(path);
    expect(index.exactUrlCount).toBe(2);
  });

  it('rejects a non-array top-level value', () => {
    expect(() => buildPhishTankIndex({ records: [] })).toThrow(/JSON array/);
  });
});

describe('threat-intel service and backend routes', () => {
  it('reports unavailable for a missing feed', async () => {
    await initializeThreatIntel({ ...phishtankOnly, feedPath: 'missing-phishtank-feed.json.gz' });
    expect(getThreatIntelService().health()).toMatchObject({
      available: false,
      records: 0,
      hostnames: 0,
    });
    expect(getThreatIntelService().lookup('https://example.com/').status).toBe('unavailable');
  });

  it('retains a previous valid index when a reload is corrupted', async () => {
    const validPath = await writeGzipFixture('valid');
    await initializeThreatIntel({ ...phishtankOnly, feedPath: validPath });
    expect(getThreatIntelService().health().available).toBe(true);

    const corruptPath = `${fileURLToPath(fixtureUrl)}.${process.pid}.corrupt.json.gz`;
    temporaryFiles.push(corruptPath);
    await writeFile(corruptPath, 'not gzip data');
    await initializeThreatIntel({ ...phishtankOnly, feedPath: corruptPath });

    expect(getThreatIntelService().health()).toMatchObject({
      available: true,
      records: 2,
      hostnames: 1,
    });
    expect(getThreatIntelService().lookup('https://login.example/another-path').status)
      .toBe('complete');
  });

  it('serves health and URL lookup without fetching the supplied page', async () => {
    const validPath = await writeGzipFixture('server');
    await initializeThreatIntel({ ...phishtankOnly, feedPath: validPath });
    const server = createBackendServer();
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

    try {
      const address = server.address();
      if (!address || typeof address === 'string') throw new Error('missing server address');
      const base = `http://127.0.0.1:${address.port}`;

      const healthResponse = await fetch(`${base}/health`);
      expect(healthResponse.headers.get('cache-control')).toBe('no-store');
      const health = await healthResponse.json();
      expect(health.threatIntel).toMatchObject({
        available: true,
        records: 2,
        providers: {
          phishtank: { available: true, records: 2 },
          urlhaus: { available: false, records: 0 },
        },
      });

      const lookupResponse = await fetch(`${base}/threat-intel`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: 'https://login.example/login?campaign=alpha' }),
      });
      expect(lookupResponse.status).toBe(200);
      expect(await lookupResponse.json()).toMatchObject({
        status: 'complete',
        findings: [
          { provider: 'phishtank', matched: true, matchType: 'exact-url' },
          { provider: 'urlhaus', available: false, matched: false },
        ],
      });

      const batchResponse = await fetch(`${base}/threat-intel/batch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          urls: [
            'https://login.example/login?campaign=alpha',
            'https://clean.example/',
          ],
        }),
      });
      expect(batchResponse.status).toBe(200);
      const batch = await batchResponse.json();
      expect(batch.results).toHaveLength(2);
      expect(batch.results[0].status).toBe('complete');
      expect(batch.results[0].findings[0]).toMatchObject({
        provider: 'phishtank', matched: true, matchType: 'exact-url',
      });
      expect(batch.results[1].status).toBe('complete');
      expect(batch.results[1].findings[0]).toMatchObject({
        provider: 'phishtank', matched: false,
      });

      const invalidResponse = await fetch(`${base}/threat-intel`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: 'ftp://example.com/file' }),
      });
      expect(invalidResponse.status).toBe(400);

      const wrongContentType = await fetch(`${base}/threat-intel`, {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain' },
        body: JSON.stringify({ url: 'https://login.example/' }),
      });
      expect(wrongContentType.status).toBe(415);

      const disallowedOrigin = await fetch(`${base}/health`, {
        headers: { Origin: 'https://attacker.example' },
      });
      expect(disallowedOrigin.status).toBe(403);

      const extensionOrigin = 'chrome-extension://abcdefghijklmnopabcdefghijklmnop';
      const allowedExtension = await fetch(`${base}/health`, {
        headers: { Origin: extensionOrigin },
      });
      expect(allowedExtension.status).toBe(200);
      expect(allowedExtension.headers.get('access-control-allow-origin')).toBe(extensionOrigin);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error: Error | undefined) => error ? reject(error) : resolve());
      });
    }
  });
});

describe('PhishTank provider', () => {
  it('returns exact, hostname-only, and absent matches', async () => {
    const records = JSON.parse(await readFile(fixtureUrl, 'utf8'));
    const provider = createPhishTankProvider(buildPhishTankIndex(records));

    const exact = provider.lookup('https://login.example/login?campaign=alpha#ignored');
    expect(exact).toMatchObject({
      available: true,
      matched: true,
      matchType: 'exact-url',
      confidence: 'high',
      targetBrand: 'Example Mail',
    });

    const hostname = provider.lookup('https://login.example/not-listed');
    expect(hostname).toMatchObject({
      matched: true,
      matchType: 'hostname',
      confidence: 'medium',
    });

    expect(provider.lookup('https://clean.example/')).toMatchObject({
      available: true,
      matched: false,
      matchType: null,
    });
  });

  it('reports unavailable without claiming a match', () => {
    expect(unavailablePhishTankFinding()).toMatchObject({
      provider: 'phishtank',
      available: false,
      matched: false,
    });
    expect(createPhishTankProvider(null).lookup('https://example.com/'))
      .toEqual(unavailablePhishTankFinding());
  });
});
