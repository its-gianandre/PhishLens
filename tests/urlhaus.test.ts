import { readFile } from 'node:fs/promises';
import { describe, expect, it, vi } from 'vitest';
// @ts-expect-error plain-JS modules without type declarations
import { buildUrlhausIndex, loadUrlhausFeed } from '../backend/threat-intel/urlhaus/parser.mjs';
// @ts-expect-error plain-JS modules without type declarations
import { createUrlhausProvider, unavailableUrlhausFinding } from '../backend/threat-intel/urlhaus/provider.mjs';
// @ts-expect-error plain-JS modules without type declarations
import { fetchUrlhausRecentCsv } from '../backend/threat-intel/urlhaus/download.mjs';
// @ts-expect-error plain-JS module without type declarations
import { getThreatIntelService, initializeThreatIntel, resetThreatIntelForTests } from '../backend/threat-intel/index.mjs';

const fixtureUrl = new URL('./fixtures/urlhaus-small.csv', import.meta.url);

describe('URLhaus parser and provider', () => {
  it('indexes valid CSV rows and skips malformed URLs', async () => {
    const index = buildUrlhausIndex(await readFile(fixtureUrl, 'utf8'));
    expect(index.rawRecordCount).toBe(3);
    expect(index.acceptedRecordCount).toBe(2);
    expect(index.exactUrlCount).toBe(2);
    expect(index.hostnameCount).toBe(1);
  });

  it('loads a CSV fixture from disk', async () => {
    const index = await loadUrlhausFeed(fixtureUrl);
    expect(index.exactUrlCount).toBe(2);
  });

  it('returns exact, hostname-only, absent, and unavailable findings', async () => {
    const index = await loadUrlhausFeed(fixtureUrl);
    const provider = createUrlhausProvider(index);

    expect(provider.lookup('https://download.example/payload.exe#ignored')).toMatchObject({
      provider: 'urlhaus',
      matched: true,
      category: 'malware',
      matchType: 'exact-url',
      confidence: 'high',
      status: 'online',
      threat: 'malware_download',
      tags: ['exe', 'trojan'],
    });
    expect(provider.lookup('https://download.example/unlisted')).toMatchObject({
      matched: true,
      matchType: 'hostname',
      confidence: 'medium',
    });
    expect(provider.lookup('https://clean.example/')).toMatchObject({
      available: true,
      matched: false,
    });
    expect(createUrlhausProvider(null).lookup('https://example.com/'))
      .toEqual(unavailableUrlhausFinding());
  });

  it('rejects feeds without a supported header', () => {
    expect(() => buildUrlhausIndex('one,two\n1,2')).toThrow(/header/);
  });
});

describe('URLhaus authenticated download', () => {
  it('requires an auth key', async () => {
    await expect(fetchUrlhausRecentCsv('')).rejects.toThrow(/URLhaus download failed/);
  });

  it('downloads CSV with a descriptive user agent', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('id,url\n1,https://example.test/', {
      status: 200,
    }));
    await expect(fetchUrlhausRecentCsv('secret-key', fetchMock)).resolves.toContain('id,url');
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/secret-key/recent.csv'),
      expect.objectContaining({ headers: expect.objectContaining({ 'User-Agent': expect.any(String) }) }),
    );
  });

  it('does not expose the auth key in download errors', async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error('network error at secret-key'));
    await expect(fetchUrlhausRecentCsv('secret-key', fetchMock))
      .rejects.not.toThrow(/secret-key/);
  });

  it('rejects a response that exceeds the download size limit', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('ignored', {
      status: 200,
      headers: { 'Content-Length': String(51 * 1024 * 1024) },
    }));
    await expect(fetchUrlhausRecentCsv('secret-key', fetchMock)).rejects.toThrow(/50 MB/);
  });
});

describe('URLhaus service integration', () => {
  it('loads a configured safe feed and returns it beside unavailable PhishTank', async () => {
    resetThreatIntelForTests();
    const health = await initializeThreatIntel({
      feedPath: 'missing-phishtank-feed.json.gz',
      urlhausFeedPath: fixtureUrl,
      urlhausAuthKey: '',
    });
    expect(health.providers).toMatchObject({
      phishtank: { available: false },
      urlhaus: { available: true, records: 2, hostnames: 1 },
    });
    expect(getThreatIntelService().lookup('https://download.example/payload.exe'))
      .toMatchObject({
        status: 'complete',
        findings: [
          { provider: 'phishtank', available: false },
          { provider: 'urlhaus', matched: true, matchType: 'exact-url' },
        ],
      });
    resetThreatIntelForTests();
  });

  it('falls back to a valid cache when an authenticated refresh fails', async () => {
    resetThreatIntelForTests();
    const health = await initializeThreatIntel({
      feedPath: 'missing-phishtank-feed.json.gz',
      urlhausFeedPath: fixtureUrl,
      urlhausAuthKey: 'secret-key',
      fetchImpl: vi.fn().mockRejectedValue(new Error('network error containing secret-key')),
    });
    expect(health.providers.urlhaus).toMatchObject({
      available: true,
      records: 2,
      source: 'local-cache-fallback',
      error: 'URLhaus download failed',
    });
    expect(JSON.stringify(health)).not.toContain('secret-key');
    resetThreatIntelForTests();
  });

  it('rejects an empty remote feed instead of replacing a valid provider', async () => {
    resetThreatIntelForTests();
    const health = await initializeThreatIntel({
      feedPath: 'missing-phishtank-feed.json.gz',
      urlhausFeedPath: 'missing-urlhaus-cache.csv',
      urlhausAuthKey: 'secret-key',
      fetchImpl: vi.fn().mockResolvedValue(new Response('id,url\n', { status: 200 })),
    });
    expect(health.providers.urlhaus).toMatchObject({ available: false, records: 0 });
    expect(JSON.stringify(health)).not.toContain('secret-key');
    resetThreatIntelForTests();
  });
});
