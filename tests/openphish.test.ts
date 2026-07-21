import { describe, expect, it, vi } from 'vitest';
// @ts-expect-error plain-JS module without type declarations
import { buildOpenPhishIndex, createOpenPhishProvider, fetchOpenPhishFeed, unavailableOpenPhishFinding } from '../backend/threat-intel/providers/openphish.mjs';
// @ts-expect-error plain-JS module without type declarations
import { getThreatIntelService, initializeThreatIntel, resetThreatIntelForTests } from '../backend/threat-intel/index.mjs';

const fixtureUrl = new URL('../backend/threat-intel/data/demo-openphish.txt', import.meta.url);

describe('OpenPhish parser and provider', () => {
  it('indexes valid URLs while skipping comments and malformed records', () => {
    const index = buildOpenPhishIndex([
      '# OpenPhish fixture',
      'https://login.example.test/sign-in',
      'not a url',
      'https://login.example.test/reset',
      '',
    ].join('\n'));

    expect(index.acceptedRecordCount).toBe(2);
    expect(index.exactUrlCount).toBe(2);
    expect(index.hostnameCount).toBe(1);
  });

  it('returns exact, hostname-only, absent, and unavailable findings', () => {
    const provider = createOpenPhishProvider(buildOpenPhishIndex(
      'https://login.example.test/sign-in\n',
    ));

    expect(provider.lookup('https://login.example.test/sign-in#ignored')).toMatchObject({
      provider: 'openphish',
      matched: true,
      category: 'phishing',
      matchType: 'exact-url',
      confidence: 'high',
      submissionTime: null,
      status: null,
    });
    expect(provider.lookup('https://login.example.test/unlisted')).toMatchObject({
      matched: true,
      matchType: 'hostname',
      confidence: 'medium',
    });
    expect(provider.lookup('https://clean.example/')).toMatchObject({
      available: true,
      matched: false,
    });
    expect(createOpenPhishProvider(null).lookup('https://example.com/'))
      .toEqual(unavailableOpenPhishFinding());
  });
});

describe('OpenPhish download', () => {
  it('downloads the feed with a descriptive user agent', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(
      'https://login.example.test/sign-in\n',
      { status: 200 },
    ));
    await expect(fetchOpenPhishFeed(fetchMock)).resolves.toContain('login.example.test');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://www.openphish.com/feed.txt',
      expect.objectContaining({ headers: expect.objectContaining({ 'User-Agent': expect.any(String) }) }),
    );
  });

  it('does not leak network details and rejects oversized feeds', async () => {
    await expect(fetchOpenPhishFeed(vi.fn().mockRejectedValue(new Error('private detail'))))
      .rejects.toThrow('OpenPhish download failed');

    const oversized = vi.fn().mockResolvedValue(new Response('ignored', {
      status: 200,
      headers: { 'Content-Length': String(11 * 1024 * 1024) },
    }));
    await expect(fetchOpenPhishFeed(oversized)).rejects.toThrow(/10 MB/);
  });
});

describe('OpenPhish service integration', () => {
  it('loads a configured feed and returns it with the other provider findings', async () => {
    try {
      const health = await initializeThreatIntel({
        feedPath: 'missing-phishtank-feed.json.gz',
        urlhausFeedPath: 'missing-urlhaus-feed.csv',
        urlhausAuthKey: '',
        includeOpenPhish: true,
        openphishFeedPath: fixtureUrl,
      });

      expect(health.providers.openphish).toMatchObject({
        available: true,
        records: 2,
        source: 'configured-file',
      });
      expect(getThreatIntelService().lookup('http://localhost:8000/openphish-demo.html'))
        .toMatchObject({
          status: 'complete',
          findings: [
            { provider: 'phishtank', available: false },
            { provider: 'urlhaus', available: false },
            { provider: 'openphish', matched: true, matchType: 'exact-url' },
          ],
        });
    } finally {
      resetThreatIntelForTests();
    }
  });

  it('rejects an empty configured feed instead of reporting it as available', async () => {
    try {
      const health = await initializeThreatIntel({
        feedPath: 'missing-phishtank-feed.json.gz',
        urlhausFeedPath: 'missing-urlhaus-feed.csv',
        urlhausAuthKey: '',
        includeOpenPhish: true,
        openphishFeedPath: new URL('./fixtures/empty-openphish.txt', import.meta.url),
      });
      expect(health.providers.openphish).toMatchObject({ available: false, records: 0 });
    } finally {
      resetThreatIntelForTests();
    }
  });
});
