import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';
import { describe, expect, it } from 'vitest';
import { applyThreatIntel } from '../extension/background/enrichment';
import { runAnalysis } from '../extension/background/pipeline';
import { extractPageEvidence } from '../extension/content/extract-page';
import type { ThreatIntelSummary } from '../extension/shared/types';
// @ts-expect-error plain-JS module without type declarations
import { buildPhishTankIndex } from '../backend/threat-intel/parser.mjs';
// @ts-expect-error plain-JS module without type declarations
import { createPhishTankProvider } from '../backend/threat-intel/providers/phishtank.mjs';
// @ts-expect-error plain-JS module without type declarations
import { buildUrlhausIndex } from '../backend/threat-intel/urlhaus/parser.mjs';
// @ts-expect-error plain-JS module without type declarations
import { createUrlhausProvider } from '../backend/threat-intel/urlhaus/provider.mjs';
// @ts-expect-error plain-JS module without type declarations
import { getThreatIntelService, initializeThreatIntel, resetThreatIntelForTests } from '../backend/threat-intel/index.mjs';

const phishtankRecords = JSON.parse(readFileSync(
  new URL('../backend/threat-intel/data/demo-phishtank.json', import.meta.url),
  'utf8',
));
const urlhausCsv = readFileSync(
  new URL('../backend/threat-intel/data/demo-urlhaus.csv', import.meta.url),
  'utf8',
);
const phishtank = createPhishTankProvider(buildPhishTankIndex(phishtankRecords));
const urlhaus = createUrlhausProvider(buildUrlhausIndex(urlhausCsv));

function analyze(file: string, url: string) {
  const html = readFileSync(new URL(`../test-pages/${file}`, import.meta.url), 'utf8');
  const dom = new JSDOM(html, { url });
  const evidence = extractPageEvidence(dom.window.document as unknown as Document, url);
  return runAnalysis(evidence, { threatIntelEnabled: true, approvedDomains: [] });
}

function enrich(file: string, url: string) {
  const local = analyze(file, url);
  const summary: ThreatIntelSummary = {
    status: 'complete',
    checkedAt: Date.now(),
    findings: [phishtank.lookup(url), urlhaus.lookup(url)],
  };
  return { local, enriched: applyThreatIntel(local, summary) };
}

describe('presentation threat-intelligence pages', () => {
  it('overlays all presentation matches on the regular backend feeds', async () => {
    try {
      const health = await initializeThreatIntel({
        phishtankRecords: [],
        urlhausFeedPath: new URL('./fixtures/urlhaus-small.csv', import.meta.url),
        urlhausAuthKey: '',
        includeDemoFixtures: true,
      });

      expect(health.providers.phishtank).toMatchObject({
        available: true,
        records: 2,
        source: 'configured-records+demo-fixtures',
      });
      expect(health.providers.urlhaus).toMatchObject({
        available: true,
        records: 4,
        source: 'configured-file+demo-fixtures',
      });
      expect(getThreatIntelService().lookup(
        'http://signin-portal.localhost:8000/verified-apple-id.html',
      ).findings).toEqual(expect.arrayContaining([
        expect.objectContaining({ provider: 'phishtank', matchType: 'exact-url' }),
      ]));
      expect(getThreatIntelService().lookup(
        'http://software-update.localhost:8000/critical-browser-update.html',
      ).findings).toEqual(expect.arrayContaining([
        expect.objectContaining({ provider: 'urlhaus', matchType: 'exact-url' }),
      ]));
      expect(getThreatIntelService().lookup(
        'http://reputation-lab.localhost:8000/vendor-status.html',
      ).findings).toEqual([
        expect.objectContaining({ provider: 'phishtank', matchType: 'hostname' }),
        expect.objectContaining({ provider: 'urlhaus', matchType: 'hostname' }),
      ]);
    } finally {
      resetThreatIntelForTests();
    }
  });

  it('shows a scored exact PhishTank match on the credential page', () => {
    const { local, enriched } = enrich(
      'verified-apple-id.html',
      'http://signin-portal.localhost:8000/verified-apple-id.html',
    );

    expect(local).toMatchObject({ score: 68, classification: 'High' });
    expect(enriched).toMatchObject({ score: 100, classification: 'Critical' });
    expect(enriched.signals.map((signal) => signal.id)).toContain('known-malicious-url');
    expect(enriched.threatIntel.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ provider: 'phishtank', matchType: 'exact-url' }),
    ]));
  });

  it('shows a scored active exact URLhaus match on the update page', () => {
    const { local, enriched } = enrich(
      'critical-browser-update.html',
      'http://software-update.localhost:8000/critical-browser-update.html',
    );

    expect(local).toMatchObject({ score: 8, classification: 'Low' });
    expect(enriched).toMatchObject({ score: 68, classification: 'High' });
    expect(enriched.signals.map((signal) => signal.id)).toContain('known-malware-url');
    expect(enriched.threatIntel.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        provider: 'urlhaus',
        matchType: 'exact-url',
        status: 'online',
      }),
    ]));
  });

  it('shows both hostname findings without changing the clean page score', () => {
    const { local, enriched } = enrich(
      'vendor-status.html',
      'http://reputation-lab.localhost:8000/vendor-status.html',
    );

    expect(local.score).toBe(0);
    expect(enriched.score).toBe(local.score);
    expect(enriched.threatIntel.findings).toEqual([
      expect.objectContaining({ provider: 'phishtank', matchType: 'hostname' }),
      expect.objectContaining({ provider: 'urlhaus', matchType: 'hostname' }),
    ]);
    expect(enriched.signals.map((signal) => signal.id)).not.toEqual(expect.arrayContaining([
      'known-malicious-url',
      'known-malware-url',
    ]));
  });
});
