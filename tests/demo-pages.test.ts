import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';
import { describe, expect, it } from 'vitest';
import { applyThreatIntel } from '../extension/background/enrichment';
import { runAnalysis } from '../extension/background/pipeline';
import { assessLink } from '../extension/background/link-analysis';
import { extractPageEvidence } from '../extension/content/extract-page';
import { collectExternalLinks } from '../extension/content/link-protection';
import type { ThreatIntelSummary } from '../extension/shared/types';
import { lookupBlockListProject } from '../extension/threat-intel/blocklist-project';
import { getPresentationThreatIntelFindings } from '../extension/threat-intel/presentation-fixtures';
// @ts-expect-error plain-JS module without type declarations
import { buildPhishTankIndex } from '../backend/threat-intel/parser.mjs';
// @ts-expect-error plain-JS module without type declarations
import { createPhishTankProvider } from '../backend/threat-intel/providers/phishtank.mjs';
// @ts-expect-error plain-JS module without type declarations
import { buildUrlhausIndex } from '../backend/threat-intel/urlhaus/parser.mjs';
// @ts-expect-error plain-JS module without type declarations
import { createUrlhausProvider } from '../backend/threat-intel/urlhaus/provider.mjs';
// @ts-expect-error plain-JS module without type declarations
import { buildOpenPhishIndex, createOpenPhishProvider } from '../backend/threat-intel/providers/openphish.mjs';
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
const openphishText = readFileSync(
  new URL('../backend/threat-intel/data/demo-openphish.txt', import.meta.url),
  'utf8',
);
const phishtank = createPhishTankProvider(buildPhishTankIndex(phishtankRecords));
const urlhaus = createUrlhausProvider(buildUrlhausIndex(urlhausCsv));
const openphish = createOpenPhishProvider(buildOpenPhishIndex(openphishText));
const blockListProjectDomains = new Set([
  'blocklist-demo.localhost',
  'intel-showcase.localhost',
]);

function analyze(file: string, url: string) {
  const html = readFileSync(new URL(`../test-pages/${file}`, import.meta.url), 'utf8');
  const dom = new JSDOM(html, { url });
  const evidence = extractPageEvidence(dom.window.document as unknown as Document, url);
  return runAnalysis(evidence, { threatIntelEnabled: true, approvedDomains: [] });
}

function enrich(file: string, url: string) {
  const local = analyze(file, url);
  const presentation = getPresentationThreatIntelFindings(url);
  const presentationProviders = new Set(presentation.map((finding) => finding.provider));
  const backendFindings = [phishtank.lookup(url), urlhaus.lookup(url), openphish.lookup(url)]
    .filter((finding) => !presentationProviders.has(finding.provider));
  const summary: ThreatIntelSummary = {
    status: 'complete',
    checkedAt: Date.now(),
    findings: [
      ...backendFindings,
      ...presentation,
      lookupBlockListProject(url, blockListProjectDomains),
    ],
  };
  return { local, enriched: applyThreatIntel(local, summary) };
}

describe('presentation threat-intelligence pages', () => {
  it('demonstrates all three link-protection levels on a low-risk social feed', () => {
    const html = readFileSync(
      new URL('../test-pages/link-protection.html', import.meta.url),
      'utf8',
    );
    const pageUrl = 'http://social-feed.localhost:8000/link-protection.html';
    const dom = new JSDOM(html, { url: pageUrl });
    const doc = dom.window.document as unknown as Document;
    const page = runAnalysis(extractPageEvidence(doc, pageUrl), {
      threatIntelEnabled: true,
      approvedDomains: [],
    });
    expect(page.classification).toBe('Low');

    const links = collectExternalLinks(doc, pageUrl);
    const byUrl = new Map(links.map((link) => [link.candidate.lookupUrl, link]));
    const assess = (url: string) => {
      const link = byUrl.get(url);
      expect(link).toBeDefined();
      return {
        link: link!,
        result: assessLink(link!.candidate, {
          status: 'complete',
          checkedAt: Date.now(),
          findings: [phishtank.lookup(url), urlhaus.lookup(url)],
        }),
      };
    };

    expect(assess('http://safe-destination.localhost:8000/vendor-status.html').result.risk)
      .toBe('safe');

    const suspicious = assess('https://paypal-rewards.example/claim-prize');
    expect(suspicious.result.risk).toBe('suspicious');
    expect(suspicious.link.anchors).toHaveLength(2);
    expect(suspicious.link.candidate.urlSignalIds).toContain('brand-in-hostname');
    expect(suspicious.link.candidate.contextSignalIds).toContain('reward-language');

    const known = assess(
      'http://signin-portal.localhost:8000/verified-apple-id.html',
    );
    expect(known.result.risk).toBe('high');
    expect(known.result.reasons[0]).toMatch(/exact destination/i);
  });

  it('overlays all presentation matches on the regular backend feeds', async () => {
    try {
      const health = await initializeThreatIntel({
        phishtankRecords: [],
        urlhausFeedPath: new URL('./fixtures/urlhaus-small.csv', import.meta.url),
        urlhausAuthKey: '',
        includeDemoFixtures: true,
        includeOpenPhish: true,
        openphishFeedPath: new URL('../backend/threat-intel/data/demo-openphish.txt', import.meta.url),
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
      expect(health.providers.openphish).toMatchObject({
        available: true,
        records: 2,
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
      ).findings).toEqual(expect.arrayContaining([
        expect.objectContaining({ provider: 'phishtank', matchType: 'hostname' }),
        expect.objectContaining({ provider: 'urlhaus', matchType: 'hostname' }),
      ]));
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

  it('shows a scored exact OpenPhish match on the demo page', () => {
    expect(getPresentationThreatIntelFindings(
      'http://localhost:8000/openphish-demo.html',
    )).toEqual([
      expect.objectContaining({
        provider: 'openphish',
        matched: true,
        matchType: 'exact-url',
      }),
    ]);
    expect(getPresentationThreatIntelFindings(
      'http://localhost:9000/openphish-demo.html',
    )).toEqual([]);

    const { local, enriched } = enrich(
      'openphish-demo.html',
      'http://localhost:8000/openphish-demo.html',
    );

    expect(local.classification).toBe('Low');
    expect(enriched.score).toBeGreaterThan(local.score);
    expect(enriched.signals.map((signal) => signal.id)).toContain('known-malicious-url');
    expect(enriched.threatIntel.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        provider: 'openphish',
        matchType: 'exact-url',
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
    expect(enriched.threatIntel.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ provider: 'phishtank', matchType: 'hostname' }),
      expect.objectContaining({ provider: 'urlhaus', matchType: 'hostname' }),
    ]));
    expect(enriched.signals.map((signal) => signal.id)).not.toEqual(expect.arrayContaining([
      'known-malicious-url',
      'known-malware-url',
    ]));
  });

  it('shows a scored local Block List Project domain match', () => {
    const { local, enriched } = enrich(
      'blocklist-demo.html',
      'http://blocklist-demo.localhost:8000/blocklist-demo.html',
    );

    expect(local).toMatchObject({ score: 0, classification: 'Low' });
    expect(enriched).toMatchObject({ score: 30, classification: 'Caution' });
    expect(enriched.signals.map((signal) => signal.id)).toContain('known-malicious-url');
    expect(enriched.threatIntel.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        provider: 'blocklist-project',
        matched: true,
        matchType: 'hostname',
      }),
    ]));
    expect(enriched.threatIntel.findings.filter((finding) => finding.matched))
      .toHaveLength(1);
  });

  it('shows every configured feed together on the presentation showcase', () => {
    const { local, enriched } = enrich(
      'threat-intel-showcase.html',
      'http://intel-showcase.localhost:8000/threat-intel-showcase.html',
    );

    expect(local).toMatchObject({ score: 0, classification: 'Low' });
    expect(enriched.classification).toBe('Critical');
    expect(enriched.threatIntel.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ provider: 'phishtank', matchType: 'exact-url' }),
      expect.objectContaining({ provider: 'urlhaus', matchType: 'exact-url' }),
      expect.objectContaining({ provider: 'openphish', matchType: 'exact-url' }),
      expect.objectContaining({ provider: 'blocklist-project', matchType: 'hostname' }),
    ]));
    expect(enriched.signals.map((signal) => signal.id)).toEqual(expect.arrayContaining([
      'known-malicious-url',
      'known-malware-url',
    ]));
  });
});
