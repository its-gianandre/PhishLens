// Integration: real test-page HTML → evidence extraction (jsdom) → detectors →
// scoring. Enforces the expectations documented in test-pages/EXPECTED.md.
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';
import { describe, expect, it } from 'vitest';
import { runAnalysis, type PipelineOptions } from '../extension/background/pipeline';
import { extractPageEvidence } from '../extension/content/extract-page';
import { makeEvidence } from './helpers';

const DEFAULTS: PipelineOptions = { threatIntelEnabled: true, approvedDomains: [] };

function analyzeFixture(file: string, opts: PipelineOptions = DEFAULTS) {
  const html = readFileSync(new URL(`../test-pages/${file}`, import.meta.url), 'utf8');
  const url = `http://localhost:8000/${file}`;
  const dom = new JSDOM(html, { url });
  const evidence = extractPageEvidence(dom.window.document as unknown as Document, url);
  return runAnalysis(evidence, opts);
}

describe('pipeline on the documented test pages', () => {
  it('normal-login.html → Low', () => {
    const result = analyzeFixture('normal-login.html');
    expect(result.classification).toBe('Low');
    expect(result.signals.map((s) => s.id)).toContain('password-field');
    expect(result.signals.map((s) => s.id)).not.toContain('brand-domain-mismatch');
  });

  it('fake-microsoft-login.html → High, impersonating Microsoft', () => {
    const result = analyzeFixture('fake-microsoft-login.html');
    expect(result.classification).toBe('High');
    expect(result.score).toBeGreaterThanOrEqual(60);
    expect(result.suspectedBrand).toBe('Microsoft');
    const ids = result.signals.map((s) => s.id);
    expect(ids).toContain('brand-domain-mismatch');
    expect(ids).toContain('password-field');
  });

  it('external-form.html → Caution with external credential exfiltration', () => {
    const result = analyzeFixture('external-form.html');
    expect(result.classification).toBe('Caution');
    expect(result.score).toBeGreaterThanOrEqual(45);
    expect(result.signals.map((s) => s.id)).toContain('external-form-action');
  });

  it('urgency-page.html → Caution from stacked language alone', () => {
    const result = analyzeFixture('urgency-page.html');
    expect(result.classification).toBe('Caution');
    const languageSignals = result.signals.filter((s) => s.detector === 'language');
    expect(languageSignals.length).toBeGreaterThanOrEqual(3);
    expect(result.signals.map((s) => s.id)).not.toContain('password-field');
  });

  it('combined-phish.html → Critical', () => {
    const result = analyzeFixture('combined-phish.html');
    expect(result.classification).toBe('Critical');
    expect(result.score).toBeGreaterThanOrEqual(80);
    const ids = result.signals.map((s) => s.id);
    expect(ids).toEqual(expect.arrayContaining([
      'brand-domain-mismatch', 'password-field', 'sensitive-field', 'external-form-action',
    ]));
  });

  it('approved-domain override suppresses analysis', () => {
    const result = analyzeFixture('combined-phish.html', {
      threatIntelEnabled: true,
      approvedDomains: ['localhost'],
    });
    expect(result.overridden).toBe(true);
    expect(result.score).toBe(0);
    expect(result.signals).toEqual([]);
  });

  it('known-threat lookup contributes a signal when enabled', () => {
    const evidence = makeEvidence({ url: 'https://phish.example.test/login' });
    const flagged = runAnalysis(evidence, DEFAULTS);
    expect(flagged.signals.map((s) => s.id)).toContain('known-malicious-url');

    const disabled = runAnalysis(evidence, { ...DEFAULTS, threatIntelEnabled: false });
    expect(disabled.signals.map((s) => s.id)).not.toContain('known-malicious-url');
  });
});
