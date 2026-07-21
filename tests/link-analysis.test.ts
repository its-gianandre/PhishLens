import { describe, expect, it } from 'vitest';
import { assessLink } from '../extension/background/link-analysis';
import type { LinkCandidate, ThreatIntelFinding, ThreatIntelSummary } from '../extension/shared/types';

function candidate(partial: Partial<LinkCandidate> = {}): LinkCandidate {
  return {
    key: 'https://example.net/',
    lookupUrl: 'https://example.net/',
    urlSignalIds: [],
    contextSignalIds: [],
    ...partial,
  };
}

function finding(partial: Partial<ThreatIntelFinding> = {}): ThreatIntelFinding {
  return {
    provider: 'phishtank',
    available: true,
    matched: false,
    category: null,
    matchType: null,
    confidence: null,
    targetBrand: null,
    referenceUrl: null,
    verificationTime: null,
    submissionTime: null,
    status: null,
    threat: null,
    tags: [],
    ...partial,
  };
}

function summary(findings: ThreatIntelFinding[] = []): ThreatIntelSummary {
  return { status: 'complete', checkedAt: Date.now(), findings };
}

describe('embedded-link assessment', () => {
  it('does not warn based on persuasive surrounding text alone', () => {
    const result = assessLink(candidate({
      contextSignalIds: ['urgency-language', 'reward-language'],
    }), summary());
    expect(result.risk).toBe('safe');
    expect(result.score).toBe(0);
  });

  it('marks obfuscated destinations as suspicious and uses context as support', () => {
    const result = assessLink(candidate({
      urlSignalIds: ['url-shortener'],
      contextSignalIds: ['reward-language'],
    }), summary());
    expect(result.risk).toBe('suspicious');
    expect(result.reasons).toEqual(expect.arrayContaining([
      'URL-shortening service',
      'The surrounding message promises a prize, gift, or reward',
    ]));
  });

  it('escalates stacked brand impersonation, URL, and context evidence', () => {
    const result = assessLink(candidate({
      urlSignalIds: ['brand-in-hostname', 'suspicious-url-keyword'],
      contextSignalIds: ['reward-language'],
    }), summary());
    expect(result.risk).toBe('high');
    expect(result.score).toBeGreaterThanOrEqual(30);
  });

  it('blocks an exact verified phishing match', () => {
    const result = assessLink(candidate(), summary([finding({
      matched: true,
      category: 'phishing',
      matchType: 'exact-url',
      confidence: 'high',
    })]));
    expect(result.risk).toBe('high');
    expect(result.score).toBe(80);
  });

  it('blocks a local Block List Project domain match', () => {
    const result = assessLink(candidate(), summary([finding({
      provider: 'blocklist-project',
      matched: true,
      category: 'phishing',
      matchType: 'hostname',
      confidence: 'high',
      status: 'listed',
    })]));
    expect(result.risk).toBe('high');
    expect(result.score).toBe(80);
  });

  it('uses a hostname-only feed finding as a non-blocking warning', () => {
    const result = assessLink(candidate(), summary([finding({
      matched: true,
      category: 'phishing',
      matchType: 'hostname',
      confidence: 'medium',
    })]));
    expect(result.risk).toBe('suspicious');
  });
});
