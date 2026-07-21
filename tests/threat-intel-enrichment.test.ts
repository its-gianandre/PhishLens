import { describe, expect, it } from 'vitest';
import {
  applyThreatIntel,
  isSameAnalysis,
  unavailableThreatIntel,
} from '../extension/background/enrichment';
import { runAnalysis } from '../extension/background/pipeline';
import { threatIntelToSignals } from '../extension/detectors/threat-intel-result';
import type { ThreatIntelFinding, ThreatIntelSummary } from '../extension/shared/types';
import { makeEvidence } from './helpers';

function finding(overrides: Partial<ThreatIntelFinding> = {}): ThreatIntelFinding {
  return {
    provider: 'phishtank',
    available: true,
    matched: true,
    category: 'phishing',
    matchType: 'exact-url',
    confidence: 'high',
    targetBrand: 'Example Mail',
    referenceUrl: null,
    verificationTime: '2026-07-15T10:05:00Z',
    submissionTime: null,
    status: 'online',
    threat: 'phishing',
    tags: [],
    ...overrides,
  };
}

function summary(findings: ThreatIntelFinding[]): ThreatIntelSummary {
  return { status: 'complete', checkedAt: Date.now(), findings };
}

describe('threat-intel signal conversion', () => {
  it('emits one scored signal for duplicate exact findings', () => {
    const signals = threatIntelToSignals(summary([
      finding(),
      finding({ provider: 'openphish', targetBrand: null }),
    ]));
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('known-malicious-url');
    expect(signals[0].evidence).toMatch(/PhishTank and OpenPhish/);
  });

  it('scores an exact OpenPhish match as known phishing', () => {
    const signals = threatIntelToSignals(summary([
      finding({ provider: 'openphish', targetBrand: null }),
    ]));
    expect(signals.map((signal) => signal.id)).toEqual(['known-malicious-url']);
  });

  it('does not score hostname-only findings', () => {
    expect(threatIntelToSignals(summary([
      finding({ matchType: 'hostname', confidence: 'medium' }),
    ]))).toEqual([]);
  });

  it('scores only exact URLhaus matches that are currently online', () => {
    const urlhaus = finding({
      provider: 'urlhaus',
      category: 'malware',
      targetBrand: null,
      threat: 'malware_download',
      tags: ['exe'],
    });
    expect(threatIntelToSignals(summary([urlhaus])).map((signal) => signal.id))
      .toEqual(['known-malware-url']);
    expect(threatIntelToSignals(summary([{ ...urlhaus, status: 'offline' }]))).toEqual([]);
    expect(threatIntelToSignals(summary([{ ...urlhaus, matchType: 'hostname' }]))).toEqual([]);
  });
});

describe('asynchronous enrichment state transitions', () => {
  it('returns local analysis immediately in a pending state', () => {
    const local = runAnalysis(makeEvidence(), {
      threatIntelEnabled: true,
      approvedDomains: [],
    });
    expect(local.threatIntel.status).toBe('pending');
    expect(local.signals.some((signal) => signal.id === 'known-malicious-url')).toBe(false);
  });

  it('rescoring an exact match increases or preserves risk and recommendation', () => {
    const local = runAnalysis(makeEvidence({ passwordFieldCount: 1 }), {
      threatIntelEnabled: true,
      approvedDomains: [],
    });
    const enriched = applyThreatIntel(local, summary([finding()]));
    expect(enriched.score).toBeGreaterThanOrEqual(local.score);
    expect(enriched.signals.map((signal) => signal.id)).toContain('known-malicious-url');
    expect(enriched.recommendedAction).not.toBe('');
  });

  it('backend failure preserves local signals and score', () => {
    const local = runAnalysis(makeEvidence(), {
      threatIntelEnabled: true,
      approvedDomains: [],
    });
    const enriched = applyThreatIntel(local, unavailableThreatIntel());
    expect(enriched.score).toBe(local.score);
    expect(enriched.signals).toEqual(local.signals);
    expect(enriched.threatIntel.status).toBe('unavailable');
  });

  it('disabled and approved-domain analyses do not request enrichment', () => {
    const disabled = runAnalysis(makeEvidence(), {
      threatIntelEnabled: false,
      approvedDomains: [],
    });
    expect(disabled.threatIntel.status).toBe('disabled');

    const approved = runAnalysis(makeEvidence(), {
      threatIntelEnabled: true,
      approvedDomains: ['example.com'],
    });
    expect(approved.overridden).toBe(true);
    expect(approved.threatIntel.status).toBe('disabled');
  });

  it('rejects a late result for an older analysis generation', () => {
    const first = runAnalysis(makeEvidence(), {
      threatIntelEnabled: true,
      approvedDomains: [],
    });
    const second = runAnalysis(makeEvidence(), {
      threatIntelEnabled: true,
      approvedDomains: [],
    });
    expect(isSameAnalysis(second, first)).toBe(false);
    expect(isSameAnalysis(first, first)).toBe(true);
  });
});
