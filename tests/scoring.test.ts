import { describe, expect, it } from 'vitest';
import { calculateRisk, classify } from '../extension/scoring/calculate-risk';
import { makeSignal } from '../extension/shared/signals';
import type { Signal, SignalId } from '../extension/shared/types';

function signalsFor(...ids: SignalId[]): Signal[] {
  return ids.map((id) => makeSignal(id, 'url', 'test', 'test'));
}

describe('classify', () => {
  it('maps scores to the documented bands', () => {
    expect(classify(0)).toBe('Low');
    expect(classify(29)).toBe('Low');
    expect(classify(30)).toBe('Caution');
    expect(classify(59)).toBe('Caution');
    expect(classify(60)).toBe('High');
    expect(classify(79)).toBe('High');
    expect(classify(80)).toBe('Critical');
    expect(classify(100)).toBe('Critical');
  });
});

describe('calculateRisk', () => {
  it('returns 0/Low for no signals', () => {
    const risk = calculateRisk([]);
    expect(risk.score).toBe(0);
    expect(risk.classification).toBe('Low');
    expect(risk.breakdown).toEqual([]);
  });

  it('counts each signal id once', () => {
    const single = calculateRisk(signalsFor('password-field')).score;
    const doubled = calculateRisk(signalsFor('password-field', 'password-field')).score;
    expect(doubled).toBe(single);
  });

  it('applies the brand-mismatch + password combination bonus', () => {
    const risk = calculateRisk(signalsFor('brand-domain-mismatch', 'password-field'));
    // 20 + 5 + 35 combo — the classic phishing pattern lands in High.
    expect(risk.score).toBe(60);
    expect(risk.classification).toBe('High');
    expect(risk.breakdown.some((line) => line.points === 35)).toBe(true);
  });

  it('applies the external-action + password bonus', () => {
    const risk = calculateRisk(signalsFor('password-field', 'external-form-action'));
    expect(risk.score).toBe(45); // 5 + 25 + 15
  });

  it('rewards stacked social-engineering categories', () => {
    const twoCategories = calculateRisk(signalsFor('urgency-language', 'account-threat-language'));
    const threeCategories = calculateRisk(
      signalsFor('urgency-language', 'account-threat-language', 'credential-request-language'),
    );
    expect(twoCategories.score).toBe(12);
    expect(threeCategories.score).toBe(28); // 5 + 7 + 6 + 10 bonus
  });

  it('clamps to 100', () => {
    const everything = calculateRisk(signalsFor(
      'known-malicious-url', 'external-form-action', 'brand-domain-mismatch',
      'punycode-host', 'ip-address-host', 'password-field', 'sensitive-field',
      'urgency-language', 'account-threat-language', 'credential-request-language',
    ));
    expect(everything.score).toBe(100);
    expect(everything.classification).toBe('Critical');
  });

  it('breakdown totals match the pre-clamp arithmetic', () => {
    const risk = calculateRisk(signalsFor('password-field', 'urgency-language'));
    const total = risk.breakdown.reduce((sum, line) => sum + line.points, 0);
    expect(total).toBe(risk.score);
  });
});
