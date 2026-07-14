import { describe, expect, it } from 'vitest';
import { detectLanguageSignals } from '../extension/detectors/language-detector';
import { makeEvidence } from './helpers';
import type { SignalId } from '../extension/shared/types';

function ids(text: string, title = ''): SignalId[] {
  return detectLanguageSignals(makeEvidence({ title, visibleText: text })).map((s) => s.id);
}

describe('detectLanguageSignals', () => {
  it('detects each category', () => {
    expect(ids('You must act immediately to keep access.')).toContain('urgency-language');
    expect(ids('Your account will be suspended tomorrow.')).toContain('account-threat-language');
    expect(ids('Please verify your password to continue.')).toContain('credential-request-language');
    expect(ids('Your payment failed. Update billing information.')).toContain('financial-pressure-language');
    expect(ids('This is an official notice from the security team.')).toContain('authority-language');
    expect(ids('Congratulations, you have been selected! Claim your prize.')).toContain('reward-language');
  });

  it('emits at most one signal per category', () => {
    const found = ids('Act now! Act immediately! This is urgent and expires today.');
    expect(found.filter((id) => id === 'urgency-language')).toHaveLength(1);
  });

  it('includes the matched phrase as evidence', () => {
    const signals = detectLanguageSignals(makeEvidence({
      visibleText: 'Your account will be suspended unless you respond.',
    }));
    expect(signals[0].evidence).toContain('account will be suspended');
  });

  it('stays silent on neutral text', () => {
    expect(ids('Welcome to our documentation. Browse guides and API references.')).toEqual([]);
  });

  it('scans the title and headings too', () => {
    expect(ids('', 'URGENT: verify your password')).toEqual(
      expect.arrayContaining(['urgency-language', 'credential-request-language']),
    );
  });
});
