import { describe, expect, it } from 'vitest';
import { detectFormSignals } from '../extension/detectors/form-detector';
import { makeEvidence, makeForm } from './helpers';
import type { SignalId } from '../extension/shared/types';

function ids(evidence: Parameters<typeof detectFormSignals>[0]): SignalId[] {
  return detectFormSignals(evidence).map((s) => s.id);
}

describe('detectFormSignals', () => {
  it('flags password and other sensitive fields', () => {
    const evidence = makeEvidence({
      passwordFieldCount: 1,
      forms: [makeForm({ hasPassword: true, sensitiveFields: ['password', 'mfa-code'] })],
    });
    const found = ids(evidence);
    expect(found).toContain('password-field');
    expect(found).toContain('sensitive-field');
  });

  it('flags cross-domain submission only for sensitive forms', () => {
    const searchForm = makeForm({
      crossDomain: true,
      actionDomain: 'search-partner.com',
    });
    expect(ids(makeEvidence({ forms: [searchForm] }))).not.toContain('external-form-action');

    const credentialForm = makeForm({
      hasPassword: true,
      sensitiveFields: ['password'],
      crossDomain: true,
      actionDomain: 'evil.com',
    });
    expect(ids(makeEvidence({ forms: [credentialForm] }))).toContain('external-form-action');
  });

  it('flags insecure submission of sensitive data', () => {
    const form = makeForm({
      hasPassword: true,
      sensitiveFields: ['password'],
      secureSubmission: false,
      action: 'http://plain.example.com/login',
    });
    expect(ids(makeEvidence({ forms: [form] }))).toContain('insecure-form-action');
  });

  it('flags hidden sensitive fields and JS-intercepted password forms', () => {
    const evidence = makeEvidence({
      forms: [makeForm({
        hasPassword: true,
        sensitiveFields: ['password'],
        hiddenSensitiveFields: ['access-token'],
        jsIntercepted: true,
      })],
    });
    const found = ids(evidence);
    expect(found).toContain('hidden-sensitive-field');
    expect(found).toContain('js-intercepted-form');
  });

  it('is silent for a plain page with no forms', () => {
    expect(ids(makeEvidence())).toEqual([]);
  });
});
