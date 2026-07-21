import { describe, expect, it } from 'vitest';
import { describePageThreat } from '../extension/popup/threat-context';

describe('threat-intelligence page context', () => {
  it('explains the specific credential risk on the OpenPhish demo page', () => {
    const description = describePageThreat([
      { id: 'password-field' },
      { id: 'js-intercepted-form' },
      { id: 'known-malicious-url' },
    ]);

    expect(description).toMatch(/asks for a password/i);
    expect(description).toMatch(/JavaScript handles the form/i);
    expect(description).toMatch(/credential destination is not visible/i);
  });

  it('does not invent page behavior when only a feed match exists', () => {
    expect(describePageThreat([{ id: 'known-malicious-url' }])).toBeNull();
  });

  it('prioritizes other concrete high-risk page behavior', () => {
    const description = describePageThreat([
      { id: 'external-form-action' },
      { id: 'brand-domain-mismatch' },
      { id: 'sensitive-field' },
    ]);

    expect(description).toMatch(/different domain/i);
    expect(description).toMatch(/brand that does not match/i);
    expect(description).toMatch(/other sensitive information/i);
  });
});
