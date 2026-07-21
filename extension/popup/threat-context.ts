import type { Signal } from '../shared/types';

type SignalReference = Pick<Signal, 'id'>;

function joinConcerns(concerns: string[]): string {
  if (concerns.length === 1) return concerns[0];
  if (concerns.length === 2) return `${concerns[0]} and ${concerns[1]}`;
  return `${concerns.slice(0, -1).join(', ')}, and ${concerns.at(-1)}`;
}

/** Summarize the strongest page-level evidence without attributing it to a feed. */
export function describePageThreat(
  signals: ReadonlyArray<SignalReference>,
): string | null {
  const ids = new Set(signals.map((signal) => signal.id));
  const concerns: string[] = [];

  if (ids.has('password-field') && ids.has('js-intercepted-form')) {
    concerns.push(
      'asks for a password while JavaScript handles the form instead of a normal submission, so the credential destination is not visible in the form action',
    );
  } else {
    if (ids.has('password-field')) concerns.push('asks for a password');
    if (ids.has('js-intercepted-form')) {
      concerns.push(
        'uses JavaScript instead of a normal form submission, so its destination is not visible in the form action',
      );
    }
  }

  if (ids.has('external-form-action')) {
    concerns.push('sends submitted form data to a different domain');
  }
  if (ids.has('brand-domain-mismatch')) {
    concerns.push('claims a brand that does not match its actual domain');
  }
  if (ids.has('sensitive-field')) concerns.push('requests other sensitive information');
  if (
    ids.has('urgency-language') ||
    ids.has('account-threat-language') ||
    ids.has('credential-request-language')
  ) concerns.push('uses pressure or credential-request language');

  if (concerns.length === 0) return null;
  return `PhishLens also found that this page ${joinConcerns(concerns.slice(0, 3))}.`;
}
