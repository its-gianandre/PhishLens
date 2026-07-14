import { makeSignal } from '../shared/signals';
import type { PageEvidence, Signal } from '../shared/types';

export function detectFormSignals(evidence: PageEvidence): Signal[] {
  const signals: Signal[] = [];
  const forms = evidence.forms;

  const passwordCount =
    evidence.passwordFieldCount || forms.filter((f) => f.hasPassword).length;
  if (passwordCount > 0) {
    signals.push(makeSignal('password-field', 'form',
      'The page asks for a password',
      `${passwordCount} password field(s)`));
  }

  const otherSensitive = new Set(
    forms.flatMap((f) => f.sensitiveFields).filter((label) => label !== 'password'),
  );
  if (otherSensitive.size > 0) {
    signals.push(makeSignal('sensitive-field', 'form',
      'The page asks for other sensitive information',
      [...otherSensitive].join(', ')));
  }

  const sensitiveForms = forms.filter(
    (f) => f.hasPassword || f.sensitiveFields.length > 0,
  );

  const external = sensitiveForms.find((f) => f.crossDomain);
  if (external) {
    signals.push(makeSignal('external-form-action', 'form',
      `A form collecting sensitive data submits to "${external.actionDomain}", a different domain than the page ("${external.pageDomain}")`,
      external.action));
  }

  const insecure = sensitiveForms.find((f) => !f.secureSubmission);
  if (insecure) {
    signals.push(makeSignal('insecure-form-action', 'form',
      'A form collecting sensitive data submits over unencrypted HTTP',
      insecure.action));
  }

  const hidden = forms.find((f) => f.hiddenSensitiveFields.length > 0);
  if (hidden) {
    signals.push(makeSignal('hidden-sensitive-field', 'form',
      'A form contains hidden fields with sensitive-looking names',
      hidden.hiddenSensitiveFields.join(', ')));
  }

  const intercepted = sensitiveForms.find((f) => f.jsIntercepted && f.hasPassword);
  if (intercepted) {
    signals.push(makeSignal('js-intercepted-form', 'form',
      'A password form is handled by JavaScript instead of a normal submission, hiding its true destination',
      intercepted.action || '(no action attribute)'));
  }

  return signals;
}
