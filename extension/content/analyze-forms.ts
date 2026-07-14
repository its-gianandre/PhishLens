import { SENSITIVE_FIELD_RULES, LIMITS } from '../shared/constants';
import { getRegistrableDomain, isLoopback } from '../shared/domain';
import type { FormEvidence } from '../shared/types';

/**
 * Classifies a field as sensitive by its type and descriptive attributes.
 * Never reads the field's value.
 */
export function classifySensitiveField(el: Element): string | null {
  const type = (el.getAttribute('type') ?? '').toLowerCase();
  if (type === 'password') return 'password';
  const descriptor = ['name', 'id', 'autocomplete', 'placeholder', 'aria-label']
    .map((attr) => el.getAttribute(attr) ?? '')
    .join(' ')
    .toLowerCase();
  if (!descriptor.trim()) return null;
  for (const rule of SENSITIVE_FIELD_RULES) {
    if (rule.pattern.test(descriptor)) return rule.label;
  }
  return null;
}

export function analyzeForms(doc: Document, pageUrl: string): FormEvidence[] {
  let pageHost = '';
  try {
    pageHost = new URL(pageUrl).hostname;
  } catch {
    return [];
  }
  const pageDomain = getRegistrableDomain(pageHost);

  const forms = [...doc.querySelectorAll('form')].slice(0, LIMITS.formsPerPage);
  return forms.map((form) => {
    // form.action the property can be shadowed by an <input name="action">,
    // so always go through the attribute.
    const rawAction = (form.getAttribute('action') ?? '').trim();
    let actionUrl: URL | null = null;
    if (!rawAction.toLowerCase().startsWith('javascript:')) {
      try {
        actionUrl = new URL(rawAction || pageUrl, pageUrl);
      } catch {
        actionUrl = null;
      }
    }

    let hasPassword = false;
    const sensitiveFields: string[] = [];
    const hiddenSensitiveFields: string[] = [];
    for (const el of form.querySelectorAll('input, select, textarea')) {
      const label = classifySensitiveField(el);
      if (!label) continue;
      const type = (el.getAttribute('type') ?? '').toLowerCase();
      if (type === 'hidden') {
        hiddenSensitiveFields.push(label);
      } else {
        sensitiveFields.push(label);
        if (label === 'password') hasPassword = true;
      }
    }

    const actionHost = actionUrl?.hostname ?? pageHost;
    const actionDomain = getRegistrableDomain(actionHost);
    const secureSubmission =
      (actionUrl?.protocol ?? 'https:') === 'https:' || isLoopback(actionHost);
    const jsIntercepted =
      form.hasAttribute('onsubmit') ||
      rawAction === '' ||
      rawAction.toLowerCase().startsWith('javascript:');

    return {
      action: actionUrl?.href ?? '',
      method: (form.getAttribute('method') ?? 'get').toLowerCase(),
      hasPassword,
      sensitiveFields: [...new Set(sensitiveFields)],
      hiddenSensitiveFields: [...new Set(hiddenSensitiveFields)],
      pageDomain,
      actionDomain,
      crossDomain: actionDomain !== pageDomain,
      secureSubmission,
      jsIntercepted,
    };
  });
}
