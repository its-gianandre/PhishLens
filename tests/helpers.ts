import type { FormEvidence, PageEvidence } from '../extension/shared/types';

export function makeEvidence(partial: Partial<PageEvidence> = {}): PageEvidence {
  return {
    url: 'https://example.com/',
    title: '',
    visibleText: '',
    headings: [],
    imageAltText: [],
    metaDescription: '',
    faviconUrl: '',
    passwordFieldCount: 0,
    emailFieldCount: 0,
    forms: [],
    ...partial,
  };
}

export function makeForm(partial: Partial<FormEvidence> = {}): FormEvidence {
  return {
    action: 'https://example.com/session',
    method: 'post',
    hasPassword: false,
    sensitiveFields: [],
    hiddenSensitiveFields: [],
    pageDomain: 'example.com',
    actionDomain: 'example.com',
    crossDomain: false,
    secureSubmission: true,
    jsIntercepted: false,
    ...partial,
  };
}
