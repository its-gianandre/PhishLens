import { LIMITS } from '../shared/constants';
import type { PageEvidence } from '../shared/types';
import { analyzeForms } from './analyze-forms';

function normalize(text: string): string {
  return text.replace(/\s+/g, ' ').trim();
}

/**
 * Collects the page evidence the detectors need. Never collects entered
 * values, cookies, auth tokens, or the full page HTML.
 */
export function extractPageEvidence(
  doc: Document = document,
  url: string = location.href,
): PageEvidence {
  const body = doc.body as (HTMLElement & { innerText?: string }) | null;
  // innerText reflects what the user actually sees; textContent is the
  // fallback for environments without layout (jsdom).
  const rawText = body?.innerText ?? body?.textContent ?? '';

  const headings = [...doc.querySelectorAll('h1, h2, h3')]
    .slice(0, LIMITS.headings)
    .map((h) => normalize(h.textContent ?? ''))
    .filter(Boolean);

  const imageAltText = [...doc.querySelectorAll('img[alt]')]
    .slice(0, LIMITS.altTexts)
    .map((img) => normalize(img.getAttribute('alt') ?? ''))
    .filter(Boolean);

  const favicon = doc.querySelector<HTMLLinkElement>('link[rel~="icon"]');

  return {
    url,
    title: normalize(doc.title ?? ''),
    visibleText: normalize(rawText).slice(0, LIMITS.visibleTextChars),
    headings,
    imageAltText,
    metaDescription: normalize(
      doc.querySelector('meta[name="description"]')?.getAttribute('content') ?? '',
    ),
    faviconUrl: favicon?.href ?? '',
    passwordFieldCount: doc.querySelectorAll('input[type="password"]').length,
    emailFieldCount: doc.querySelectorAll('input[type="email"], input[name*="email" i]').length,
    forms: analyzeForms(doc, url),
  };
}
