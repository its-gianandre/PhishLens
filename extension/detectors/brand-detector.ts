import { BRANDS } from '../shared/constants';
import { getRegistrableDomain } from '../shared/domain';
import { makeSignal } from '../shared/signals';
import type { BrandEntry, BrandMatch, PageEvidence, Signal } from '../shared/types';

export interface BrandDetection {
  match: BrandMatch | null;
  signals: Signal[];
}

/** Confidence at or above which a domain mismatch becomes a signal. */
const MISMATCH_CONFIDENCE = 0.5;
const MAX_HITS_PER_SOURCE = 3;

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Builds a regex that tolerates the keyword being split by spaces, hyphens,
 * or zero-width characters ("Micro soft", "P-a-y-P-a-l"), while anchoring
 * both ends so substrings of larger words don't match ("purchase" ≠ "chase").
 */
export function fuzzyKeywordRegex(keyword: string): RegExp {
  const sep = '[\\s\\u200b\\u200c\\u200d\\u00ad\\-_.]{0,2}';
  const body = [...keyword.toLowerCase()]
    .map((ch) => (ch === ' ' ? '' : escapeRegExp(ch)))
    .join(sep);
  return new RegExp(`(?<![a-z0-9])${body}(?![a-z0-9])`, 'g');
}

const KEYWORD_REGEXES = new Map<string, RegExp>();
for (const brand of BRANDS) {
  for (const keyword of brand.keywords) {
    KEYWORD_REGEXES.set(keyword, fuzzyKeywordRegex(keyword));
  }
}

function countMatches(text: string, regex: RegExp): number {
  regex.lastIndex = 0;
  let count = 0;
  while (regex.exec(text) !== null && count < MAX_HITS_PER_SOURCE) count += 1;
  return count;
}

export function detectBrand(evidence: PageEvidence): BrandDetection {
  const sources: Array<{ text: string; weight: number }> = [
    { text: evidence.title.toLowerCase(), weight: 3 },
    { text: evidence.headings.join('\n').toLowerCase(), weight: 2 },
    { text: evidence.metaDescription.toLowerCase(), weight: 1 },
    { text: evidence.imageAltText.join('\n').toLowerCase(), weight: 1 },
    { text: evidence.visibleText.slice(0, 8000).toLowerCase(), weight: 1 },
  ];

  let best: { brand: BrandEntry; score: number } | null = null;
  for (const brand of BRANDS) {
    let score = 0;
    for (const keyword of brand.keywords) {
      const regex = KEYWORD_REGEXES.get(keyword)!;
      for (const source of sources) {
        score += countMatches(source.text, regex) * source.weight;
      }
    }
    if (score > 0 && (!best || score > best.score)) best = { brand, score };
  }

  if (!best) return { match: null, signals: [] };

  const confidence = best.score / (best.score + 3);
  const match: BrandMatch = {
    brand: best.brand.name,
    confidence: Math.round(confidence * 100) / 100,
    officialDomains: best.brand.domains,
  };

  const signals: Signal[] = [];
  let pageDomain = '';
  try {
    pageDomain = getRegistrableDomain(new URL(evidence.url).hostname);
  } catch {
    return { match, signals };
  }

  if (confidence >= MISMATCH_CONFIDENCE && !best.brand.domains.includes(pageDomain)) {
    signals.push(makeSignal('brand-domain-mismatch', 'brand',
      `The page presents itself as ${best.brand.name} but is hosted on "${pageDomain}", which is not an official ${best.brand.name} domain`,
      `claimed=${best.brand.name} actual=${pageDomain} confidence=${match.confidence}`));
  }

  return { match, signals };
}
