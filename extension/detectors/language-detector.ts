import { LANGUAGE_RULES } from '../shared/constants';
import { makeSignal } from '../shared/signals';
import type { PageEvidence, Signal } from '../shared/types';

type LanguageEvidence = Pick<PageEvidence, 'title' | 'headings' | 'visibleText'>;

/**
 * Deterministic social-engineering language detection.
 * At most one signal per category; evidence is the first matched phrase.
 */
export function detectLanguageSignals(evidence: LanguageEvidence): Signal[] {
  const haystack = [evidence.title, ...evidence.headings, evidence.visibleText].join('\n');
  const signals: Signal[] = [];

  for (const rule of LANGUAGE_RULES) {
    for (const pattern of rule.patterns) {
      const match = haystack.match(pattern);
      if (match) {
        signals.push(makeSignal(rule.signal, 'language', rule.description, `"${match[0]}"`));
        break;
      }
    }
  }

  return signals;
}
