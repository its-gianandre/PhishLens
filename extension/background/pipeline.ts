import { detectBrand } from '../detectors/brand-detector';
import { detectFormSignals } from '../detectors/form-detector';
import { detectLanguageSignals } from '../detectors/language-detector';
import { lookupKnownThreat } from '../detectors/threat-intel';
import { detectUrlSignals } from '../detectors/url-detector';
import { calculateRisk } from '../scoring/calculate-risk';
import { RECOMMENDED_ACTIONS } from '../shared/constants';
import { getRegistrableDomain } from '../shared/domain';
import type { AnalysisResult, PageEvidence, Signal } from '../shared/types';

export interface PipelineOptions {
  threatIntelEnabled: boolean;
  approvedDomains: string[];
}

/**
 * The full deterministic pipeline: evidence → detectors → signals → score.
 * Pure function (no chrome.* APIs) so it is directly unit-testable.
 */
export function runAnalysis(evidence: PageEvidence, opts: PipelineOptions): AnalysisResult {
  let domain = '';
  try {
    domain = getRegistrableDomain(new URL(evidence.url).hostname);
  } catch {
    // leave domain empty; URL detector will also produce nothing
  }

  if (domain && opts.approvedDomains.includes(domain)) {
    return {
      url: evidence.url,
      domain,
      score: 0,
      classification: 'Low',
      suspectedBrand: null,
      brandConfidence: null,
      signals: [],
      scoreBreakdown: [],
      recommendedAction: `You marked "${domain}" as trusted, so analysis was skipped. Remove it from approved domains to re-enable checks.`,
      overridden: true,
      analyzedAt: Date.now(),
    };
  }

  const brand = detectBrand(evidence);
  const signals: Signal[] = [
    ...detectUrlSignals(evidence.url),
    ...brand.signals,
    ...detectFormSignals(evidence),
    ...detectLanguageSignals(evidence),
  ];

  if (opts.threatIntelEnabled) {
    const threat = lookupKnownThreat(evidence.url);
    if (threat) signals.push(threat);
  }

  const { score, classification, breakdown } = calculateRisk(signals);

  return {
    url: evidence.url,
    domain,
    score,
    classification,
    suspectedBrand: brand.match?.brand ?? null,
    brandConfidence: brand.match?.confidence ?? null,
    signals,
    scoreBreakdown: breakdown,
    recommendedAction: RECOMMENDED_ACTIONS[classification],
    overridden: false,
    analyzedAt: Date.now(),
  };
}
