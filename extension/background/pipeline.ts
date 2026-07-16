import { detectBrand } from '../detectors/brand-detector';
import { detectFormSignals } from '../detectors/form-detector';
import { detectLanguageSignals } from '../detectors/language-detector';
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
  const analyzedAt = Date.now();
  const analysisId = `${analyzedAt}-${Math.random().toString(36).slice(2)}`;
  let domain = '';
  try {
    domain = getRegistrableDomain(new URL(evidence.url).hostname);
  } catch {
    // leave domain empty; URL detector will also produce nothing
  }

  if (domain && opts.approvedDomains.includes(domain)) {
    return {
      analysisId,
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
      threatIntel: { status: 'disabled', checkedAt: null, findings: [] },
      analyzedAt,
    };
  }

  const brand = detectBrand(evidence);
  const signals: Signal[] = [
    ...detectUrlSignals(evidence.url),
    ...brand.signals,
    ...detectFormSignals(evidence),
    ...detectLanguageSignals(evidence),
  ];

  const { score, classification, breakdown } = calculateRisk(signals);

  return {
    analysisId,
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
    threatIntel: {
      status: opts.threatIntelEnabled ? 'pending' : 'disabled',
      checkedAt: null,
      findings: [],
    },
    analyzedAt,
  };
}
