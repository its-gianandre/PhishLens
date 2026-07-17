import { threatIntelToSignals } from '../detectors/threat-intel-result';
import { calculateRisk } from '../scoring/calculate-risk';
import { RECOMMENDED_ACTIONS } from '../shared/constants';
import type {
  AnalysisResult,
  ThreatIntelFinding,
  ThreatIntelSummary,
} from '../shared/types';

export function unavailableThreatIntel(checkedAt = Date.now()): ThreatIntelSummary {
  const finding = (provider: ThreatIntelFinding['provider']): ThreatIntelFinding => ({
    provider,
    available: false,
    matched: false,
    category: null,
    matchType: null,
    confidence: null,
    targetBrand: null,
    referenceUrl: null,
    verificationTime: null,
    submissionTime: null,
    status: null,
    threat: null,
    tags: [],
  });
  return { status: 'unavailable', checkedAt, findings: [finding('phishtank'), finding('urlhaus')] };
}

export function applyThreatIntel(
  initial: AnalysisResult,
  threatIntel: ThreatIntelSummary,
): AnalysisResult {
  const localSignals = initial.signals.filter((signal) => (
    signal.id !== 'known-malicious-url' && signal.id !== 'known-malware-url'
  ));
  const signals = [...localSignals, ...threatIntelToSignals(threatIntel)];
  const { score, classification, breakdown } = calculateRisk(signals);

  return {
    ...initial,
    signals,
    score,
    classification,
    scoreBreakdown: breakdown,
    recommendedAction: RECOMMENDED_ACTIONS[classification],
    threatIntel,
  };
}

export function isSameAnalysis(
  current: AnalysisResult | null | undefined,
  expected: AnalysisResult,
): boolean {
  return Boolean(
    current &&
    current.analysisId === expected.analysisId &&
    current.url === expected.url,
  );
}
