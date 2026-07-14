import {
  COMBO_BRAND_PLUS_LANGUAGE,
  COMBO_MULTI_LANGUAGE,
  LANGUAGE_SIGNAL_IDS,
  PAIR_COMBOS,
  RISK_BANDS,
  SIGNAL_LABELS,
  SIGNAL_WEIGHTS,
} from '../shared/constants';
import type { RiskClass, ScoreLine, Signal, SignalId } from '../shared/types';

export interface RiskAssessment {
  score: number;
  classification: RiskClass;
  breakdown: ScoreLine[];
}

export function classify(score: number): RiskClass {
  for (const band of RISK_BANDS) {
    if (score >= band.min) return band.classification;
  }
  return 'Low';
}

/**
 * The only place evidence becomes a number. Each signal id counts once;
 * combination bonuses reward dangerous groupings; result clamps to 0–100.
 */
export function calculateRisk(signals: Signal[]): RiskAssessment {
  const present = new Set<SignalId>(signals.map((s) => s.id));
  const breakdown: ScoreLine[] = [];
  let score = 0;

  for (const id of present) {
    const points = SIGNAL_WEIGHTS[id] ?? 0;
    score += points;
    breakdown.push({ label: SIGNAL_LABELS[id] ?? id, points });
  }
  breakdown.sort((a, b) => b.points - a.points);

  for (const combo of PAIR_COMBOS) {
    if (combo.requires.every((id) => present.has(id))) {
      score += combo.bonus;
      breakdown.push({ label: combo.label, points: combo.bonus });
    }
  }

  const languageCategories = [...present].filter((id) => LANGUAGE_SIGNAL_IDS.has(id)).length;
  if (present.has('brand-domain-mismatch') && languageCategories > 0) {
    score += COMBO_BRAND_PLUS_LANGUAGE.bonus;
    breakdown.push({ label: COMBO_BRAND_PLUS_LANGUAGE.label, points: COMBO_BRAND_PLUS_LANGUAGE.bonus });
  }
  if (languageCategories >= COMBO_MULTI_LANGUAGE.minCategories) {
    score += COMBO_MULTI_LANGUAGE.bonus;
    breakdown.push({ label: COMBO_MULTI_LANGUAGE.label, points: COMBO_MULTI_LANGUAGE.bonus });
  }

  score = Math.max(0, Math.min(100, Math.round(score)));
  return { score, classification: classify(score), breakdown };
}
