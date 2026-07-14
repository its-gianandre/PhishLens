import { LIMITS, SIGNAL_WEIGHTS } from './constants';
import type { DetectorName, Severity, Signal, SignalId } from './types';

/** Collapse whitespace and cap length so evidence stays a snippet, never a payload. */
export function snippet(text: string): string {
  return text.replace(/\s+/g, ' ').trim().slice(0, LIMITS.evidenceSnippetChars);
}

function severityFor(id: SignalId): Severity {
  const weight = SIGNAL_WEIGHTS[id];
  if (weight >= 20) return 'high';
  if (weight >= 10) return 'medium';
  return 'low';
}

export function makeSignal(
  id: SignalId,
  detector: DetectorName,
  description: string,
  evidence: string,
): Signal {
  return { id, detector, severity: severityFor(id), description, evidence: snippet(evidence) };
}
