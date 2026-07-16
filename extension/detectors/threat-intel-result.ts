import { makeSignal } from '../shared/signals';
import type { Signal, ThreatIntelSummary } from '../shared/types';

/**
 * Convert normalized provider evidence into detector-owned signals.
 * Only an exact verified URL match affects scoring in this first version.
 */
export function threatIntelToSignals(summary: ThreatIntelSummary): Signal[] {
  const exact = summary.findings.find((finding) => (
    finding.available &&
    finding.matched &&
    finding.category === 'phishing' &&
    finding.matchType === 'exact-url'
  ));

  if (!exact) return [];

  const target = exact.targetBrand ? ` Target: ${exact.targetBrand}` : '';
  return [
    makeSignal(
      'known-malicious-url',
      'threat-intel',
      'The exact URL appears in the PhishTank verified phishing database',
      `PhishTank exact URL match.${target}`,
    ),
  ];
}
