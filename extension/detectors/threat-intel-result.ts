import { makeSignal } from '../shared/signals';
import type { Signal, ThreatIntelSummary } from '../shared/types';

/**
 * Convert normalized provider evidence into detector-owned signals.
 * Only an exact verified URL match affects scoring in this first version.
 */
export function threatIntelToSignals(summary: ThreatIntelSummary): Signal[] {
  const phishtankExact = summary.findings.find((finding) => (
    finding.provider === 'phishtank' &&
    finding.available &&
    finding.matched &&
    finding.category === 'phishing' &&
    finding.matchType === 'exact-url'
  ));

  const urlhausExact = summary.findings.find((finding) => (
    finding.provider === 'urlhaus' &&
    finding.available &&
    finding.matched &&
    finding.category === 'malware' &&
    finding.matchType === 'exact-url' &&
    finding.status?.toLowerCase() === 'online'
  ));

  const signals: Signal[] = [];
  if (phishtankExact) {
    const target = phishtankExact.targetBrand ? ` Target: ${phishtankExact.targetBrand}` : '';
    signals.push(makeSignal(
      'known-malicious-url',
      'threat-intel',
      'The exact URL appears in the PhishTank verified phishing database',
      `PhishTank exact URL match.${target}`,
    ));
  }
  if (urlhausExact) {
    const tags = urlhausExact.tags.length ? ` Tags: ${urlhausExact.tags.join(', ')}.` : '';
    signals.push(makeSignal(
      'known-malware-url',
      'threat-intel',
      'The exact URL appears as online in the URLhaus malware-distribution database',
      `URLhaus exact active URL match.${tags}`,
    ));
  }
  return signals;
}
