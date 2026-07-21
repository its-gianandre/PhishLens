import { makeSignal } from '../shared/signals';
import type { Signal, ThreatIntelSummary } from '../shared/types';

/**
 * Convert normalized provider evidence into detector-owned signals.
 * Only an exact verified URL match affects scoring in this first version.
 */
export function threatIntelToSignals(summary: ThreatIntelSummary): Signal[] {
  const phishingExact = summary.findings.filter((finding) => (
    (finding.provider === 'phishtank' || finding.provider === 'openphish') &&
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
  if (phishingExact.length) {
    const providers = [...new Set(phishingExact.map((finding) => finding.provider))]
      .map((provider) => provider === 'phishtank' ? 'PhishTank' : 'OpenPhish');
    const targetBrand = phishingExact.find((finding) => finding.targetBrand)?.targetBrand;
    const target = targetBrand ? ` Target: ${targetBrand}` : '';
    signals.push(makeSignal(
      'known-malicious-url',
      'threat-intel',
      'The exact URL appears in a known phishing feed',
      `${providers.join(' and ')} exact URL match.${target}`,
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
