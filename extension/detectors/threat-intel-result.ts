import { makeSignal } from '../shared/signals';
import type { Signal, ThreatIntelSummary } from '../shared/types';

/**
 * Convert normalized provider evidence into detector-owned signals.
 * Exact URL-feed matches and direct Block List Project domain matches affect scoring.
 * Multiple providers still collapse into one phishing signal.
 */
export function threatIntelToSignals(summary: ThreatIntelSummary): Signal[] {
  const phishingMatches = summary.findings.filter((finding) => (
    finding.available &&
    finding.matched &&
    finding.category === 'phishing' &&
    (
      ((finding.provider === 'phishtank' || finding.provider === 'openphish') &&
        finding.matchType === 'exact-url') ||
      (finding.provider === 'blocklist-project' &&
        (finding.matchType === 'hostname' || finding.matchType === 'registrable-domain'))
    )
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
  if (phishingMatches.length) {
    const providers = [...new Set(phishingMatches.map((finding) => finding.provider))]
      .map((provider) => ({
        phishtank: 'PhishTank',
        urlhaus: 'URLhaus',
        openphish: 'OpenPhish',
        'blocklist-project': 'Block List Project',
      })[provider]);
    const targetBrand = phishingMatches.find((finding) => finding.targetBrand)?.targetBrand;
    const target = targetBrand ? ` Target: ${targetBrand}` : '';
    signals.push(makeSignal(
      'known-malicious-url',
      'threat-intel',
      'This site appears in a known phishing feed',
      `${providers.join(' and ')} phishing match.${target}`,
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
