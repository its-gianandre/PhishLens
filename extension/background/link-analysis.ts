import { SIGNAL_LABELS, SIGNAL_WEIGHTS } from '../shared/constants';
import type {
  LinkAssessment,
  LinkCandidate,
  LinkContextSignalId,
  LinkUrlSignalId,
  ThreatIntelFinding,
  ThreatIntelSummary,
} from '../shared/types';

const CONTEXT_LABELS: Record<LinkContextSignalId, string> = {
  'urgency-language': 'The surrounding message uses urgency or time pressure',
  'account-threat-language': 'The surrounding message threatens an account restriction',
  'credential-request-language': 'The surrounding message asks for credentials or verification',
  'financial-pressure-language': 'The surrounding message applies financial pressure',
  'authority-language': 'The surrounding message claims official authority',
  'reward-language': 'The surrounding message promises a prize, gift, or reward',
};

function exactActiveThreat(findings: ThreatIntelFinding[]): boolean {
  return findings.some((finding) => (
    finding.available &&
    finding.matched &&
    finding.matchType === 'exact-url' &&
    (finding.category === 'phishing' ||
      (finding.category === 'malware' && finding.status?.toLowerCase() === 'online'))
  ));
}

function hostnameThreat(findings: ThreatIntelFinding[]): boolean {
  return findings.some((finding) => (
    finding.available && finding.matched && finding.matchType === 'hostname'
  ));
}

/** Score a destination. Context can strengthen URL evidence, but never warns by itself. */
export function assessLink(
  candidate: LinkCandidate,
  threatIntel: ThreatIntelSummary,
): LinkAssessment {
  const urlIds = [...new Set(candidate.urlSignalIds)];
  const contextIds = [...new Set(candidate.contextSignalIds)];
  const reasons = urlIds.map((id) => SIGNAL_LABELS[id]);
  let score = urlIds.reduce((total, id) => total + (SIGNAL_WEIGHTS[id] ?? 0), 0);

  // Treat persuasion language only as supporting context for an independently
  // suspicious destination, and cap its contribution to avoid noisy warnings.
  if (urlIds.length > 0 && contextIds.length > 0) {
    score += Math.min(12, contextIds.reduce(
      (total, id) => total + (SIGNAL_WEIGHTS[id] ?? 0),
      0,
    ));
    reasons.push(...contextIds.map((id) => CONTEXT_LABELS[id]));
  }

  if (urlIds.includes('brand-in-hostname') && contextIds.length > 0) score += 10;

  const exactThreat = exactActiveThreat(threatIntel.findings);
  const relatedHostThreat = hostnameThreat(threatIntel.findings);
  if (exactThreat) {
    score = Math.max(score, 80);
    reasons.unshift('This exact destination appears in a known phishing or malware feed');
  } else if (relatedHostThreat) {
    score = Math.max(score, 12);
    reasons.push('Other malicious URLs have been reported on this hostname');
  }

  score = Math.min(100, score);
  const risk = exactThreat || score >= 30
    ? 'high'
    : score >= 6 || relatedHostThreat
      ? 'suspicious'
      : 'safe';

  return {
    key: candidate.key,
    risk,
    score,
    reasons: [...new Set(reasons)].slice(0, 6),
    threatIntelStatus: threatIntel.status,
  };
}

export const LINK_URL_SIGNAL_IDS = new Set<LinkUrlSignalId>([
  'ip-address-host', 'punycode-host', 'excessive-subdomains', 'long-url',
  'suspicious-url-keyword', 'excessive-hyphens', 'brand-in-hostname',
  'insecure-scheme', 'url-shortener', 'suspicious-port', 'userinfo-in-url',
]);

export const LINK_CONTEXT_SIGNAL_IDS = new Set<LinkContextSignalId>([
  'urgency-language', 'account-threat-language', 'credential-request-language',
  'financial-pressure-language', 'authority-language', 'reward-language',
]);
