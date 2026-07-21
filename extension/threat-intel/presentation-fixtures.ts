import type { ThreatIntelFinding } from '../shared/types';

const SHOWCASE_HOST = 'intel-showcase.localhost';
const SHOWCASE_PATH = '/threat-intel-showcase.html';
const OPENPHISH_DEMO_HOSTS = new Set(['localhost', '127.0.0.1']);
const OPENPHISH_DEMO_PATH = '/openphish-demo.html';

function openPhishFinding(): ThreatIntelFinding {
  return {
    provider: 'openphish',
    available: true,
    matched: true,
    category: 'phishing',
    matchType: 'exact-url',
    confidence: 'high',
    targetBrand: null,
    referenceUrl: null,
    verificationTime: null,
    submissionTime: null,
    status: null,
    threat: 'phishing',
    tags: ['phishing', 'presentation-fixture'],
  };
}

/**
 * Safe localhost-only findings used by the presentation gallery. They keep the
 * video demo deterministic without changing or impersonating any live feed.
 */
export function getPresentationThreatIntelFindings(
  rawUrl: string,
): ThreatIntelFinding[] {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return [];
  }
  if (
    url.protocol === 'http:' &&
    url.port === '8000' &&
    OPENPHISH_DEMO_HOSTS.has(url.hostname) &&
    url.pathname === OPENPHISH_DEMO_PATH
  ) return [openPhishFinding()];

  if (
    url.protocol !== 'http:' ||
    url.port !== '8000' ||
    url.hostname !== SHOWCASE_HOST ||
    url.pathname !== SHOWCASE_PATH
  ) return [];

  return [
    {
      provider: 'phishtank',
      available: true,
      matched: true,
      category: 'phishing',
      matchType: 'exact-url',
      confidence: 'high',
      targetBrand: null,
      referenceUrl: 'https://phishtank.org/',
      verificationTime: '2026-07-21T18:05:00Z',
      submissionTime: '2026-07-21T18:00:00Z',
      status: 'online',
      threat: 'phishing',
      tags: ['presentation-fixture'],
    },
    {
      provider: 'urlhaus',
      available: true,
      matched: true,
      category: 'malware',
      matchType: 'exact-url',
      confidence: 'high',
      targetBrand: null,
      referenceUrl: 'https://urlhaus.abuse.ch/',
      verificationTime: '2026-07-21T18:15:00Z',
      submissionTime: '2026-07-21T18:10:00Z',
      status: 'online',
      threat: 'malware_download',
      tags: ['demo', 'presentation'],
    },
    openPhishFinding(),
  ];
}
