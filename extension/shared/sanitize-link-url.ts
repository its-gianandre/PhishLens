const TRACKING_PARAMETER_NAMES = new Set([
  'fbclid', 'gclid', 'dclid', 'msclkid', 'mc_cid', 'mc_eid', 'igshid',
  'vero_id', 'oly_anon_id', 'oly_enc_id', '_hsenc', '_hsmi', 'mkt_tok',
]);

const SENSITIVE_PARAMETER = /token|password|passwd|passcode|secret|session|jwt|apikey|email|phone|ssn|cardnumber|cvv|otp|authorizationcode|authcode/i;
const HIGH_ENTROPY_VALUE = /^[A-Za-z0-9_-]{48,}$/;

function isTrackingParameter(name: string): boolean {
  const lower = name.toLowerCase();
  return lower.startsWith('utm_') || TRACKING_PARAMETER_NAMES.has(lower);
}

function isSensitiveParameter(name: string): boolean {
  const compact = name.toLowerCase().replace(/[^a-z0-9]/g, '');
  return compact === 'code' || compact === 'sid' || SENSITIVE_PARAMETER.test(compact);
}

/**
 * Produce the only URL form that may leave the content script. It removes
 * fragments, userinfo and trackers, and redacts likely secrets in the query.
 */
export function sanitizeLinkUrl(rawUrl: string): string | null {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return null;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;

  url.hash = '';
  url.username = '';
  url.password = '';
  for (const name of [...url.searchParams.keys()]) {
    if (isTrackingParameter(name)) {
      url.searchParams.delete(name);
      continue;
    }
    const values = url.searchParams.getAll(name);
    if (isSensitiveParameter(name) || values.some((value) => HIGH_ENTROPY_VALUE.test(value))) {
      url.searchParams.set(name, 'REDACTED');
    }
  }
  return url.href.slice(0, 4096);
}
