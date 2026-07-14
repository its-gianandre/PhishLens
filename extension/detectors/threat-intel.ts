import { KNOWN_MALICIOUS_URLS } from '../shared/constants';
import { getRegistrableDomain } from '../shared/domain';
import { makeSignal } from '../shared/signals';
import type { Signal } from '../shared/types';

/**
 * Known-threat lookup, returned as one more structured signal.
 * Currently a local stub list; a real feed (e.g. Google Safe Browsing /
 * PhishTank) should be queried from the backend, never with an API key in
 * extension code.
 */
export function lookupKnownThreat(rawUrl: string): Signal | null {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return null;
  }
  const host = url.hostname.toLowerCase();
  const registrable = getRegistrableDomain(host);

  if (KNOWN_MALICIOUS_URLS.has(host) || KNOWN_MALICIOUS_URLS.has(registrable)) {
    return makeSignal('known-malicious-url', 'threat-intel',
      'This domain appears on a known-phishing blocklist', registrable);
  }
  return null;
}
