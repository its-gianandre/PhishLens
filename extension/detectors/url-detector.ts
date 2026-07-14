import { BRANDS, SUSPICIOUS_URL_KEYWORDS, URL_SHORTENERS } from '../shared/constants';
import { getRegistrableDomain, isIpAddress, isLoopback, subdomainDepth } from '../shared/domain';
import { makeSignal } from '../shared/signals';
import type { Signal } from '../shared/types';

/** Hostname tokens that indicate a brand. Short/generic names need explicit hostTokens. */
function brandHostTokens(): Array<{ brand: string; token: string; domains: string[] }> {
  const entries: Array<{ brand: string; token: string; domains: string[] }> = [];
  for (const brand of BRANDS) {
    const tokens = brand.hostTokens ?? [];
    const derived = brand.name.toLowerCase().replace(/\s+/g, '');
    if (derived.length >= 6 && !tokens.includes(derived)) tokens.push(derived);
    for (const token of tokens) entries.push({ brand: brand.name, token, domains: brand.domains });
  }
  return entries;
}

const HOST_TOKENS = brandHostTokens();

export function detectUrlSignals(rawUrl: string): Signal[] {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return [];
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return [];

  const signals: Signal[] = [];
  const host = url.hostname.toLowerCase();
  const loopback = isLoopback(host);
  const registrable = getRegistrableDomain(host);

  if (isIpAddress(host) && !loopback) {
    signals.push(makeSignal('ip-address-host', 'url',
      'The site is addressed by a raw IP address instead of a domain name', host));
  }
  if (host.split('.').some((label) => label.startsWith('xn--'))) {
    signals.push(makeSignal('punycode-host', 'url',
      'The domain uses punycode, often used for look-alike characters', host));
  }
  if (subdomainDepth(host) >= 3) {
    signals.push(makeSignal('excessive-subdomains', 'url',
      'The address has an unusual number of subdomains', host));
  }
  if (rawUrl.length > 100) {
    signals.push(makeSignal('long-url', 'url',
      `The URL is unusually long (${rawUrl.length} characters)`, rawUrl));
  }
  const hyphens = (host.match(/-/g) ?? []).length;
  if (hyphens >= 3) {
    signals.push(makeSignal('excessive-hyphens', 'url',
      'The domain contains an unusual number of hyphens', host));
  }
  if (!loopback && url.protocol === 'http:') {
    signals.push(makeSignal('insecure-scheme', 'url',
      'The page is served over unencrypted HTTP', url.protocol + '//' + host));
  }
  if (URL_SHORTENERS.has(registrable)) {
    signals.push(makeSignal('url-shortener', 'url',
      'The address is a URL-shortening service that hides the real destination', registrable));
  }
  if (!loopback && url.port !== '') {
    signals.push(makeSignal('suspicious-port', 'url',
      `The site uses a non-standard port (${url.port})`, host + ':' + url.port));
  }
  if (url.username) {
    signals.push(makeSignal('userinfo-in-url', 'url',
      'The URL embeds a username before "@", a trick to disguise the real domain', url.username + '@' + host));
  }

  const lowered = rawUrl.toLowerCase();
  const matchedKeywords = SUSPICIOUS_URL_KEYWORDS.filter((kw) => lowered.includes(kw));
  if (matchedKeywords.length > 0) {
    signals.push(makeSignal('suspicious-url-keyword', 'url',
      'The URL contains keywords commonly used on phishing pages', matchedKeywords.join(', ')));
  }

  if (!loopback) {
    const labels = host.split('.');
    for (const { brand, token, domains } of HOST_TOKENS) {
      if (domains.includes(registrable)) continue;
      const hit = labels.some((label) => label === token || (token.length >= 6 && label.includes(token)));
      if (hit) {
        signals.push(makeSignal('brand-in-hostname', 'url',
          `The hostname contains "${token}" (${brand}) but is not an official ${brand} domain`, host));
        break;
      }
    }
  }

  return signals;
}
