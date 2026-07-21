import { normalizeUrl } from '../normalize-url.mjs';
function emptyFinding(available) {
  return {
    provider: 'openphish',
    available,
    matched: false,
    category: null,
    matchType: null,
    confidence: null,
    targetBrand: null,
    referenceUrl: null,
    verificationTime: null,
    submissionTime: null,
    status: null,
    threat: null,
    tags: [],
  };
}

function matchedFinding(metadata, matchType) {
  return {
    provider: 'openphish',
    available: true,
    matched: true,
    category: 'phishing',
    matchType,
    confidence: matchType === 'exact-url' ? 'high' : 'medium',
    targetBrand: null,
    referenceUrl: null,
    verificationTime: null,
    submissionTime: metadata.submissionTime,
    status: 'online',
    threat: 'phishing',
    tags: ['phishing'],
  };
}

export function buildOpenPhishIndex(textData) {
  if (typeof textData !== 'string') {
    throw new Error('OpenPhish feed must be a string');
  }

  const exactUrls = new Map();
  const hostnames = new Map();
  let acceptedRecords = 0;

  const lines = textData.split('\n');
  for (const line of lines) {
    const rawUrl = line.trim();
    if (!rawUrl || rawUrl.startsWith('#')) continue;

    try {
      const normalizedUrl = normalizeUrl(rawUrl);
      const hostname = new URL(normalizedUrl).hostname;
      const metadata = { submissionTime: new Date().toISOString() };

      exactUrls.set(normalizedUrl, metadata);
      if (!hostnames.has(hostname)) hostnames.set(hostname, metadata);
      acceptedRecords += 1;
    } catch {
      // Skip malformed records safely
    }
  }

  return {
    exactUrls,
    hostnames,
    rawRecordCount: lines.length,
    acceptedRecordCount: acceptedRecords,
    exactUrlCount: exactUrls.size,
    hostnameCount: hostnames.size,
  };
}

export async function fetchOpenPhishFeed(fetchImpl = fetch) {
  const response = await fetchImpl('https://www.openphish.com/feed.txt', {
    headers: { 'User-Agent': 'PhishLens/0.1 threat-intelligence updater' },
    signal: AbortSignal.timeout(15000),
  });
  if (!response.ok) throw new Error(`OpenPhish download returned HTTP ${response.status}`);
  return await response.text();
}

export function createOpenPhishProvider(index) {
  return {
    lookup(rawUrl) {
      if (!index) return emptyFinding(false);
      try {
        const normalizedUrl = normalizeUrl(rawUrl);
        const exact = index.exactUrls.get(normalizedUrl);
        if (exact) return matchedFinding(exact, 'exact-url');

        const hostnameMatch = index.hostnames.get(new URL(normalizedUrl).hostname);
        if (hostnameMatch) return matchedFinding(hostnameMatch, 'hostname');
      } catch {}
      return emptyFinding(true);
    },
  };
}

export function unavailableOpenPhishFinding() {
  return emptyFinding(false);
}