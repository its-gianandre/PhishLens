import { normalizeUrl } from '../normalize-url.mjs';

const FEED_URL = 'https://www.openphish.com/feed.txt';
const DOWNLOAD_TIMEOUT_MS = 15_000;
const MAX_DOWNLOAD_BYTES = 10 * 1024 * 1024;

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

function matchedFinding(matchType) {
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
    submissionTime: null,
    status: null,
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
      exactUrls.set(normalizedUrl, true);
      if (!hostnames.has(hostname)) hostnames.set(hostname, true);
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
  let response;
  try {
    response = await fetchImpl(FEED_URL, {
      headers: { 'User-Agent': 'PhishLens/0.1 threat-intelligence updater' },
      signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS),
    });
  } catch {
    throw new Error('OpenPhish download failed');
  }
  if (!response.ok) throw new Error(`OpenPhish download returned HTTP ${response.status}`);
  const declaredSize = Number(response.headers.get('content-length'));
  if (Number.isFinite(declaredSize) && declaredSize > MAX_DOWNLOAD_BYTES) {
    throw new Error('OpenPhish download exceeds the 10 MB safety limit');
  }

  const body = Buffer.from(await response.arrayBuffer());
  if (body.byteLength > MAX_DOWNLOAD_BYTES) {
    throw new Error('OpenPhish download exceeds the 10 MB safety limit');
  }
  return body.toString('utf8');
}

export function createOpenPhishProvider(index) {
  return {
    lookup(rawUrl) {
      if (!index) return emptyFinding(false);
      try {
        const normalizedUrl = normalizeUrl(rawUrl);
        const exact = index.exactUrls.has(normalizedUrl);
        if (exact) return matchedFinding('exact-url');

        const hostnameMatch = index.hostnames.has(new URL(normalizedUrl).hostname);
        if (hostnameMatch) return matchedFinding('hostname');
      } catch {}
      return emptyFinding(true);
    },
  };
}

export function unavailableOpenPhishFinding() {
  return emptyFinding(false);
}
