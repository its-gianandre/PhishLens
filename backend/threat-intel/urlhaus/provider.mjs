import { normalizeUrl } from '../normalize-url.mjs';

function emptyFinding(available) {
  return {
    provider: 'urlhaus',
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
    provider: 'urlhaus',
    available: true,
    matched: true,
    category: 'malware',
    matchType,
    confidence: matchType === 'exact-url' ? 'high' : 'medium',
    targetBrand: null,
    referenceUrl: metadata.referenceUrl,
    verificationTime: metadata.lastOnline,
    submissionTime: metadata.dateAdded,
    status: metadata.status,
    threat: metadata.threat,
    tags: metadata.tags,
  };
}

export function createUrlhausProvider(index) {
  return {
    lookup(rawUrl) {
      if (!index) return emptyFinding(false);
      const normalizedUrl = normalizeUrl(rawUrl);
      const exact = index.exactUrls.get(normalizedUrl);
      if (exact) return matchedFinding(exact, 'exact-url');

      const hostnameMatch = index.hostnames.get(new URL(normalizedUrl).hostname);
      if (hostnameMatch) return matchedFinding(hostnameMatch, 'hostname');
      return emptyFinding(true);
    },
  };
}

export function unavailableUrlhausFinding() {
  return emptyFinding(false);
}
