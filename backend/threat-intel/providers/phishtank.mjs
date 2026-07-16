import { normalizeUrl } from '../normalize-url.mjs';

function emptyFinding(available) {
  return {
    provider: 'phishtank',
    available,
    matched: false,
    category: null,
    matchType: null,
    confidence: null,
    targetBrand: null,
    referenceUrl: null,
    verificationTime: null,
    submissionTime: null,
  };
}

function matchedFinding(metadata, matchType) {
  return {
    provider: 'phishtank',
    available: true,
    matched: true,
    category: 'phishing',
    matchType,
    confidence: matchType === 'exact-url' ? 'high' : 'medium',
    targetBrand: metadata.targetBrand,
    referenceUrl: metadata.referenceUrl,
    verificationTime: metadata.verificationTime,
    submissionTime: metadata.submissionTime,
  };
}

export function createPhishTankProvider(index) {
  return {
    lookup(rawUrl) {
      if (!index) return emptyFinding(false);

      const normalizedUrl = normalizeUrl(rawUrl);
      const exact = index.exactUrls.get(normalizedUrl);
      if (exact) return matchedFinding(exact, 'exact-url');

      const hostname = new URL(normalizedUrl).hostname;
      const hostnameMatch = index.hostnames.get(hostname);
      if (hostnameMatch) return matchedFinding(hostnameMatch, 'hostname');

      return emptyFinding(true);
    },
  };
}

export function unavailablePhishTankFinding() {
  return emptyFinding(false);
}
