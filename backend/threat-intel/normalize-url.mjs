/**
 * Canonicalize an HTTP(S) URL for deterministic feed indexing and lookup.
 * This function only parses the supplied string; it never performs a request.
 */
export function normalizeUrl(rawUrl) {
  if (typeof rawUrl !== 'string' || rawUrl.trim() === '') {
    throw new Error('URL must be a non-empty string');
  }

  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error('URL is malformed');
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('URL must use HTTP or HTTPS');
  }

  url.hash = '';
  url.hostname = url.hostname.toLowerCase();

  if (
    (url.protocol === 'http:' && url.port === '80') ||
    (url.protocol === 'https:' && url.port === '443')
  ) {
    url.port = '';
  }

  if (!url.pathname) url.pathname = '/';
  return url.href;
}
