const EXPORT_BASE = 'https://urlhaus-api.abuse.ch/v2/files/exports';
const DOWNLOAD_TIMEOUT_MS = 30_000;
const MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024;

function urlhausRecentCsvUrl(authKey) {
  if (typeof authKey !== 'string' || !authKey.trim()) {
    throw new Error('URLHAUS_AUTH_KEY is not configured');
  }
  return `${EXPORT_BASE}/${encodeURIComponent(authKey.trim())}/recent.csv`;
}

/** Download CSV without ever logging or returning the credential-bearing URL. */
export async function fetchUrlhausRecentCsv(authKey, fetchImpl = fetch) {
  let response;
  try {
    response = await fetchImpl(urlhausRecentCsvUrl(authKey), {
      headers: { 'User-Agent': 'PhishLens/0.1 threat-intelligence updater' },
      signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS),
    });
  } catch {
    throw new Error('URLhaus download failed');
  }
  if (!response.ok) throw new Error(`URLhaus download returned HTTP ${response.status}`);
  const declaredSize = Number(response.headers.get('content-length'));
  if (Number.isFinite(declaredSize) && declaredSize > MAX_DOWNLOAD_BYTES) {
    throw new Error('URLhaus download exceeds the 50 MB safety limit');
  }

  const body = Buffer.from(await response.arrayBuffer());
  if (body.byteLength > MAX_DOWNLOAD_BYTES) {
    throw new Error('URLhaus download exceeds the 50 MB safety limit');
  }
  return body.toString('utf8');
}
