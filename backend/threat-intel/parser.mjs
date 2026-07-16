import { readFile } from 'node:fs/promises';
import { promisify } from 'node:util';
import { gunzip } from 'node:zlib';
import { normalizeUrl } from './normalize-url.mjs';

const gunzipAsync = promisify(gunzip);
const MAX_METADATA_LENGTH = 500;

function cleanMetadata(value) {
  if (value == null) return null;
  const cleaned = String(value)
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, MAX_METADATA_LENGTH);
  return cleaned || null;
}

function metadataFor(record) {
  return {
    phishId: cleanMetadata(record.phish_id),
    targetBrand: cleanMetadata(record.target),
    verificationTime: cleanMetadata(record.verification_time),
    submissionTime: cleanMetadata(record.submission_time),
    referenceUrl: cleanMetadata(record.phish_detail_url),
  };
}

/**
 * Build constant-time exact URL and hostname indexes from untrusted feed data.
 */
export function buildPhishTankIndex(records) {
  if (!Array.isArray(records)) {
    throw new Error('PhishTank feed must contain a JSON array');
  }

  const exactUrls = new Map();
  const hostnames = new Map();
  let acceptedRecords = 0;

  for (const record of records) {
    if (
      typeof record !== 'object' ||
      record === null ||
      record.verified !== 'yes' ||
      record.online !== 'yes' ||
      typeof record.url !== 'string'
    ) {
      continue;
    }

    try {
      const normalizedUrl = normalizeUrl(record.url);
      const hostname = new URL(normalizedUrl).hostname;
      const metadata = metadataFor(record);

      exactUrls.set(normalizedUrl, metadata);
      if (!hostnames.has(hostname)) hostnames.set(hostname, metadata);
      acceptedRecords += 1;
    } catch {
      // One malformed feed entry must not prevent the remaining feed from loading.
    }
  }

  return {
    exactUrls,
    hostnames,
    rawRecordCount: records.length,
    acceptedRecordCount: acceptedRecords,
    exactUrlCount: exactUrls.size,
    hostnameCount: hostnames.size,
  };
}

/**
 * Read, decompress, parse, validate, and index a PhishTank JSON gzip feed once.
 */
export async function loadPhishTankFeed(filePath) {
  const compressed = await readFile(filePath);

  let decompressed;
  try {
    decompressed = await gunzipAsync(compressed);
  } catch {
    throw new Error('PhishTank feed is not a valid gzip file');
  }

  let records;
  try {
    records = JSON.parse(decompressed.toString('utf8'));
  } catch {
    throw new Error('PhishTank feed does not contain valid JSON');
  }

  return buildPhishTankIndex(records);
}
