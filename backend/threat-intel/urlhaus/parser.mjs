import { readFile } from 'node:fs/promises';
import { normalizeUrl } from '../normalize-url.mjs';

const MAX_METADATA_LENGTH = 500;
const MAX_TAGS = 20;

function cleanMetadata(value) {
  if (value == null) return null;
  const cleaned = String(value)
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, MAX_METADATA_LENGTH);
  return cleaned || null;
}

function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quoted) {
      if (char === '"' && text[index + 1] === '"') {
        field += '"';
        index += 1;
      } else if (char === '"') {
        quoted = false;
      } else {
        field += char;
      }
      continue;
    }

    if (char === '"') {
      quoted = true;
    } else if (char === ',') {
      row.push(field);
      field = '';
    } else if (char === '\n') {
      row.push(field.replace(/\r$/, ''));
      rows.push(row);
      row = [];
      field = '';
    } else {
      field += char;
    }
  }

  if (quoted) throw new Error('URLhaus feed contains an unterminated CSV field');
  if (field || row.length) {
    row.push(field.replace(/\r$/, ''));
    rows.push(row);
  }
  return rows;
}

function normalizedHeader(value) {
  return value.trim().replace(/^#\s*/, '').toLowerCase();
}

function splitTags(value) {
  if (!value) return [];
  return value
    .split(/[|,]/)
    .map(cleanMetadata)
    .filter(Boolean)
    .slice(0, MAX_TAGS);
}

function metadataFor(record) {
  return {
    urlhausId: cleanMetadata(record.id),
    dateAdded: cleanMetadata(record.dateadded ?? record.date_added),
    lastOnline: cleanMetadata(record.last_online),
    status: cleanMetadata(record.url_status ?? record.status),
    threat: cleanMetadata(record.threat),
    tags: splitTags(record.tags),
    referenceUrl: cleanMetadata(record.urlhaus_link ?? record.reference),
  };
}

/** Build exact-URL and hostname indexes from an untrusted URLhaus CSV export. */
export function buildUrlhausIndex(csvText) {
  if (typeof csvText !== 'string') throw new Error('URLhaus feed must be CSV text');
  const rows = parseCsv(csvText).filter((row) => row.some((field) => field.trim()));
  const headerIndex = rows.findIndex((row) => {
    const headers = row.map(normalizedHeader);
    return headers.includes('url') && (headers.includes('id') || headers.includes('urlhaus_id'));
  });
  if (headerIndex < 0) throw new Error('URLhaus feed is missing a supported CSV header');

  const headers = rows[headerIndex].map(normalizedHeader);
  const exactUrls = new Map();
  const hostnames = new Map();
  let acceptedRecords = 0;

  for (const row of rows.slice(headerIndex + 1)) {
    if (row[0]?.trim().startsWith('#')) continue;
    const record = Object.fromEntries(headers.map((header, index) => [header, row[index] ?? '']));
    if (typeof record.url !== 'string' || !record.url.trim()) continue;

    try {
      const normalizedUrl = normalizeUrl(record.url);
      const hostname = new URL(normalizedUrl).hostname;
      const metadata = metadataFor(record);
      exactUrls.set(normalizedUrl, metadata);
      if (!hostnames.has(hostname)) hostnames.set(hostname, metadata);
      acceptedRecords += 1;
    } catch {
      // One malformed entry must not prevent the rest of the feed from loading.
    }
  }

  return {
    exactUrls,
    hostnames,
    rawRecordCount: Math.max(0, rows.length - headerIndex - 1),
    acceptedRecordCount: acceptedRecords,
    exactUrlCount: exactUrls.size,
    hostnameCount: hostnames.size,
  };
}

export async function loadUrlhausFeed(filePath) {
  return buildUrlhausIndex(await readFile(filePath, 'utf8'));
}
