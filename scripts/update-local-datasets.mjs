import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const SOURCE_URL = 'https://raw.githubusercontent.com/blocklistproject/Lists/main/alt-version/phishing-nl.txt';
const MAX_DOWNLOAD_BYTES = 10 * 1024 * 1024;
const MIN_EXPECTED_DOMAINS = 1_000;
const DOMAIN_PATTERN = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const outputPath = join(projectRoot, 'extension', 'data', 'blocklist-project-phishing.txt');

const response = await fetch(SOURCE_URL, {
  headers: { 'User-Agent': 'PhishLens/0.1 local-dataset-builder' },
  signal: AbortSignal.timeout(30_000),
});
if (!response.ok) throw new Error(`Block List Project download returned HTTP ${response.status}`);
const declaredSize = Number(response.headers.get('content-length'));
if (Number.isFinite(declaredSize) && declaredSize > MAX_DOWNLOAD_BYTES) {
  throw new Error('Block List Project download exceeds the 10 MB safety limit');
}
const bytes = Buffer.from(await response.arrayBuffer());
if (bytes.byteLength > MAX_DOWNLOAD_BYTES) {
  throw new Error('Block List Project download exceeds the 10 MB safety limit');
}

const domains = new Set();
for (const line of bytes.toString('utf8').split(/\r?\n/)) {
  const value = line.trim().toLowerCase().replace(/\.$/, '');
  if (!value || value.startsWith('#') || value.length > 253) continue;
  if (DOMAIN_PATTERN.test(value)) domains.add(value);
}
if (domains.size < MIN_EXPECTED_DOMAINS) {
  throw new Error(`Block List Project download contained only ${domains.size} valid domains`);
}

const retrievedAt = new Date().toISOString();
const upstreamSha256 = createHash('sha256').update(bytes).digest('hex');
const output = [
  '# Block List Project phishing-domain snapshot for PhishLens',
  `# Source: ${SOURCE_URL}`,
  '# License: Unlicense (see https://github.com/blocklistproject/Lists/blob/main/LICENSE)',
  `# Retrieved: ${retrievedAt}`,
  `# Upstream-SHA256: ${upstreamSha256}`,
  `# Entries: ${domains.size}`,
  ...[...domains].sort(),
  '',
].join('\n');

await mkdir(dirname(outputPath), { recursive: true });
await writeFile(outputPath, output, 'utf8');
console.log(`Wrote ${domains.size} phishing domains to ${outputPath}`);
