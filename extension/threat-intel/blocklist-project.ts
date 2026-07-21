import { getRegistrableDomain, isIpAddress } from '../shared/domain';
import type { ThreatIntelFinding } from '../shared/types';

const SNAPSHOT_PATH = 'data/blocklist-project-phishing.txt';
const DEMO_SNAPSHOT_PATH = 'data/demo-blocklist-project.txt';
const MAX_SNAPSHOT_BYTES = 10 * 1024 * 1024;
const DOMAIN_PATTERN = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

let snapshotPromise: Promise<Set<string>> | null = null;

function emptyFinding(available: boolean): ThreatIntelFinding {
  return {
    provider: 'blocklist-project',
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

function normalizeDomain(value: string): string | null {
  const domain = value.trim().toLowerCase().replace(/\.$/, '');
  if (
    !domain ||
    domain.length > 253 ||
    isIpAddress(domain) ||
    !DOMAIN_PATTERN.test(domain)
  ) return null;
  return domain;
}

/** Parse the generated domain-only snapshot. Exported for deterministic tests. */
export function parseBlockListProjectSnapshot(text: string): Set<string> {
  if (typeof text !== 'string' || text.length > MAX_SNAPSHOT_BYTES) {
    throw new Error('Block List Project snapshot is invalid or too large');
  }
  const domains = new Set<string>();
  for (const line of text.split(/\r?\n/)) {
    if (!line || line.startsWith('#')) continue;
    const domain = normalizeDomain(line);
    if (domain) domains.add(domain);
  }
  if (domains.size < 1) throw new Error('Block List Project snapshot contains no domains');
  return domains;
}

async function fetchSnapshot(path: string): Promise<Set<string>> {
  const response = await fetch(chrome.runtime.getURL(path));
  if (!response.ok) throw new Error('Block List Project snapshot could not be loaded');
  const declaredSize = Number(response.headers.get('content-length'));
  if (Number.isFinite(declaredSize) && declaredSize > MAX_SNAPSHOT_BYTES) {
    throw new Error('Block List Project snapshot exceeds the safety limit');
  }
  return parseBlockListProjectSnapshot(await response.text());
}

async function loadSnapshot(): Promise<Set<string>> {
  const [upstream, demo] = await Promise.all([
    fetchSnapshot(SNAPSHOT_PATH),
    fetchSnapshot(DEMO_SNAPSHOT_PATH),
  ]);
  return new Set([...upstream, ...demo]);
}

function candidateDomains(hostname: string): string[] {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  const registrable = getRegistrableDomain(host);
  const candidates = [];
  let current = host;
  while (current.length >= registrable.length) {
    candidates.push(current);
    if (current === registrable) break;
    current = current.slice(current.indexOf('.') + 1);
  }
  return candidates;
}

export function lookupBlockListProject(
  rawUrl: string,
  domains: ReadonlySet<string>,
): ThreatIntelFinding {
  let hostname: string;
  try {
    const url = new URL(rawUrl);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return emptyFinding(true);
    hostname = url.hostname.toLowerCase().replace(/\.$/, '');
  } catch {
    return emptyFinding(true);
  }
  const match = candidateDomains(hostname).find((domain) => domains.has(domain));
  if (!match) return emptyFinding(true);
  return {
    ...emptyFinding(true),
    matched: true,
    category: 'phishing',
    matchType: match === hostname ? 'hostname' : 'registrable-domain',
    confidence: match === hostname ? 'high' : 'medium',
    status: 'listed',
    threat: 'phishing',
    tags: ['phishing', `listed-domain:${match}`],
  };
}

export async function lookupLocalBlockList(rawUrl: string): Promise<ThreatIntelFinding> {
  snapshotPromise ??= loadSnapshot();
  try {
    return lookupBlockListProject(rawUrl, await snapshotPromise);
  } catch {
    snapshotPromise = null;
    return emptyFinding(false);
  }
}

export async function lookupLocalBlockListBatch(
  rawUrls: string[],
): Promise<ThreatIntelFinding[]> {
  snapshotPromise ??= loadSnapshot();
  try {
    const domains = await snapshotPromise;
    return rawUrls.map((url) => lookupBlockListProject(url, domains));
  } catch {
    snapshotPromise = null;
    return rawUrls.map(() => emptyFinding(false));
  }
}

export function resetLocalBlockListForTests(): void {
  snapshotPromise = null;
}
