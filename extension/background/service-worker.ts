import { LIMITS } from '../shared/constants';
import { getRegistrableDomain } from '../shared/domain';
import { loadSettings } from '../shared/settings';
import { sanitizeLinkUrl } from '../shared/sanitize-link-url';
import type {
  AnalysisResult,
  ExtensionMessage,
  HistoryEntry,
  LinkCandidate,
  RiskClass,
  ThreatIntelFinding,
  ThreatIntelSummary,
} from '../shared/types';
import {
  applyThreatIntel,
  isSameAnalysis,
  unavailableThreatIntel,
} from './enrichment';
import {
  assessLink,
  LINK_CONTEXT_SIGNAL_IDS,
  LINK_URL_SIGNAL_IDS,
} from './link-analysis';
import { runAnalysis } from './pipeline';

const THREAT_INTEL_URL = 'http://127.0.0.1:8787/threat-intel';
const THREAT_INTEL_TIMEOUT_MS = 3_000;
const MAX_LINKS_PER_BATCH = 100;
const LINK_INTEL_CACHE_MS = 15 * 60 * 1_000;

const linkIntelCache = new Map<string, { expiresAt: number; summary: ThreatIntelSummary }>();

const BADGE_COLORS: Record<RiskClass, string> = {
  Low: '#1f883d',
  Caution: '#b58a00',
  High: '#d1610d',
  Critical: '#cf222e',
};

function resultKey(tabId: number): string {
  return `result:${tabId}`;
}

async function updateBadge(tabId: number, result: AnalysisResult): Promise<void> {
  try {
    await Promise.all([
      chrome.action.setBadgeText({ tabId, text: String(result.score) }),
      chrome.action.setBadgeBackgroundColor({
        tabId,
        color: BADGE_COLORS[result.classification],
      }),
    ]);
  } catch {
    // The tab may close between analysis and the badge update.
  }
}

async function appendHistory(result: AnalysisResult): Promise<void> {
  const { history = [] } = await chrome.storage.local.get('history');
  const entry: HistoryEntry = {
    url: result.url,
    domain: result.domain,
    score: result.score,
    classification: result.classification,
    analyzedAt: result.analyzedAt,
  };
  const next = [entry, ...history].slice(0, LIMITS.historyEntries);
  await chrome.storage.local.set({ history: next });
}

function cleanNullableString(value: unknown): string | null {
  if (value == null) return null;
  if (typeof value !== 'string') throw new Error('invalid threat-intel string');
  const cleaned = value
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 500);
  return cleaned || null;
}

function cleanStringArray(value: unknown): string[] {
  if (value == null) return [];
  if (!Array.isArray(value) || value.length > 20) throw new Error('invalid threat-intel tags');
  return value.map((item) => {
    const cleaned = cleanNullableString(item);
    if (!cleaned) throw new Error('invalid threat-intel tag');
    return cleaned;
  });
}

function parseFinding(value: unknown): ThreatIntelFinding {
  if (typeof value !== 'object' || value === null) throw new Error('invalid finding');
  const finding = value as Record<string, unknown>;
  if (
    finding.provider !== 'phishtank' &&
    finding.provider !== 'urlhaus' &&
    finding.provider !== 'openphish'
  ) {
    throw new Error('invalid provider');
  }
  if (typeof finding.available !== 'boolean' || typeof finding.matched !== 'boolean') {
    throw new Error('invalid finding flags');
  }
  if (
    finding.category !== null &&
    finding.category !== 'phishing' &&
    finding.category !== 'malware'
  ) {
    throw new Error('invalid threat category');
  }
  if (
    finding.matchType !== null &&
    finding.matchType !== 'exact-url' &&
    finding.matchType !== 'hostname' &&
    finding.matchType !== 'registrable-domain'
  ) {
    throw new Error('invalid match type');
  }
  if (
    finding.confidence !== null &&
    finding.confidence !== 'high' &&
    finding.confidence !== 'medium' &&
    finding.confidence !== 'low'
  ) {
    throw new Error('invalid confidence');
  }

  return {
    provider: finding.provider,
    available: finding.available,
    matched: finding.matched,
    category: finding.category,
    matchType: finding.matchType,
    confidence: finding.confidence,
    targetBrand: cleanNullableString(finding.targetBrand),
    referenceUrl: cleanNullableString(finding.referenceUrl),
    verificationTime: cleanNullableString(finding.verificationTime),
    submissionTime: cleanNullableString(finding.submissionTime),
    status: cleanNullableString(finding.status),
    threat: cleanNullableString(finding.threat),
    tags: cleanStringArray(finding.tags),
  };
}

function parseThreatIntelSummary(value: unknown): ThreatIntelSummary {
  if (typeof value !== 'object' || value === null) throw new Error('invalid response');
  const summary = value as Record<string, unknown>;
  if (summary.status !== 'complete' && summary.status !== 'unavailable') {
    throw new Error('invalid lookup status');
  }
  if (!Number.isFinite(summary.checkedAt) || !Array.isArray(summary.findings)) {
    throw new Error('invalid lookup response');
  }
  return {
    status: summary.status,
    checkedAt: Number(summary.checkedAt),
    findings: summary.findings.map(parseFinding),
  };
}

async function fetchThreatIntel(url: string): Promise<ThreatIntelSummary> {
  const lookupUrl = sanitizeLinkUrl(url);
  if (!lookupUrl) throw new Error('unsupported threat-intel URL');
  const response = await fetch(THREAT_INTEL_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: lookupUrl }),
    signal: AbortSignal.timeout(THREAT_INTEL_TIMEOUT_MS),
  });
  if (!response.ok) throw new Error(`threat-intel backend returned ${response.status}`);
  return parseThreatIntelSummary(await response.json());
}

async function fetchThreatIntelBatch(urls: string[]): Promise<ThreatIntelSummary[]> {
  const response = await fetch(`${THREAT_INTEL_URL}/batch`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ urls }),
    signal: AbortSignal.timeout(THREAT_INTEL_TIMEOUT_MS),
  });
  if (!response.ok) throw new Error(`threat-intel backend returned ${response.status}`);
  const body = await response.json() as { results?: unknown[] };
  if (!Array.isArray(body.results) || body.results.length !== urls.length) {
    throw new Error('invalid batch lookup response');
  }
  return body.results.map(parseThreatIntelSummary);
}

function disabledThreatIntel(): ThreatIntelSummary {
  return { status: 'disabled', checkedAt: null, findings: [] };
}

async function lookupLinks(
  urls: string[],
  enabled: boolean,
): Promise<Map<string, ThreatIntelSummary>> {
  if (!enabled) return new Map(urls.map((url) => [url, disabledThreatIntel()]));

  const now = Date.now();
  const results = new Map<string, ThreatIntelSummary>();
  const missing: string[] = [];
  for (const url of [...new Set(urls)]) {
    const cached = linkIntelCache.get(url);
    if (cached && cached.expiresAt > now) results.set(url, cached.summary);
    else missing.push(url);
  }

  if (missing.length > 0) {
    let summaries: ThreatIntelSummary[];
    try {
      summaries = await fetchThreatIntelBatch(missing);
    } catch {
      summaries = missing.map(() => unavailableThreatIntel());
    }
    summaries.forEach((summary, index) => {
      const url = missing[index];
      results.set(url, summary);
      linkIntelCache.set(url, { expiresAt: now + LINK_INTEL_CACHE_MS, summary });
    });
  }

  while (linkIntelCache.size > 500) {
    const oldest = linkIntelCache.keys().next().value as string | undefined;
    if (!oldest) break;
    linkIntelCache.delete(oldest);
  }
  return results;
}

function validateLinkCandidate(value: LinkCandidate): LinkCandidate | null {
  if (!value || typeof value !== 'object') return null;
  if (typeof value.key !== 'string' || typeof value.lookupUrl !== 'string') return null;
  const sanitized = sanitizeLinkUrl(value.lookupUrl);
  if (!sanitized || sanitized !== value.lookupUrl || value.key !== sanitized) return null;
  if (!Array.isArray(value.urlSignalIds) || !Array.isArray(value.contextSignalIds)) return null;

  const urlSignalIds = [...new Set(value.urlSignalIds)]
    .filter((id) => LINK_URL_SIGNAL_IDS.has(id))
    .slice(0, LINK_URL_SIGNAL_IDS.size);
  const contextSignalIds = [...new Set(value.contextSignalIds)]
    .filter((id) => LINK_CONTEXT_SIGNAL_IDS.has(id))
    .slice(0, LINK_CONTEXT_SIGNAL_IDS.size);
  return { key: sanitized, lookupUrl: sanitized, urlSignalIds, contextSignalIds };
}

async function notifyResultUpdated(tabId: number, result: AnalysisResult): Promise<void> {
  const message = { type: 'RESULT_UPDATED' as const, tabId, result };
  await chrome.tabs.sendMessage(tabId, message).catch(() => undefined);
  await chrome.runtime.sendMessage(message).catch(() => undefined);
}

async function enrichWithThreatIntel(
  initialResult: AnalysisResult,
  tabId: number,
): Promise<void> {
  let summary: ThreatIntelSummary;
  try {
    summary = await fetchThreatIntel(initialResult.url);
  } catch {
    summary = unavailableThreatIntel();
  }

  const key = resultKey(tabId);
  const stored = await chrome.storage.session.get(key);
  if (!isSameAnalysis(stored[key] as AnalysisResult | undefined, initialResult)) return;

  try {
    const tab = await chrome.tabs.get(tabId);
    if (tab.url && tab.url !== initialResult.url) return;
  } catch {
    return; // The tab was closed before enrichment completed.
  }

  const updated = applyThreatIntel(initialResult, summary);
  await chrome.storage.session.set({ [key]: updated });
  await updateBadge(tabId, updated);
  await notifyResultUpdated(tabId, updated);
}

async function handleMessage(
  message: ExtensionMessage,
  sender: chrome.runtime.MessageSender,
): Promise<unknown> {
  switch (message?.type) {
    case 'ANALYZE': {
      const settings = await loadSettings();
      const result = runAnalysis(message.evidence, {
        threatIntelEnabled: settings.threatIntel,
        approvedDomains: settings.approvedDomains,
      });
      const tabId = sender.tab?.id;
      if (tabId != null) {
        await chrome.storage.session.set({ [resultKey(tabId)]: result });
        await updateBadge(tabId, result);
        if (settings.threatIntel && !result.overridden) {
          void enrichWithThreatIntel(result, tabId);
        }
      }
      if (settings.saveHistory && !result.overridden) await appendHistory(result);
      return {
        result,
        config: {
          bannerThreshold: settings.bannerThreshold,
          guardThreshold: settings.guardThreshold,
          submissionWarnings: settings.submissionWarnings,
          linkProtection: settings.linkProtection,
        },
      };
    }
    case 'GET_RESULT': {
      const key = resultKey(message.tabId);
      const stored = await chrome.storage.session.get(key);
      return { result: stored[key] ?? null };
    }
    case 'GET_HISTORY': {
      const { history = [] } = await chrome.storage.local.get('history');
      return { history };
    }
    case 'ANALYZE_LINKS': {
      const settings = await loadSettings();
      if (!settings.linkProtection || !Array.isArray(message.links)) return { assessments: [] };
      const candidates = message.links
        .slice(0, MAX_LINKS_PER_BATCH)
        .map(validateLinkCandidate)
        .filter((candidate): candidate is LinkCandidate => Boolean(candidate));
      const unique = [...new Map(candidates.map((candidate) => [candidate.key, candidate])).values()]
        .filter((candidate) => {
          const domain = getRegistrableDomain(new URL(candidate.lookupUrl).hostname);
          return !settings.approvedDomains.includes(domain);
        });
      const intel = await lookupLinks(
        unique.map((candidate) => candidate.lookupUrl),
        settings.threatIntel,
      );
      return {
        assessments: unique.map((candidate) => assessLink(
          candidate,
          intel.get(candidate.lookupUrl) ?? unavailableThreatIntel(),
        )),
      };
    }
    case 'CLEAR_DATA': {
      await chrome.storage.local.remove('history');
      const all = await chrome.storage.session.get(null);
      const resultKeys = Object.keys(all).filter((k) => k.startsWith('result:'));
      if (resultKeys.length) await chrome.storage.session.remove(resultKeys);
      linkIntelCache.clear();
      return { ok: true };
    }
    case 'RESULT_UPDATED':
      return { ok: true };
    default:
      return { error: 'unknown-message' };
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender).then(sendResponse, (err) => sendResponse({ error: String(err) }));
  return true; // keep the channel open for the async response
});

chrome.tabs.onRemoved.addListener((tabId) => {
  void chrome.storage.session.remove(resultKey(tabId)).catch(() => undefined);
});