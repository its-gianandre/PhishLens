import { LIMITS } from '../shared/constants';
import { loadSettings } from '../shared/settings';
import type {
  AnalysisResult,
  ExtensionMessage,
  HistoryEntry,
  RiskClass,
  ThreatIntelFinding,
  ThreatIntelSummary,
} from '../shared/types';
import {
  applyThreatIntel,
  isSameAnalysis,
  unavailableThreatIntel,
} from './enrichment';
import { runAnalysis } from './pipeline';

const THREAT_INTEL_URL = 'http://127.0.0.1:8787/threat-intel';
const THREAT_INTEL_TIMEOUT_MS = 3_000;

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

function parseFinding(value: unknown): ThreatIntelFinding {
  if (typeof value !== 'object' || value === null) throw new Error('invalid finding');
  const finding = value as Record<string, unknown>;
  if (finding.provider !== 'phishtank') throw new Error('invalid provider');
  if (typeof finding.available !== 'boolean' || typeof finding.matched !== 'boolean') {
    throw new Error('invalid finding flags');
  }
  if (finding.category !== null && finding.category !== 'phishing') {
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
    provider: 'phishtank',
    available: finding.available,
    matched: finding.matched,
    category: finding.category,
    matchType: finding.matchType,
    confidence: finding.confidence,
    targetBrand: cleanNullableString(finding.targetBrand),
    referenceUrl: cleanNullableString(finding.referenceUrl),
    verificationTime: cleanNullableString(finding.verificationTime),
    submissionTime: cleanNullableString(finding.submissionTime),
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
  const response = await fetch(THREAT_INTEL_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
    signal: AbortSignal.timeout(THREAT_INTEL_TIMEOUT_MS),
  });
  if (!response.ok) throw new Error(`threat-intel backend returned ${response.status}`);
  return parseThreatIntelSummary(await response.json());
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
    case 'CLEAR_DATA': {
      await chrome.storage.local.remove('history');
      const all = await chrome.storage.session.get(null);
      const resultKeys = Object.keys(all).filter((k) => k.startsWith('result:'));
      if (resultKeys.length) await chrome.storage.session.remove(resultKeys);
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
