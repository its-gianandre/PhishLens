import { LIMITS } from '../shared/constants';
import { loadSettings } from '../shared/settings';
import type {
  AnalysisResult,
  ExtensionMessage,
  HistoryEntry,
  RiskClass,
} from '../shared/types';
import { runAnalysis } from './pipeline';

const BADGE_COLORS: Record<RiskClass, string> = {
  Low: '#1f883d',
  Caution: '#b58a00',
  High: '#d1610d',
  Critical: '#cf222e',
};

function resultKey(tabId: number): string {
  return `result:${tabId}`;
}

function updateBadge(tabId: number, result: AnalysisResult): void {
  chrome.action.setBadgeText({ tabId, text: String(result.score) });
  chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLORS[result.classification] });
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
        updateBadge(tabId, result);
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
    default:
      return { error: 'unknown-message' };
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender).then(sendResponse, (err) => sendResponse({ error: String(err) }));
  return true; // keep the channel open for the async response
});

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove(resultKey(tabId));
});
