import type {
  AnalysisResult,
  AnalyzeResponse,
  ContentConfig,
  ResultUpdatedMessage,
} from '../shared/types';
import { extractPageEvidence } from './extract-page';
import { installSubmitGuard, showWarningBanner } from './warning-banner';

let contentConfig: ContentConfig | null = null;

function applyResult(result: AnalysisResult): void {
  if (result.url !== location.href || !contentConfig) return;
  if (result.score >= contentConfig.bannerThreshold) {
    showWarningBanner(result);
  }
  if (contentConfig.submissionWarnings && result.score >= contentConfig.guardThreshold) {
    installSubmitGuard(result);
  }
}

chrome.runtime.onMessage.addListener((message: ResultUpdatedMessage) => {
  if (message?.type === 'RESULT_UPDATED') applyResult(message.result);
});

(async () => {
  try {
    const evidence = extractPageEvidence();
    const response: AnalyzeResponse | undefined = await chrome.runtime.sendMessage({
      type: 'ANALYZE',
      evidence,
    });
    if (!response?.result) return;

    const { result, config } = response;
    contentConfig = config;
    applyResult(result);
  } catch {
    // Extension context invalidated (e.g. reload during analysis) — nothing to do.
  }
})();
