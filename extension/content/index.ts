import type { AnalyzeResponse } from '../shared/types';
import { extractPageEvidence } from './extract-page';
import { installSubmitGuard, showWarningBanner } from './warning-banner';

(async () => {
  try {
    const evidence = extractPageEvidence();
    const response: AnalyzeResponse | undefined = await chrome.runtime.sendMessage({
      type: 'ANALYZE',
      evidence,
    });
    if (!response?.result) return;

    const { result, config } = response;
    if (result.score >= config.bannerThreshold) {
      showWarningBanner(result);
    }
    if (config.submissionWarnings && result.score >= config.guardThreshold) {
      installSubmitGuard(result);
    }
  } catch {
    // Extension context invalidated (e.g. reload during analysis) — nothing to do.
  }
})();
