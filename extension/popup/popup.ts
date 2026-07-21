import { loadSettings, saveSettings } from '../shared/settings';
import type {
  AnalysisResult,
  ExplainRequest,
  ExplainResponse,
  ResultUpdatedMessage,
  Settings,
} from '../shared/types';

const BACKEND_URL = 'http://127.0.0.1:8787/explain';

const main = document.getElementById('main')!;
const settingsSection = document.getElementById('settings')!;

function el<T extends HTMLElement = HTMLElement>(id: string): T {
  return document.getElementById(id) as T;
}

function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, (ch) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]!
  ));
}

async function getActiveTabResult(): Promise<{ tabId: number | null; result: AnalysisResult | null }> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.id == null) return { tabId: null, result: null };
  const response = await chrome.runtime.sendMessage({ type: 'GET_RESULT', tabId: tab.id });
  return { tabId: tab.id, result: response?.result ?? null };
}

function renderNoResult(): void {
  main.innerHTML = `<p class="muted">No analysis for this page. PhishLens runs on regular
    http(s) pages once they finish loading.</p>`;
}

function formatTime(value: string | null): string | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function renderThreatIntel(result: AnalysisResult): string {
  const summary = result.threatIntel;
  if (!summary) {
    return `<h2>Threat intelligence</h2>
      <div class="threat-intel muted">Reload this page to start known-threat lookups.</div>`;
  }
  if (summary.status === 'disabled') {
    return `<h2>Threat intelligence</h2>
      <div class="threat-intel muted">Known-threat lookups are disabled.</div>`;
  }
  if (summary.status === 'pending') {
    return `<h2>Threat intelligence</h2>
      <div class="threat-intel"><strong>Checking PhishTank, URLhaus, and OpenPhish…</strong></div>`;
  }

  // --- PhishTank Card ---
  const phishtank = summary.findings.find((item) => item.provider === 'phishtank');
  let phishtankCard: string;
  if (!phishtank?.available) {
    phishtankCard = `<div class="threat-intel"><strong>PhishTank unavailable</strong></div>`;
  } else if (phishtank.matched && phishtank.matchType === 'exact-url') {
    const verified = formatTime(phishtank.verificationTime);
    phishtankCard = `<div class="threat-intel threat-match">
      <strong>PhishTank</strong>
      <div>Exact verified phishing URL match in the bundled snapshot</div>
      <div>Confidence: High</div>
      ${phishtank.targetBrand ? `<div>Target: ${escapeHtml(phishtank.targetBrand)}</div>` : ''}
      ${verified ? `<div>Verified: ${escapeHtml(verified)}</div>` : ''}
    </div>`;
  } else if (phishtank.matched && phishtank.matchType === 'hostname') {
    phishtankCard = `<div class="threat-intel">
      <strong>PhishTank</strong>
      <div>Other phishing URLs were reported on this hostname in the bundled snapshot.</div>
      <div class="muted">This hostname-only finding did not independently increase the score.</div>
    </div>`;
  } else {
    phishtankCard = `<div class="threat-intel">
      <strong>PhishTank</strong>
      <div>No match found in the bundled snapshot</div>
      <div class="muted">Snapshot date: July 16, 2026. This is not a safety guarantee.</div>
    </div>`;
  }

  // --- URLhaus Card ---
  const urlhaus = summary.findings.find((item) => item.provider === 'urlhaus');
  let urlhausCard: string;
  if (!urlhaus?.available) {
    urlhausCard = `<div class="threat-intel">
      <strong>URLhaus unavailable</strong>
      <div class="muted">Configure the local backend with a URLhaus auth key or cached feed.</div>
    </div>`;
  } else if (urlhaus.matched && urlhaus.matchType === 'exact-url') {
    const observed = formatTime(urlhaus.verificationTime);
    const active = urlhaus.status?.toLowerCase() === 'online';
    urlhausCard = `<div class="threat-intel ${active ? 'threat-match' : ''}">
      <strong>URLhaus</strong>
      <div>Exact malware-distribution URL match</div>
      ${urlhaus.status ? `<div>Status: ${escapeHtml(urlhaus.status)}</div>` : ''}
      ${urlhaus.threat ? `<div>Threat: ${escapeHtml(urlhaus.threat)}</div>` : ''}
      ${urlhaus.tags?.length ? `<div>Tags: ${escapeHtml(urlhaus.tags.join(', '))}</div>` : ''}
      ${observed ? `<div>Last observed: ${escapeHtml(observed)}</div>` : ''}
      ${active ? '' : '<div class="muted">Offline matches are displayed but do not increase the score.</div>'}
    </div>`;
  } else if (urlhaus.matched && urlhaus.matchType === 'hostname') {
    urlhausCard = `<div class="threat-intel">
      <strong>URLhaus</strong>
      <div>Other malware URLs were reported on this hostname.</div>
      <div class="muted">This hostname-only finding did not independently increase the score.</div>
    </div>`;
  } else {
    urlhausCard = `<div class="threat-intel">
      <strong>URLhaus</strong>
      <div>No malware URL match found in the local feed</div>
      <div class="muted">No match is not a safety guarantee.</div>
    </div>`;
  }

  // --- OpenPhish Card ---
  const openphish = summary.findings.find((item) => item.provider === 'openphish');
  let openphishCard = '';
  if (openphish?.available) {
    if (openphish.matched && openphish.matchType === 'exact-url') {
      openphishCard = `<div class="threat-intel threat-match">
        <strong>OpenPhish</strong>
        <div>Exact verified active phishing URL match</div>
        <div>Confidence: High</div>
        ${openphish.targetBrand ? `<div>Target: ${escapeHtml(openphish.targetBrand)}</div>` : ''}
      </div>`;
    } else if (openphish.matched && openphish.matchType === 'hostname') {
      openphishCard = `<div class="threat-intel">
        <strong>OpenPhish</strong>
        <div>Other active phishing URLs were reported on this hostname.</div>
        <div class="muted">This hostname-only finding did not independently increase the score.</div>
      </div>`;
    } else {
      openphishCard = `<div class="threat-intel">
        <strong>OpenPhish</strong>
        <div>No active phishing match found in feed</div>
      </div>`;
    }
  }

  return `<h2>Threat intelligence</h2>${phishtankCard}${urlhausCard}${openphishCard}`;
}

function renderResult(result: AnalysisResult, settings: Settings): void {
  const brandLine = result.suspectedBrand
    ? `<div class="meta">Presents itself as: <strong>${escapeHtml(result.suspectedBrand)}</strong>${
        settings.technicalMode && result.brandConfidence != null
          ? ` <span class="muted">(confidence ${result.brandConfidence})</span>` : ''
      }</div>`
    : '';

  const findings = result.signals.length
    ? `<h2>Findings (${result.signals.length})</h2>
       <ul class="findings">${result.signals
         .map((s) => `<li class="sev-${s.severity}">${escapeHtml(s.description)}${
           settings.technicalMode ? `<br><code>${escapeHtml(s.id)}: ${escapeHtml(s.evidence)}</code>` : ''
         }</li>`)
         .join('')}</ul>`
    : '<h2>Findings</h2><p class="muted">No phishing indicators detected.</p>';

  const breakdown = settings.technicalMode && result.scoreBreakdown.length
    ? `<details class="disclosure">
       <summary>Score breakdown <span>${result.score}/100</span></summary>
       <table class="breakdown">${result.scoreBreakdown
         .map((line) => `<tr><td>${escapeHtml(line.label)}</td><td>+${line.points}</td></tr>`)
         .join('')}
         <tr><td><strong>Total (clamped 0–100)</strong></td><td><strong>${result.score}</strong></td></tr>
       </table>
       </details>`
    : '';

  const explanationSection = settings.explanations
    ? `<h2>Explanation</h2>
       <button id="explainBtn">Explain this result</button>
       <div id="explanationBox" class="explanation-box" hidden></div>`
    : '';

  main.innerHTML = `
    <div class="scorecard">
      <div class="score-dial ${result.classification}">${result.score}</div>
      <div>
        <span class="chip ${result.classification}">${result.classification} risk</span>
        <div class="meta">Domain: <code>${escapeHtml(result.domain || '(unknown)')}</code></div>
        ${brandLine}
        ${result.overridden ? '<div class="meta muted">Trusted-domain override active.</div>' : ''}
      </div>
    </div>
    ${findings}
    ${renderThreatIntel(result)}
    <h2>Recommended action</h2>
    <div class="action">${escapeHtml(result.recommendedAction)}</div>
    ${breakdown}
    ${explanationSection}`;

  document.getElementById('explainBtn')?.addEventListener('click', () => {
    void fetchExplanation(result, settings);
  });
}

async function fetchExplanation(result: AnalysisResult, settings: Settings): Promise<void> {
  const box = el('explanationBox');
  const button = el<HTMLButtonElement>('explainBtn');
  box.hidden = false;
  box.textContent = 'Generating explanation…';
  button.disabled = true;
  button.textContent = 'Generating…';

  const request: ExplainRequest = {
    score: result.score,
    classification: result.classification,
    domain: result.domain,
    suspectedBrand: result.suspectedBrand,
    signals: result.signals.map((s) => ({ id: s.id, description: s.description, evidence: s.evidence })),
    scoreBreakdown: result.scoreBreakdown,
  };

  try {
    const response = await fetch(BACKEND_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    });
    if (!response.ok) throw new Error(`backend returned ${response.status}`);
    const explanation: ExplainResponse = await response.json();

    const reasons = explanation.reasons.length
      ? `<ul>${explanation.reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join('')}</ul>`
      : '';
    const citations = explanation.citations.length
      ? `<details class="explanation-citations">
           <summary>Evidence citations (${explanation.citations.length})</summary>
           <ul>${explanation.citations.map((citation) => `
             <li>
               <code>${escapeHtml(citation.signalId)}</code>
               <span>${escapeHtml(citation.description)}</span>
               <small>${escapeHtml(citation.evidence)}</small>
             </li>`).join('')}
           </ul>
         </details>`
      : '';
    const technicalDetails = settings.technicalMode
      ? `<details class="explanation-details">
           <summary>Technical details and limitations</summary>
           <p><strong>Technical:</strong> ${escapeHtml(explanation.technicalExplanation)}</p>
           ${explanation.limitations.length
             ? `<p><strong>Limitations</strong></p><ul>${explanation.limitations
               .map((limitation) => `<li>${escapeHtml(limitation)}</li>`).join('')}</ul>`
             : ''}
         </details>`
      : '';
    box.innerHTML = `
      <div class="explanation-source">Evidence-based local explanation</div>
      <p>${escapeHtml(explanation.summary)}</p>
      ${reasons}
      ${citations}
      ${technicalDetails}`;
  } catch {
    box.textContent =
      'Could not reach the explanation backend. Start it with "npm run backend" ' +
      '(the risk score above is computed locally and does not depend on it).';
  } finally {
    button.disabled = false;
    button.textContent = 'Regenerate explanation';
  }
}

async function bindSettings(result: AnalysisResult | null): Promise<void> {
  const settings = await loadSettings();

  const toggles: Array<keyof Settings> = [
    'technicalMode', 'explanations', 'submissionWarnings', 'threatIntel', 'linkProtection',
    'saveHistory',
  ];
  for (const key of toggles) {
    const box = el<HTMLInputElement>(key);
    box.checked = Boolean(settings[key]);
    box.addEventListener('change', async () => {
      const next = await saveSettings({ [key]: box.checked });
      if (result) renderResult(result, next);
    });
  }

  const trustBtn = el<HTMLButtonElement>('trustDomain');
  if (result?.domain) {
    const trusted = settings.approvedDomains.includes(result.domain);
    trustBtn.textContent = trusted ? `Untrust ${result.domain}` : `Trust ${result.domain}`;
    trustBtn.addEventListener('click', async () => {
      const current = await loadSettings();
      const approved = current.approvedDomains.includes(result.domain)
        ? current.approvedDomains.filter((d) => d !== result.domain)
        : [...current.approvedDomains, result.domain];
      await saveSettings({ approvedDomains: approved });
      trustBtn.textContent = approved.includes(result.domain)
        ? `Untrust ${result.domain}` : `Trust ${result.domain}`;
    });
  } else {
    trustBtn.hidden = true;
  }

  el<HTMLButtonElement>('clearData').addEventListener('click', async () => {
    await chrome.runtime.sendMessage({ type: 'CLEAR_DATA' });
    window.close();
  });

  el('toggleSettings').addEventListener('click', () => {
    settingsSection.hidden = !settingsSection.hidden;
  });
}

(async () => {
  el('version').textContent = `v${chrome.runtime.getManifest().version}`;
  const settings = await loadSettings();
  const { tabId, result } = await getActiveTabResult();
  if (result) renderResult(result, settings);
  else renderNoResult();
  await bindSettings(result);

  chrome.runtime.onMessage.addListener((message: ResultUpdatedMessage) => {
    if (message?.type === 'RESULT_UPDATED' && message.tabId === tabId) {
      void loadSettings().then((current) => renderResult(message.result, current));
    }
  });
})();