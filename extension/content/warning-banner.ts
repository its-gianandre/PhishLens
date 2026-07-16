import type { AnalysisResult } from '../shared/types';
import { classifySensitiveField } from './analyze-forms';

const HOST_ID = '__phishlens_root';

const STYLES = `
  :host { all: initial; }
  * { box-sizing: border-box; font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
  .banner {
    position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
    background: #40101a; color: #fff; border-bottom: 3px solid #ff4d4d;
    padding: 12px 16px; font-size: 14px; line-height: 1.45;
    display: flex; gap: 12px; align-items: flex-start;
    box-shadow: 0 2px 12px rgba(0,0,0,.4);
  }
  .banner .icon { font-size: 20px; }
  .banner .body { flex: 1; }
  .banner strong { font-weight: 700; }
  .banner button, .modal button {
    cursor: pointer; border: 1px solid rgba(255,255,255,.35); border-radius: 6px;
    background: rgba(255,255,255,.12); color: #fff; padding: 6px 12px; font-size: 13px;
    margin: 6px 8px 0 0;
  }
  .banner button:hover, .modal button:hover { background: rgba(255,255,255,.22); }
  .evidence { margin: 8px 0 0; padding-left: 18px; display: none; }
  .evidence.open { display: block; }
  .evidence li { margin: 3px 0; }
  .evidence code { background: rgba(255,255,255,.12); padding: 1px 5px; border-radius: 4px; font-size: 12px; }
  .overlay {
    position: fixed; inset: 0; z-index: 2147483647; background: rgba(0,0,0,.65);
    display: flex; align-items: center; justify-content: center;
  }
  .modal {
    background: #1c1c22; color: #fff; max-width: 440px; width: calc(100% - 40px);
    border-radius: 12px; padding: 20px 22px; font-size: 14px; line-height: 1.5;
    border-top: 4px solid #ff4d4d;
  }
  .modal h1 { font-size: 16px; margin: 0 0 8px; }
  .modal .danger { background: #b3261e; border-color: #b3261e; }
  .modal .ghost { background: transparent; }
`;

function ensureRoot(): ShadowRoot {
  let host = document.getElementById(HOST_ID);
  if (!host) {
    host = document.createElement('div');
    host.id = HOST_ID;
    document.documentElement.appendChild(host);
  }
  if (host.shadowRoot) return host.shadowRoot;
  const shadow = host.attachShadow({ mode: 'open' });
  const style = document.createElement('style');
  style.textContent = STYLES;
  shadow.appendChild(style);
  return shadow;
}

function evidenceListHtml(result: AnalysisResult): string {
  return result.signals
    .map((s) => `<li>${escapeHtml(s.description)} — <code>${escapeHtml(s.evidence)}</code></li>`)
    .join('');
}

function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, (ch) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]!
  ));
}

/** In-page warning banner, shown only for High/Critical pages. */
export function showWarningBanner(result: AnalysisResult): void {
  const shadow = ensureRoot();
  const brandNote = result.suspectedBrand
    ? ` It presents itself as <strong>${escapeHtml(result.suspectedBrand)}</strong> but is hosted on <strong>${escapeHtml(result.domain)}</strong>.`
    : '';

  let banner = shadow.querySelector<HTMLElement>('.banner');
  if (!banner) {
    banner = document.createElement('div');
    banner.className = 'banner';
    banner.addEventListener('click', (event) => {
      const act = (event.target as HTMLElement).getAttribute?.('data-act');
      if (act === 'dismiss') banner?.remove();
      if (act === 'details') banner?.querySelector('.evidence')?.classList.toggle('open');
    });
    shadow.appendChild(banner);
  }

  banner.innerHTML = `
    <div class="icon">⚠️</div>
    <div class="body">
      <div><strong>PhishLens warning:</strong> this page looks like a phishing attempt
        (risk ${result.score}/100 — ${result.classification}).${brandNote}</div>
      <button data-act="details">View evidence</button>
      <button data-act="dismiss">Dismiss</button>
      <ul class="evidence">${evidenceListHtml(result)}</ul>
    </div>`;

}

interface SubmitWarningActions {
  onProceed: () => void;
  onLeave: () => void;
}

function showSubmitWarning(result: AnalysisResult, actions: SubmitWarningActions): void {
  const shadow = ensureRoot();
  shadow.querySelector('.overlay')?.remove();

  const overlay = document.createElement('div');
  overlay.className = 'overlay';
  overlay.innerHTML = `
    <div class="modal">
      <h1>⚠️ PhishLens blocked this submission</h1>
      <p>You are about to send sensitive information to a page rated
        <strong>${result.classification}</strong> risk (${result.score}/100)${
          result.suspectedBrand
            ? ` that presents itself as <strong>${escapeHtml(result.suspectedBrand)}</strong> but is hosted on <strong>${escapeHtml(result.domain)}</strong>`
            : ''
        }.</p>
      <ul class="evidence">${evidenceListHtml(result)}</ul>
      <div>
        <button data-act="cancel">Cancel</button>
        <button data-act="leave" class="danger">Leave page</button>
        <button data-act="details" class="ghost">View evidence</button>
        <button data-act="proceed" class="ghost">Proceed anyway</button>
      </div>
    </div>`;

  overlay.addEventListener('click', (event) => {
    const act = (event.target as HTMLElement).getAttribute?.('data-act');
    if (!act && event.target !== overlay) return;
    switch (act) {
      case 'details':
        overlay.querySelector('.evidence')?.classList.toggle('open');
        return;
      case 'leave':
        overlay.remove();
        actions.onLeave();
        return;
      case 'proceed':
        overlay.remove();
        actions.onProceed();
        return;
      default: // cancel or click outside
        overlay.remove();
    }
  });

  shadow.appendChild(overlay);
}

function formIsSensitive(form: HTMLFormElement): boolean {
  for (const el of form.querySelectorAll('input, select, textarea')) {
    const type = (el.getAttribute('type') ?? '').toLowerCase();
    if (type === 'hidden') continue;
    if (classifySensitiveField(el)) return true;
  }
  return false;
}

/**
 * Intercepts sensitive-form submissions on risky pages. Uses a capture-phase
 * listener so it runs before the page's own handlers.
 */
export function installSubmitGuard(result: AnalysisResult): void {
  activeGuardResult = result;
  if (submitGuardInstalled) return;
  submitGuardInstalled = true;

  window.addEventListener(
    'submit',
    (event) => {
      const currentResult = activeGuardResult;
      if (!currentResult) return;
      const form = event.target;
      if (!(form instanceof HTMLFormElement)) return;
      if (approvedForms.has(form)) return;
      if (!formIsSensitive(form)) return;

      event.preventDefault();
      event.stopImmediatePropagation();

      showSubmitWarning(currentResult, {
        onProceed: () => {
          approvedForms.add(form);
          if (typeof form.requestSubmit === 'function') form.requestSubmit();
          else form.submit();
        },
        onLeave: () => {
          if (history.length > 1) history.back();
          else location.href = 'about:blank';
        },
      });
    },
    true,
  );
}

const approvedForms = new WeakSet<HTMLFormElement>();
let activeGuardResult: AnalysisResult | null = null;
let submitGuardInstalled = false;
