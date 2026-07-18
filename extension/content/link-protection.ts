import { detectLanguageSignals } from '../detectors/language-detector';
import { detectUrlSignals } from '../detectors/url-detector';
import { getRegistrableDomain } from '../shared/domain';
import { sanitizeLinkUrl } from '../shared/sanitize-link-url';
import type {
  AnalyzeLinksResponse,
  LinkAssessment,
  LinkCandidate,
  LinkContextSignalId,
  LinkUrlSignalId,
} from '../shared/types';
import { showLinkWarning } from './warning-banner';

const MARKER_ATTRIBUTE = 'data-phishlens-link-warning';
const MAX_LINKS_PER_MESSAGE = 100;
const MAX_UNIQUE_LINKS_PER_SCAN = 500;
const CONTEXT_CHARS = 800;

export interface CollectedLink {
  candidate: LinkCandidate;
  anchors: HTMLAnchorElement[];
}

function isVisible(anchor: HTMLAnchorElement): boolean {
  if (anchor.hidden || anchor.closest('[hidden], [aria-hidden="true"]')) return false;
  const view = anchor.ownerDocument.defaultView;
  if (!view?.getComputedStyle) return true;
  let element: HTMLElement | null = anchor;
  while (element) {
    const style = view.getComputedStyle(element);
    if (
      style.display === 'none' ||
      style.visibility === 'hidden' ||
      style.visibility === 'collapse' ||
      style.opacity === '0'
    ) return false;
    element = element.parentElement;
  }
  return true;
}

function surroundingText(anchor: HTMLAnchorElement): string {
  const container = anchor.closest(
    'article, [role="article"], [data-testid*="post" i], blockquote, li, p',
  ) ?? anchor.parentElement;
  return (container?.textContent ?? '').replace(/\s+/g, ' ').trim().slice(0, CONTEXT_CHARS);
}

function signalIdsFor(anchor: HTMLAnchorElement): {
  urlSignalIds: LinkUrlSignalId[];
  contextSignalIds: LinkContextSignalId[];
} {
  const urlSignalIds = detectUrlSignals(anchor.href).map((signal) => signal.id as LinkUrlSignalId);
  const contextSignalIds = detectLanguageSignals({
    title: '',
    headings: [],
    visibleText: surroundingText(anchor),
  }).map((signal) => signal.id as LinkContextSignalId);
  return {
    urlSignalIds: [...new Set(urlSignalIds)],
    contextSignalIds: [...new Set(contextSignalIds)],
  };
}

/** Collect visible cross-site HTTP(S) links, merging repeated destinations. */
export function collectExternalLinks(
  doc: Document = document,
  pageUrl: string = location.href,
): CollectedLink[] {
  let pageDomain: string;
  try {
    pageDomain = getRegistrableDomain(new URL(pageUrl).hostname);
  } catch {
    return [];
  }

  const collected = new Map<string, CollectedLink>();
  for (const anchor of doc.querySelectorAll<HTMLAnchorElement>('a[href]')) {
    if (collected.size >= MAX_UNIQUE_LINKS_PER_SCAN) break;
    if (!isVisible(anchor) || anchor.hasAttribute('download')) continue;
    let destination: URL;
    try {
      destination = new URL(anchor.href, pageUrl);
    } catch {
      continue;
    }
    if (destination.protocol !== 'http:' && destination.protocol !== 'https:') continue;
    if (getRegistrableDomain(destination.hostname) === pageDomain) continue;

    const lookupUrl = sanitizeLinkUrl(anchor.href);
    if (!lookupUrl) continue;
    const ids = signalIdsFor(anchor);
    const existing = collected.get(lookupUrl);
    if (existing) {
      existing.anchors.push(anchor);
      existing.candidate.urlSignalIds = [
        ...new Set([...existing.candidate.urlSignalIds, ...ids.urlSignalIds]),
      ];
      existing.candidate.contextSignalIds = [
        ...new Set([...existing.candidate.contextSignalIds, ...ids.contextSignalIds]),
      ];
    } else {
      collected.set(lookupUrl, {
        candidate: { key: lookupUrl, lookupUrl, ...ids },
        anchors: [anchor],
      });
    }
  }
  return [...collected.values()];
}

function markerTitle(assessment: LinkAssessment): string {
  const heading = assessment.risk === 'high'
    ? 'High-risk link — PhishLens will pause before opening it.'
    : 'Suspicious link.';
  return `${heading} ${assessment.reasons.join('. ')}`.trim();
}

function updateMarker(anchor: HTMLAnchorElement, assessment: LinkAssessment): void {
  const existing = anchor.nextElementSibling as HTMLElement | null;
  if (assessment.risk === 'safe') {
    if (existing?.hasAttribute(MARKER_ATTRIBUTE)) existing.remove();
    return;
  }

  let marker = existing?.hasAttribute(MARKER_ATTRIBUTE) ? existing : null;
  if (!marker) {
    marker = document.createElement('span');
    marker.setAttribute(MARKER_ATTRIBUTE, '');
    marker.setAttribute('aria-hidden', 'false');
    const shadow = marker.attachShadow({ mode: 'open' });
    const style = document.createElement('style');
    style.textContent = `
      :host { all: initial; display: inline; margin-left: .2em; }
      span { cursor: help; font: 13px/1 -apple-system, "Segoe UI", sans-serif; }
      .suspicious { color: #9a6700; }
      .high { color: #cf222e; }
    `;
    shadow.append(style, document.createElement('span'));
    anchor.insertAdjacentElement('afterend', marker);
  }
  marker.title = markerTitle(assessment);
  marker.setAttribute('aria-label', marker.title);
  const icon = marker.shadowRoot?.querySelector('span');
  if (icon) {
    icon.className = assessment.risk;
    icon.textContent = assessment.risk === 'high' ? '⛔' : '⚠️';
  }
}

function signature(candidate: LinkCandidate): string {
  return JSON.stringify([
    [...candidate.urlSignalIds].sort(),
    [...candidate.contextSignalIds].sort(),
  ]);
}

export function installLinkProtection(): void {
  const assessments = new Map<string, LinkAssessment>();
  const signatures = new Map<string, string>();
  const anchorsByKey = new Map<string, HTMLAnchorElement[]>();
  const approvedAnchors = new WeakSet<HTMLAnchorElement>();
  let scanTimer: number | undefined;

  const scan = async (): Promise<void> => {
    const collected = collectExternalLinks();
    anchorsByKey.clear();
    const activeAnchors = new Set<HTMLAnchorElement>();
    for (const item of collected) {
      anchorsByKey.set(item.candidate.key, item.anchors);
      item.anchors.forEach((anchor) => activeAnchors.add(anchor));
      const existing = assessments.get(item.candidate.key);
      if (existing) item.anchors.forEach((anchor) => updateMarker(anchor, existing));
    }
    document.querySelectorAll<HTMLElement>(`[${MARKER_ATTRIBUTE}]`).forEach((marker) => {
      const anchor = marker.previousElementSibling;
      if (!(anchor instanceof HTMLAnchorElement) || !activeAnchors.has(anchor)) marker.remove();
    });

    const changed = collected
      .map((item) => item.candidate)
      .filter((candidate) => signatures.get(candidate.key) !== signature(candidate));
    for (let offset = 0; offset < changed.length; offset += MAX_LINKS_PER_MESSAGE) {
      const links = changed.slice(offset, offset + MAX_LINKS_PER_MESSAGE);
      links.forEach((candidate) => signatures.set(candidate.key, signature(candidate)));
      try {
        const response = await chrome.runtime.sendMessage({
          type: 'ANALYZE_LINKS',
          links,
        }) as AnalyzeLinksResponse | undefined;
        if (!response?.assessments) return;
        for (const assessment of response.assessments) {
          assessments.set(assessment.key, assessment);
          anchorsByKey.get(assessment.key)?.forEach((anchor) => updateMarker(anchor, assessment));
        }
      } catch {
        return; // Extension reload or backend unavailability should not affect browsing.
      }
    }
  };

  const scheduleScan = (): void => {
    if (scanTimer !== undefined) window.clearTimeout(scanTimer);
    scanTimer = window.setTimeout(() => void scan(), 350);
  };

  document.addEventListener('click', (event) => {
    if (!(event instanceof MouseEvent) || event.button !== 0) return;
    const target = event.target;
    if (!(target instanceof Element)) return;
    const anchor = target.closest<HTMLAnchorElement>('a[href]');
    if (!anchor || approvedAnchors.has(anchor)) return;
    const key = sanitizeLinkUrl(anchor.href);
    const assessment = key ? assessments.get(key) : null;
    if (!assessment || assessment.risk !== 'high') return;

    event.preventDefault();
    event.stopImmediatePropagation();
    const openNew = event.metaKey || event.ctrlKey || event.shiftKey || anchor.target === '_blank';
    showLinkWarning(key!, assessment, {
      onProceed: () => {
        approvedAnchors.add(anchor);
        if (openNew) window.open(anchor.href, anchor.target || '_blank', 'noopener');
        else location.assign(anchor.href);
      },
    });
  }, true);

  const observer = new MutationObserver((mutations) => {
    const relevant = mutations.some((mutation) => {
      const target = mutation.target as Element;
      return !target.closest?.(`[${MARKER_ATTRIBUTE}]`);
    });
    if (relevant) scheduleScan();
  });
  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['href', 'hidden', 'aria-hidden'],
  });

  void scan();
}
