# PhishLens 🔎

*Project for OpenAI's Build Week.*

A Chrome (Manifest V3) extension that detects phishing websites in real time
using **rule-based detection plus explainable AI**. It answers four questions
about every page:

1. What organization does the page claim to represent?
2. Does the actual domain match that organization?
3. Is the page collecting sensitive information?
4. What concrete evidence makes it suspicious?

The output is a transparent 0–100 risk score, a classification
(Low / Caution / High / Critical), and a plain-language + technical
explanation — never a black-box verdict.

```
Webpage → Evidence extraction → Rule-based detection → Risk scoring
        → AI explanation → Warning and recommended action
```

## Quick start

```bash
npm install
npm run build        # bundles the extension into ./dist
npm test             # 64 unit / integration / adversarial tests
npm run test-pages   # harmless phishing simulations on http://localhost:8000
npm run backend      # explanation backend (stub mode) on http://127.0.0.1:8787
```

Load the extension: `chrome://extensions` → enable **Developer mode** →
**Load unpacked** → select the `dist/` folder. Then open
`http://localhost:8000/` and click through the test pages
(expectations documented in `test-pages/EXPECTED.md`).

## Architecture

| Layer | Where | Role |
| --- | --- | --- |
| Evidence extraction | `extension/content/` | Collects URL, title, visible text, headings, alt text, and per-form metadata. Never collects entered values, cookies, tokens, or full HTML. |
| Detectors | `extension/detectors/` | URL, brand-domain mismatch, sensitive forms, social-engineering language, known-threat lookup. Each returns structured **evidence** (`Signal[]`), never a score. |
| Scoring | `extension/scoring/calculate-risk.ts` | The **only** place evidence becomes a number: per-signal weights + combination bonuses, clamped 0–100, banded into Low <30 ≤ Caution <60 ≤ High <80 ≤ Critical. |
| UI | `extension/popup/`, `content/warning-banner.ts` | Popup with score/findings/breakdown; in-page banner (High/Critical only); submission interception with Cancel / Leave / View evidence / Proceed. |
| Explainable AI | `backend/` | Receives structured signals, returns a plain-language + technical explanation. **Explains the verdict; never changes it.** Currently a deterministic stub — the swap point and system prompt for a real model are in `backend/explain.mjs`. |

## Hard constraints (by design)

- Never collects or stores: entered passwords, form values, cookies, auth
  tokens, full page HTML, or complete browsing history.
- The AI layer never changes the risk score, invents signals, or invents
  domain-age/reputation data. Evidence snippets are sanitized, truncated,
  and treated as untrusted (prompt-injection-resistant) input.
- Any AI API key lives only in the backend environment, never in extension
  code.
- All webpage content is treated as attacker-controlled input
  (see `tests/adversarial.test.ts`).

## Settings & privacy

The popup's Settings panel provides: technical mode, AI explanations on/off,
submission warnings on/off, known-threat lookup on/off, optional history
(off by default), per-domain trust overrides, and one-click deletion of all
stored results.

## Deliberately postponed

Custom ML URL classifiers, screenshot similarity, logo computer vision,
browser-in-browser detection, QR analysis, enterprise dashboards,
crowdsourced reporting, OAuth analysis, autonomous threat investigation,
and analysis inside nested iframes (the content script currently runs in the
top frame only).

## Team

Gian Fernandez
Augustin Birladeanu
Saumit Guduguntla

## Demo

See [DEMO.md](DEMO.md) for the presentation sequence.
