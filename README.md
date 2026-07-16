# PhishLens 🔎

*Project for OpenAI's Build Week.*

A Chrome (Manifest V3) extension that detects phishing websites in real time
using **rule-based detection plus evidence-based explanations**. It answers four questions
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
        → Local explanation → Warning and recommended action
```

## Quick start

```bash
npm install
npm run build        # bundles the extension into ./dist
npm test             # unit / integration / adversarial tests
npm run test-pages   # harmless phishing simulations on http://localhost:8000
npm run backend      # local explanation + threat-intel backend on 127.0.0.1:8787
npm run threat-intel:test-feed  # verify the local PhishTank feed
```

Load the extension: `chrome://extensions` → enable **Developer mode** →
**Load unpacked** → select the `dist/` folder. Then open
`http://localhost:8000/` and click through the test pages
(expectations documented in `test-pages/EXPECTED.md`).

## Local explanations

The backend converts validated detector signals into plain-language and
technical explanations using deterministic templates. Evidence citations are
copied directly from the detected signals, and no paid external service or API
key is required.

## Local PhishTank threat intelligence

PhishLens includes a dated, immutable PhishTank snapshot at:

```text
backend/threat-intel/data/phishtank-snapshot-2026-07-16.json.gz
```

This snapshot is deliberately committed so the integration works without a
PhishTank account or application key. Other downloaded feed files remain
ignored by Git. Provenance, hashes, counts, and limitations are documented in
`backend/threat-intel/SNAPSHOT.md`.

Verify the bundled snapshot before starting the extension:

```bash
npm run threat-intel:test-feed
npm run backend
```

The backend decompresses and indexes the snapshot once at startup. `GET /health`
reports whether PhishTank is available and the number of indexed URLs and
hostnames without exposing the feed path.

Page analysis remains local and appears immediately. When known-threat lookup
is enabled, the service worker asynchronously asks the local backend to check
the current URL. An exact verified URL match adds the existing
`known-malicious-url` signal and the deterministic scoring engine recalculates
the score. A hostname-only match is displayed as supporting information and
does not independently add points.

If the snapshot or backend is unavailable, the original heuristic result
remains active. If a URL is absent, the popup says "No match found in the
bundled snapshot"; absence from the snapshot does not establish that a page is
safe. The snapshot does not update automatically and becomes less current over
time.

## Architecture

| Layer | Where | Role |
| --- | --- | --- |
| Evidence extraction | `extension/content/` | Collects URL, title, visible text, headings, alt text, and per-form metadata. Never collects entered values, cookies, tokens, or full HTML. |
| Detectors | `extension/detectors/` | URL, brand-domain mismatch, sensitive forms, social-engineering language, and normalized PhishTank results. Each returns structured **evidence** (`Signal[]`), never a score. |
| Scoring | `extension/scoring/calculate-risk.ts` | The **only** place evidence becomes a number: per-signal weights + combination bonuses, clamped 0–100, banded into Low <30 ≤ Caution <60 ≤ High <80 ≤ Critical. |
| UI | `extension/popup/`, `content/warning-banner.ts` | Popup with score/findings/breakdown; in-page banner (High/Critical only); submission interception with Cancel / Leave / View evidence / Proceed. |
| Local backend | `backend/` | Loads the local PhishTank feed, provides URL lookups, and returns plain-language explanations. It never visits the checked URL or directly assigns a risk score. |

## Hard constraints (by design)

- Never collects or stores: entered passwords, form values, cookies, auth
  tokens, full page HTML, or complete browsing history.
- The explanation layer never changes the risk score, invents signals, or invents
  domain-age/reputation data. Evidence snippets are sanitized, truncated,
  and treated as untrusted (prompt-injection-resistant) input.
- All webpage content is treated as attacker-controlled input
  (see `tests/adversarial.test.ts`).
- Browsing URLs are checked only against the local feed in this phase; they are
  not sent to PhishTank or another third party.

## Settings & privacy

The popup's Settings panel provides: technical mode, explanations on/off,
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
