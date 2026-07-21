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
        → AWS-hosted backend → Optional Ollama summary → Warning and recommended action
```

## Quick start

For installation, Chrome loading, test pages, and optional backend instructions,
see the **[setup guide](SETUP.md)**.

```bash
npm install
npm run build        # bundles the extension into ./dist
npm test             # unit / integration / adversarial tests
npm run test-pages   # harmless phishing simulations on http://localhost:8000
npm run backend      # optional local backend for development on 127.0.0.1:8787
npm run threat-intel:test-feed  # verify the local PhishTank feed
```

Load the extension: `chrome://extensions` → enable **Developer mode** →
**Load unpacked** → select the `dist/` folder. Then open
`http://localhost:8000/` and click through the test pages
(expectations documented in `test-pages/EXPECTED.md`).

For a presentation-ready view of every threat-intelligence provider at once,
open `http://intel-showcase.localhost:8000/threat-intel-showcase.html`. Its
matches are explicitly scoped to this harmless localhost fixture, so the
showcase works without changing or redeploying the AWS service.

## AWS-hosted explanations

The extension is configured to call the backend at `http://18.220.29.188:8787`.
That backend runs in AWS and is configured to reach an Ollama service. The
repository does not assume whether Ollama shares the same server or runs in a
separate AWS service; only `OLLAMA_URL` and `OLLAMA_MODEL` connect the two.

Repository updates do not deploy themselves. After publishing this revision to
AWS, verify that `GET /health` includes `providers.openphish` and reports
`ollama.configured: true`. The checked-in endpoint currently uses plain HTTP;
place it behind HTTPS before using PhishLens for non-demo browsing so lookup
traffic and backend responses cannot be observed or altered in transit.

The backend first builds a deterministic explanation from validated detector
signals. When `OLLAMA_URL` is configured and reachable, Ollama rewrites only
the short summary. It never receives raw page text, signal descriptions, or
evidence snippets, and it cannot change the score, reasons, recommended action,
limitations, or citations. If Ollama is unset, times out, or returns an invalid
response, the deterministic template summary is returned automatically.

For local backend development, optionally point `OLLAMA_URL` at a reachable
Ollama server before starting the process:

```powershell
$env:OLLAMA_URL = 'http://127.0.0.1:11434'
$env:OLLAMA_MODEL = 'llama3.2:3b'
npm run backend
```

The extension continues to use `BACKEND_ORIGIN` from
`extension/shared/constants.ts`; change that value and rebuild only when you
specifically want the extension to exercise a local backend.

## Threat intelligence

PhishLens combines one extension-local domain list with three optional server-side indexes:

- **Block List Project** identifies phishing hostnames from a bundled domain-only snapshot.
  Lookups happen entirely inside the extension and continue to work without the backend.

- **PhishTank** identifies verified phishing URLs from the bundled immutable snapshot.
- **URLhaus** identifies malware-distribution URLs from an authenticated recent CSV export.
- **OpenPhish** identifies phishing URLs from its public community feed, refreshed when the
  backend starts and cached for offline fallback.

The extension also uses the complete Public Suffix List, including private hosting suffixes, to
identify registrable domains correctly for brand checks, trusted-domain overrides, forms, and
link analysis. The PSL and Block List Project snapshot are packaged data, not runtime services;
neither requires an API key, AWS access, or a network request while browsing.

### Local dataset updates

The committed Block List Project snapshot is generated from its domain-only phishing list and
validated before it can replace the previous copy. Refresh it deliberately before an extension
release:

```bash
npm run datasets:update
npm run build
```

The generated file records its source, retrieval time, SHA-256 hash, license, and entry count.
Malformed, empty, or oversized downloads are rejected. Exact hostname and parent-domain matches
can contribute the existing phishing-feed signal and can stop a known-phishing link; duplicate
matches from PhishTank or OpenPhish still produce only one scored signal. The popup displays the
Block List Project card only when it reports a match.

The browser extension never contains provider credentials and never visits a URL from a feed.
For the optional server-side providers, it sends a privacy-sanitized URL to the configured
backend, which checks its indexes without visiting the submitted destination.

### URLhaus setup

Obtain an Auth-Key from the abuse.ch Authentication Portal, then provide it only to the backend
process. In PowerShell:

```powershell
$urlhausSecureKey = Read-Host "URLhaus Auth-Key" -AsSecureString
$env:URLHAUS_AUTH_KEY = [System.Net.NetworkCredential]::new("", $urlhausSecureKey).Password
npm run backend
```

Enter the key only after PowerShell displays the masked prompt. Do not replace the prompt label
`"URLhaus Auth-Key"` with the key itself; doing that exposes the credential in terminal history.

On startup, the backend downloads the official URLhaus `recent.csv` export, validates and indexes
it, and writes an ignored local cache to `backend/threat-intel/data/urlhaus-recent.csv`. Later
starts can use that cache when no key is configured. Never commit the key, put it in extension
settings, or paste it into browser code. The key-bearing export URL is deliberately excluded from
logs and error messages.

Only exact URLhaus matches whose feed status is `online` affect scoring. Exact offline matches and
hostname-only matches remain visible as supporting context but do not independently add points.

### OpenPhish setup

OpenPhish requires no API key. When `includeOpenPhish` is enabled (the default backend command
enables it), startup downloads `https://www.openphish.com/feed.txt`, validates the URLs, and writes
the ignored cache `backend/threat-intel/data/openphish-feed.txt`. A failed refresh falls back to a
valid cache. Empty, malformed, or oversized downloads are rejected rather than replacing a valid
provider. The safe presentation entries in `demo-openphish.txt` are overlaid separately.

An exact OpenPhish URL match contributes the existing `known-malicious-url` signal. If PhishTank
and OpenPhish both contain the same URL, PhishLens emits that scored signal only once. Hostname-only
matches remain informational.

### PhishTank snapshot

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
reports whether each provider is available and the number of indexed URLs and
hostnames without exposing feed paths.

Page analysis remains in the extension and appears immediately. When known-threat lookup
is enabled, the service worker checks the bundled Block List Project snapshot locally and
asynchronously asks the configured backend for any optional server-side findings. A direct local
domain match or exact server-side URL match can add a deterministic signal and recalculate the
score. Supporting hostname-only findings from URL feeds do not independently add points.

If the feeds or backend are unavailable, the original heuristic result remains
active. The popup displays only providers that report an exact or hostname
match. When no provider reports a match, it shows one neutral “Nothing to show
from threat intelligence feeds” card; this does not establish that a page is
safe. The bundled snapshot does not update automatically and becomes less
current over time.

## Proactive link protection

PhishLens also scans visible links that lead away from the current site without opening them.
Repeated destinations are deduplicated, and dynamically inserted links are picked up by a
debounced page observer. URL heuristics recognize shorteners, raw IPs, punycode, userinfo tricks,
unusual ports, and brand-like hostnames. Nearby urgency, giveaway, credential, or financial
language can strengthen URL evidence but never produces a warning by itself.

Safe or unknown links remain untouched. Suspicious links receive a small warning icon with a
hover explanation. Exact known-threat matches and destinations with stacked high-risk evidence
are paused behind an interstitial that explains the finding and still offers a deliberate
"Proceed anyway" option.

Only external links are scanned. Before a lookup, PhishLens removes fragments, userinfo and
tracking parameters and redacts sensitive or high-entropy query values. Raw surrounding post
text and unsanitized destinations stay in the page's content-script context. Sanitized lookups
are sent to the configured backend in batches and cached for 15 minutes.

## Architecture

| Layer | Where | Role |
| --- | --- | --- |
| Evidence extraction | `extension/content/` | Collects URL, title, visible text, headings, alt text, and per-form metadata. Never collects entered values, cookies, tokens, or full HTML. |
| Detectors | `extension/detectors/` | URL, brand-domain mismatch, sensitive forms, social-engineering language, and normalized local/server threat-intelligence results. Each returns structured **evidence** (`Signal[]`), never a score. |
| Scoring | `extension/scoring/calculate-risk.ts` | The **only** place evidence becomes a number: per-signal weights + combination bonuses, clamped 0–100, banded into Low <30 ≤ Caution <60 ≤ High <80 ≤ Critical. |
| UI | `extension/popup/`, `extension/content/` | Popup with score/findings/breakdown; in-page page warnings, link markers, click interstitials, and submission interception. |
| Local datasets | `extension/data/` | Bundles the Block List Project phishing snapshot; Public Suffix List data is bundled through `tldts`. Neither requires AWS at runtime. |
| Backend service | `backend/` | Hosts optional Ollama-backed explanations and the existing PhishTank, URLhaus, and OpenPhish lookup routes. It never visits the checked URL or directly assigns a risk score. |

## Hard constraints (by design)

- Never collects or stores: entered passwords, form values, cookies, auth
  tokens, full page HTML, or complete browsing history.
- The explanation layer never changes the risk score, invents signals, or invents
  domain-age/reputation data. Evidence snippets are sanitized, truncated,
  and treated as untrusted (prompt-injection-resistant) input.
- All webpage content is treated as attacker-controlled input
  (see `tests/adversarial.test.ts`).
- Local Block List Project and Public Suffix List checks never leave the extension. Sanitized
  browsing URLs used for optional server-side lookup are sent only to the configured PhishLens
  backend; they are not sent onward to PhishTank, URLhaus, OpenPhish, or Ollama.

## Settings & privacy

The popup's Settings panel provides: technical mode, explanations on/off,
submission warnings on/off, proactive link protection on/off, known-threat lookup on/off, optional history
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

