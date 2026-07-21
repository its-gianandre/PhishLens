# Expected results for the test pages

Serve with `npm run test-pages`, then open `http://localhost:8000/`. All pages
are harmless simulations with dummy endpoints — use only fake credentials.
The original detector expectations are enforced by `tests/pipeline.test.ts`;
the presentation scenarios are enforced by `tests/demo-pages.test.ts`.

Scores assume default settings (threat intel on, no approved-domain overrides).
Loopback hosts are exempt from HTTP/port signals, so scores come from content,
not from the pages being served locally.


## Explanation UI checks

Ensure the configured backend is reachable. The checked-in build uses the
AWS-hosted backend; for local backend testing, update `BACKEND_ORIGIN`, rebuild,
and start it with `npm run backend`. For each page, open the popup and click
*Explain this result*. Verify that:

- the button is disabled while *Generating explanation...* is displayed and
  changes to *Regenerate explanation* after a result appears;
- an Ollama response is labelled *Evidence-based explanation (AI-polished
  summary)*, while a fallback is labelled *Evidence-based template explanation*;
- the explanation is based only on the detected structured findings;
- *Evidence citations* expands to show the signal id, description, and exact
  supporting evidence for every detected signal; and
- Technical mode adds the score breakdown plus expandable *Technical details
  and limitations* without covering the popup content while scrolling.

## 1. normal-login.html — expected: **Low** (score 0–29; approximately 13)

| Expected signal | Why |
| --- | --- |
| `password-field` (+5) | Ordinary login form |
| `suspicious-url-keyword` (+8) | "login" appears in the page URL |

Same-origin form action, no brand claims, no manipulative language. Expected
recommendation: verify the address before signing in or entering sensitive
information. The explanation should describe the two weak indicators without
calling the page safe. Two evidence citations should appear. No banner or
submission guard is expected.

## 2. fake-microsoft-login.html — expected: **High** (score 60–79; approximately 68)

| Expected signal | Why |
| --- | --- |
| `brand-domain-mismatch` (+20) | Claims Microsoft; hosted on localhost |
| `password-field` (+5) | Credential form |
| `suspicious-url-keyword` (+8) | "login" in URL |
| combo: brand mismatch + password (+35) | Impersonation collecting credentials |

The explanation should state that the page appears to impersonate Microsoft
and connect that warning to the mismatched domain and password request. Three
evidence citations should appear. The recommended action should tell the user
not to enter passwords, codes, or payment details and to use an official app
or bookmark. Banner shows; submission guard active.

## 3. external-form.html — expected: **Caution** (score 30–59; approximately 45)

| Expected signal | Why |
| --- | --- |
| `password-field` (+5) | Credential form |
| `external-form-action` (+25) | Posts to 127.0.0.1:9999, a different domain |
| combo: password + external action (+15) | Credential exfiltration pattern |

The explanation should connect the password field to the external form
destination. Two evidence citations should appear. The recommended action
should tell the user to double-check the address before entering personal
information. No banner, but the submission guard triggers because its default
threshold is 45.

## 4. urgency-page.html — expected: **Caution** (score 30–59; approximately 39)

| Expected signal | Why |
| --- | --- |
| `urgency-language` (+5) | "act immediately", "within 24 hours" |
| `account-threat-language` (+7) | "account will be suspended" |
| `credential-request-language` (+6) | "verify your identity" |
| `financial-pressure-language` (+6) | "refund is pending", "payment method was declined" |
| `authority-language` (+5) | "security team", "official notice" |
| combo: 3+ language categories (+10) | Stacked social engineering |

The explanation should describe the stacked urgency, account-threat,
credential-request, financial-pressure, and authority language without
inventing a credential form or brand claim. Five evidence citations should
appear. No forms are present, so no submission interception occurs.

## 5. combined-phish.html — expected: **Critical** (score 80–100; clamps to 100)

| Expected signal | Why |
| --- | --- |
| `brand-domain-mismatch` (+20) | Claims Microsoft on localhost |
| `password-field` (+5) | Credential form |
| `sensitive-field` (+6) | MFA-code field |
| `external-form-action` (+25) | Posts to 127.0.0.1:9999 |
| `urgency-language` (+5), `account-threat-language` (+7), `credential-request-language` (+6), `authority-language` (+5) | Stacked manipulation |
| combos: +35, +15, +10, +10 | All dangerous groupings fire |

Raw sum far exceeds 100, so the displayed score clamps to 100 (*Critical*).
The explanation should combine the Microsoft impersonation, credential and
MFA-code fields, external form destination, and manipulative language into a
plain-language warning. The recommendation should tell the user to leave the
page and never enter credentials. Evidence citations and Technical mode must
still show the individual signals and score components rather than treating
the explanation as new detection evidence. Banner and submission guard are
both expected.


## Threat-intelligence UI checks

With the configured backend reachable and its feeds loaded, the popup should show
`Checking threat intelligence feeds...` without delaying the initial score. For a URL
with no provider matches, it should then show one `Nothing to show from threat intelligence
feeds` card. Providers with no match or unavailable data remain hidden. If one or more providers
report a match, only those provider cards appear while the local score and warnings remain active.

An exact verified URL match adds one `known-malicious-url` signal and triggers
normal deterministic rescoring. A hostname-only match is informational and
must state that it did not independently increase the score. No-match wording
must not claim the page is safe.

The normal `npm run backend` command overlays safe synthetic records for the
individual presentation scenarios below onto its feed indexes. The combined
showcase is fully local: the extension carries a localhost-only presentation
overlay for PhishTank, URLhaus, and OpenPhish plus a localhost-only Block List
Project entry. It therefore does not require an AWS change or a live-feed hit.
The AWS deployment should use the same presentation fixtures after this revision is deployed. The optional
`npm run backend:demo` alias behaves the same way. The
demo records point only at `.localhost` pages and never serve a payload.

## Presentation threat-intelligence scenarios

### 6. threat-intel-showcase.html — all four feeds together

Open `http://intel-showcase.localhost:8000/threat-intel-showcase.html`.

- Initial local result: **Low** (0), because the informational page contains no
  phishing behavior or suspicious form.
- Enriched result: **Critical**, after the safe presentation fixtures match.
- The popup displays cards for PhishTank, URLhaus, OpenPhish, and Block List
  Project at the same time.
- PhishTank, URLhaus, and OpenPhish report exact URL matches. Block List Project
  reports a hostname match from the bundled local fixture.
- Both `known-malicious-url` and `known-malware-url` signals appear, while the
  duplicate phishing providers are scored only once.

This is the recommended page for recording the threat-intelligence portion of
the presentation video.

### 7. verified-apple-id.html — PhishTank exact URL

Open `http://signin-portal.localhost:8000/verified-apple-id.html`.

- Initial local result: **High** (approximately 68) from an Apple brand-domain
  mismatch, password field, suspicious URL text, and the impersonation combo.
- Enriched result: **Critical** (100) after an exact verified PhishTank match.
- The popup shows `known-malicious-url`, High confidence, Apple as the target,
  and a verification time. URLhaus shows no match.

### 8. critical-browser-update.html — URLhaus exact active URL

Open `http://software-update.localhost:8000/critical-browser-update.html`.

- Initial local result: **Low** (approximately 8). There is no form or brand
  impersonation recognized by local rules.
- Enriched result: **High** (approximately 68) after URLhaus identifies the
  exact URL as an online malware-distribution location.
- The popup shows `known-malware-url`, status `online`, threat
  `malware_download`, and the tags `exe` and `FakeUpdate`.

### 9. blocklist-demo.html — Block List Project domain match

Open `http://blocklist-demo.localhost:8000/blocklist-demo.html`.

- Initial local result: **Low** (0), because the page contains no suspicious
  form, download, brand claim, or manipulative language.
- Enriched result: **Caution** (30) after its exact hostname matches the local
  Block List Project presentation fixture.
- Only the Block List Project provider card appears. It identifies an exact
  hostname match, High confidence, and that the check happened locally.
- One `known-malicious-url` signal is added; no remote backend or AWS change is
  required for the demonstration.

### 10. openphish-demo.html — OpenPhish exact URL

Open `http://localhost:8000/openphish-demo.html`.

- Initial local result: **Low**, driven by the password field and any weak page-text indicators.
- Enriched result: higher risk after the exact URL matches the safe synthetic OpenPhish fixture.
- The popup shows an OpenPhish exact-match card and adds one `known-malicious-url` signal.
- The card distinguishes the feed evidence from the page evidence and calls out
  the password request plus JavaScript-handled form as the specific concern.
- The match is a localhost-only presentation overlay, so it still appears when
  the remote backend is unavailable and does not alter the real OpenPhish feed.
- If the same URL appears in both OpenPhish and PhishTank, the signal is still scored only once.

## Proactive link-protection scenario

### 11. link-protection.html -- three protection levels and dynamic rescanning

Open `http://social-feed.localhost:8000/link-protection.html` with both the
test-page server and configured backend available. The page itself should remain
**Low** risk; the demonstration is about individual outbound links.

- **Safe or unknown:** the Riverside Garden Club destination receives no icon
  and opens normally.
- **Suspicious:** both Rewards Bulletin links receive an amber warning icon.
  Hovering either icon explains the brand-like hostname and reward language.
  The two tracking variants are sanitized to one destination and share a
  deduplicated lookup.
- **Known malicious:** the Account Safety destination receives a red icon
  because its sanitized URL exactly matches the safe local PhishTank fixture.
  Clicking it is paused by an interstitial that explains the finding and
  offers *Stay on this page* or *Proceed anyway*.
- **Dynamic content:** clicking *Load a new post* inserts a shortened giveaway
  link. Within a moment, a suspicious-link icon appears without a page reload.

The presentation fixture uses no live malicious destination. The dynamic
short link has a page-level click handler that prevents navigation; the local
  backend checks only its in-memory indexes and never opens it.
