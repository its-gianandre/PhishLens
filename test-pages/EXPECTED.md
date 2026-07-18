# Expected results for the test pages

Serve with `npm run test-pages`, then open `http://localhost:8000/`. All pages
are harmless simulations with dummy endpoints — use only fake credentials.
The original detector expectations are enforced by `tests/pipeline.test.ts`;
the presentation scenarios are enforced by `tests/demo-pages.test.ts`.

Scores assume default settings (threat intel on, no approved-domain overrides).
Loopback hosts are exempt from HTTP/port signals, so scores come from content,
not from the pages being served locally.


## Explanation UI checks

Start the local explanation backend with `npm run backend`. For each page,
open the popup and click *Explain this result*. Verify that:

- the button is disabled while *Generating explanation...* is displayed and
  changes to *Regenerate explanation* after a result appears;
- the output is labelled *Evidence-based local explanation*;
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

With `npm run backend` running and the local feed loaded, the popup should show
`Checking PhishTank...` without delaying the initial score. It should then show
`No match found in the bundled snapshot` for these harmless local fixtures. If
the backend or snapshot is unavailable, it should show `PhishTank lookup unavailable` while
preserving the local score and warnings.

An exact verified URL match adds one `known-malicious-url` signal and triggers
normal deterministic rescoring. A hostname-only match is informational and
must state that it did not independently increase the score. No-match wording
must not claim the page is safe.

The normal `npm run backend` command overlays safe synthetic PhishTank and
URLhaus records for the presentation scenarios below onto its real local feed
indexes. The optional `npm run backend:demo` alias behaves the same way. The
demo records point only at `.localhost` pages and never serve a payload.

## Presentation threat-intelligence scenarios

### 6. verified-apple-id.html — PhishTank exact URL

Open `http://signin-portal.localhost:8000/verified-apple-id.html`.

- Initial local result: **High** (approximately 68) from an Apple brand-domain
  mismatch, password field, suspicious URL text, and the impersonation combo.
- Enriched result: **Critical** (100) after an exact verified PhishTank match.
- The popup shows `known-malicious-url`, High confidence, Apple as the target,
  and a verification time. URLhaus shows no match.

### 7. critical-browser-update.html — URLhaus exact active URL

Open `http://software-update.localhost:8000/critical-browser-update.html`.

- Initial local result: **Low** (approximately 8). There is no form or brand
  impersonation recognized by local rules.
- Enriched result: **High** (approximately 68) after URLhaus identifies the
  exact URL as an online malware-distribution location.
- The popup shows `known-malware-url`, status `online`, threat
  `malware_download`, and the tags `exe` and `FakeUpdate`.

### 8. vendor-status.html — both providers, hostname only

Open `http://reputation-lab.localhost:8000/vendor-status.html`.

- Initial and enriched result: **Low** (0), with no local indicators.
- PhishTank and URLhaus each report other known URLs on the hostname.
- Both cards explicitly say that hostname-only findings did not independently
  increase the score. No scored threat-intelligence signal is added.

## Proactive link-protection scenario

### 9. link-protection.html -- three protection levels and dynamic rescanning

Open `http://social-feed.localhost:8000/link-protection.html` with both the
test-page server and local backend running. The page itself should remain
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
