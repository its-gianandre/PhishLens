# Expected results for the test pages

Serve with `npm run test-pages`, then open `http://localhost:8000/`. All pages
are harmless simulations with dummy endpoints — use only fake credentials.
These expectations are enforced by `tests/pipeline.test.ts`.

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
