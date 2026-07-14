# Expected results for the test pages

Serve with `npm run test-pages`, then open `http://localhost:8000/`. All pages
are harmless simulations with dummy endpoints — use only fake credentials.
These expectations are enforced by `tests/pipeline.test.ts`.

Scores assume default settings (threat intel on, no approved-domain overrides).
Loopback hosts are exempt from HTTP/port signals, so scores come from content,
not from the pages being served locally.

## 1. normal-login.html — expected: **Low** (score < 30)

| Expected signal | Why |
| --- | --- |
| `password-field` (+5) | Ordinary login form |
| `suspicious-url-keyword` (+8) | "login" appears in the page URL |

Same-origin form action, no brand claims, no manipulative language. ~13 points.

## 2. fake-microsoft-login.html — expected: **High** (score ≥ 60, < 80)

| Expected signal | Why |
| --- | --- |
| `brand-domain-mismatch` (+20) | Claims Microsoft; hosted on localhost |
| `password-field` (+5) | Credential form |
| `suspicious-url-keyword` (+8) | "login" in URL |
| combo: brand mismatch + password (+35) | Impersonation collecting credentials |

~68 points → High. Banner shows; submission guard active.

## 3. external-form.html — expected: **Caution** (score ≥ 45, < 60)

| Expected signal | Why |
| --- | --- |
| `password-field` (+5) | Credential form |
| `external-form-action` (+25) | Posts to 127.0.0.1:9999, a different domain |
| combo: password + external action (+15) | Credential exfiltration pattern |

~45 points → Caution. No banner, but the submission guard triggers (guard
threshold defaults to 45).

## 4. urgency-page.html — expected: **Caution** (score ≥ 30, < 60)

| Expected signal | Why |
| --- | --- |
| `urgency-language` (+5) | "act immediately", "within 24 hours" |
| `account-threat-language` (+7) | "account will be suspended" |
| `credential-request-language` (+6) | "verify your identity" |
| `financial-pressure-language` (+6) | "refund is pending", "payment method was declined" |
| `authority-language` (+5) | "security team", "official notice" |
| combo: 3+ language categories (+10) | Stacked social engineering |

~39 points → Caution. No forms, so no interception.

## 5. combined-phish.html — expected: **Critical** (score ≥ 80; clamps to 100)

| Expected signal | Why |
| --- | --- |
| `brand-domain-mismatch` (+20) | Claims Microsoft on localhost |
| `password-field` (+5) | Credential form |
| `sensitive-field` (+6) | MFA-code field |
| `external-form-action` (+25) | Posts to 127.0.0.1:9999 |
| `urgency-language` (+5), `account-threat-language` (+7), `credential-request-language` (+6), `authority-language` (+5) | Stacked manipulation |
| combos: +35, +15, +10, +10 | All dangerous groupings fire |

Raw sum far exceeds 100 → clamps to 100, Critical. Banner + submission guard.
