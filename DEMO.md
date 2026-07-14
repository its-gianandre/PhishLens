# PhishLens demo script

## Setup (before presenting)

```bash
npm install
npm run build
npm run test-pages   # terminal 1 — http://localhost:8000
npm run backend      # terminal 2 — http://127.0.0.1:8787
```

Load `dist/` via `chrome://extensions` → Load unpacked. Pin the PhishLens icon.

## Sequence (~4 minutes)

1. **Legitimate baseline.** Open `https://www.microsoft.com` (or
   `login.microsoftonline.com`). Badge is green with a low score. Open the
   popup: *Low risk* — the brand detector sees "Microsoft" **and** the domain
   matches, so nothing fires.

2. **The attack.** Open `http://localhost:8000/fake-microsoft-login.html` — a
   harmless simulated phishing page. The badge flips to orange (~68, High)
   and a warning banner is injected into the page.

3. **The evidence.** Open the popup: score dial, *High risk* chip, "Presents
   itself as: Microsoft", and findings — brand-domain mismatch, password
   field, suspicious URL keyword. Emphasize: every finding is verifiable
   evidence, not a model's opinion.

4. **The explanation.** Click *Explain this result*. The backend turns the
   structured signals into plain language. Point out the separation:
   the **detection engine** produces the evidence and the score; the
   **explanation layer** only narrates it and can never change the verdict.

5. **The interception.** Type a **dummy** email and password on the fake page
   and press *Sign in*. PhishLens blocks the submission with
   Cancel / Leave page / View evidence / Proceed anyway. Click *View
   evidence*, then *Leave page*.

6. **Technical mode.** Enable the *Technical* toggle, open
   `http://localhost:8000/combined-phish.html` (Critical, 100/100). The popup
   now shows raw signal ids, evidence snippets, and the full score breakdown —
   including the combination bonuses — and the form's external destination
   (`127.0.0.1:9999`).

7. **Trust & privacy (if time).** Show the Settings panel: per-domain trust
   override, history off by default, one-click *Delete stored results*.

## Talking points

- Deterministic engine + explainable AI: the score is reproducible and
  auditable; AI only makes it understandable.
- Privacy: no entered values, cookies, tokens, or page HTML ever leave the
  page; the AI backend receives only structured signal metadata.
- Adversarially tested: split brand names, punycode look-alikes, hidden
  keywords, JS-intercepted forms, and prompt-injection attempts in page
  content (`npm test` — 64 tests).
