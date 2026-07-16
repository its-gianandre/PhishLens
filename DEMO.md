# PhishLens demo script

## Setup (before presenting)

```bash
npm install
npm run build
npm run test-pages   # terminal 1 — http://localhost:8000
npm run backend      # terminal 2 — http://127.0.0.1:8787
```

Load `dist/` via `chrome://extensions` → Load unpacked. Pin the PhishLens icon.

You can confirm that the local explanation backend is ready by opening
`http://127.0.0.1:8787/health`; it should return `{"ok":true,"mode":"local"}`.

## Sequence (~4 minutes)

1. **Low-risk baseline.** Open
   `http://localhost:8000/normal-login.html`. The badge is green and the popup
   shows a score of about 13 (*Low risk*). The page has an ordinary password
   field and "login" in its test URL, but no brand mismatch, external form
   destination, or manipulative language. Point out that Low risk is not a
   guarantee of safety: the recommendation still asks the user to verify the
   address before entering sensitive information.

2. **The attack.** Open `http://localhost:8000/fake-microsoft-login.html` — a
   harmless simulated phishing page. The badge flips to orange (~68, High)
   and a warning banner is injected into the page.

3. **The evidence.** Open the popup: score dial, *High risk* chip, "Presents
   itself as: Microsoft", and findings — brand-domain mismatch, password
   field, suspicious URL keyword. Emphasize that the verdict comes from the
   deterministic detection engine and each finding is independently
   inspectable.

4. **The local explanation.** Click *Explain this result*. The button disables
   while the popup shows *Generating explanation...*, then changes to
   *Regenerate explanation*. The result is labelled *Evidence-based local
   explanation* and contains a plain-language summary, the reasons for the
   warning, and an expandable *Evidence citations* section. Expand it to show
   the exact signal ids, descriptions, and evidence that support the text.
   Point out the separation: the **detection engine** produces the evidence,
   score, and recommended action; the **local explanation layer** only
   narrates those findings and cannot change the verdict.

5. **The interception.** Type a **dummy** email and password on the fake page
   and press *Sign in*. PhishLens blocks the submission with
   Cancel / Leave page / View evidence / Proceed anyway. Click *View
   evidence*, then *Leave page*.

6. **Technical mode.** Enable the *Technical* toggle, open
   `http://localhost:8000/combined-phish.html` (Critical, 100/100). The popup
   now shows the full score breakdown — including combination bonuses — plus
   expandable evidence citations and *Technical details and limitations*.
   Expand those sections to show raw signal ids, evidence snippets, and the
   form's external destination (`127.0.0.1:9999`). Scroll through the popup to
   confirm the result card moves normally and does not cover the content.

7. **Trust & privacy (if time).** Show the Settings panel: local explanations
   on/off, per-domain trust override, history off by default, and one-click
   *Delete stored results*.

## Talking points

- Deterministic engine + local evidence-based explanation: the score and
  explanation are reproducible, auditable, and grounded in the displayed
  findings.
- Privacy: PhishLens never collects entered values, cookies, tokens, or full
  page HTML. Only sanitized structured findings are sent from the extension to
  the backend running locally on the same computer.
- Adversarially tested: split brand names, punycode look-alikes, hidden
  keywords, JS-intercepted forms, and prompt-injection attempts in page
  content (`npm test` — 64 tests).
