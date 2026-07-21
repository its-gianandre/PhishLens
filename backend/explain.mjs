/**
 * Explanation layer for PhishLens.
 *
 * The deterministic engine in the extension computes the score; this layer
 * only turns already-computed evidence into plain language. It must never
 * change the score, invent signals, invent domain-age/reputation data, or
 * declare a site malicious without evidence.
 *
 * Explanations are generated from validated signal templates. An optional
 * Ollama model may rewrite only the summary; the score, reasons, recommended
 * action, limitations, and citations remain deterministic.
 */

const VALID_CLASSIFICATIONS = new Set(['Low', 'Caution', 'High', 'Critical']);
const SIGNAL_ID_PATTERN = /^[a-z][a-z0-9-]{1,40}$/;
const MAX_SIGNALS = 32;
const MAX_STRING = 300;

// Optional: an Ollama server that rewrites the deterministic summary in more
// natural language. Only enabled when OLLAMA_URL is set. When unset or
// unreachable, `explain()` falls back to the template-only summary below.
const DEFAULT_OLLAMA_MODEL = 'llama3.2:3b';
// Generous timeout for CPU-backed cloud deployments. The popup already shows
// a "Generating..." state and allows slightly longer than the backend here.
const DEFAULT_OLLAMA_TIMEOUT_MS = 45_000;

/** Strip control characters and cap length. Applied to every incoming string. */
export function sanitizeString(value) {
  return String(value ?? '')
    .replace(/[\u0000-\u001f\u007f\u200b-\u200f\u2028\u2029]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, MAX_STRING);
}

/**
 * Validates and sanitizes an ExplainRequest. Throws on structural problems.
 * Only whitelisted fields survive.
 */
export function sanitizeRequest(body) {
  if (typeof body !== 'object' || body === null) throw new Error('body must be an object');
  const score = Number(body.score);
  if (!Number.isFinite(score) || score < 0 || score > 100) throw new Error('score must be 0-100');
  if (!VALID_CLASSIFICATIONS.has(body.classification)) throw new Error('invalid classification');
  if (!Array.isArray(body.signals)) throw new Error('signals must be an array');

  const signals = body.signals.slice(0, MAX_SIGNALS).map((signal) => {
    const id = String(signal?.id ?? '');
    if (!SIGNAL_ID_PATTERN.test(id)) throw new Error(`invalid signal id: ${id.slice(0, 40)}`);
    return {
      id,
      description: sanitizeString(signal.description),
      evidence: sanitizeString(signal.evidence),
    };
  });

  return {
    score: Math.round(score),
    classification: body.classification,
    domain: sanitizeString(body.domain),
    suspectedBrand: body.suspectedBrand == null ? null : sanitizeString(body.suspectedBrand),
    signals,
  };
}

/**
 * Plain-language reason templates, keyed by signal id. The local engine builds its
 * output ONLY from these templates plus sanitized domain/brand names — never
 * from free-form page text — which is its prompt-injection resistance.
 */
const REASON_TEMPLATES = {
  'brand-domain-mismatch': (r) =>
    `The page presents itself as ${r.suspectedBrand ?? 'a well-known brand'}, but its actual domain (${r.domain}) is not an official domain of that brand. This is the classic signature of a phishing page.`,
  'password-field': () => 'The page asks you to enter a password.',
  'sensitive-field': () => 'The page asks for other sensitive information such as codes, card details, or recovery keys.',
  'external-form-action': () => 'Information typed into this page would be sent to a different website than the one you are looking at.',
  'insecure-form-action': () => 'The form sends data over an unencrypted connection, so anyone on the network could read it.',
  'hidden-sensitive-field': () => 'The page contains hidden form fields with sensitive-sounding names, which legitimate login pages rarely need.',
  'js-intercepted-form': () => 'The login form is handled by a script rather than a normal submission, which hides where your data actually goes.',
  'ip-address-host': () => 'The site is addressed by a raw IP address instead of a normal domain name.',
  'punycode-host': () => 'The domain uses special encoded characters that can imitate the look of a legitimate domain.',
  'excessive-subdomains': () => 'The web address is padded with many subdomains, a common trick to make it look official.',
  'long-url': () => 'The web address is unusually long, which often hides the true destination.',
  'suspicious-url-keyword': () => 'The address contains words like "login" or "verify" that phishing pages use to look legitimate.',
  'excessive-hyphens': () => 'The domain name contains many hyphens, common in throwaway phishing domains.',
  'brand-in-hostname': () => 'A well-known brand name is embedded in the web address even though the site is not owned by that brand.',
  'insecure-scheme': () => 'The page is served over an unencrypted connection.',
  'url-shortener': () => 'The address is a link-shortening service, which hides the real destination.',
  'suspicious-port': () => 'The site runs on a non-standard network port, unusual for legitimate services.',
  'userinfo-in-url': () => 'The address embeds a fake username before an "@" sign — everything before the "@" is decoration; the real site comes after it.',
  'urgency-language': () => 'The page pressures you to act immediately, a standard social-engineering tactic.',
  'account-threat-language': () => 'The page threatens that your account will be suspended or closed to scare you into acting.',
  'credential-request-language': () => 'The text explicitly asks you to verify or re-enter credentials.',
  'financial-pressure-language': () => 'The page applies financial pressure, such as failed payments or pending refunds.',
  'authority-language': () => 'The page borrows the voice of an authority (security team, government, legal) to appear trustworthy.',
  'reward-language': () => 'The page promises a prize or reward, a common lure.',
  'known-malicious-url': () => 'This site appears on a list of known phishing sites.',
  'known-malware-url': () => 'This exact address appears in URLhaus as an active malware-distribution URL.',
};

const SUMMARY_BY_CLASS = {
  Low: (r) => `No strong phishing indicators were found on ${r.domain || 'this page'}. The detected signals are common on legitimate sites.`,
  Caution: (r) => `Some suspicious characteristics were found on ${r.domain || 'this page'}. It is not conclusively phishing, but be careful before entering personal information.`,
  High: (r) => `This page shows several hallmarks of a phishing attempt${r.suspectedBrand ? ` impersonating ${r.suspectedBrand}` : ''}. Treat it as unsafe.`,
  Critical: (r) => `This page is almost certainly a phishing attack${r.suspectedBrand ? ` impersonating ${r.suspectedBrand}` : ''}. Do not enter any information.`,
};

const ACTION_BY_CLASS = {
  Low: 'No strong phishing indicators were found. Verify the address before signing in or entering sensitive information.',
  Caution: 'Double-check the address bar and avoid entering credentials unless you are certain the site is genuine.',
  High: 'Do not enter passwords, codes, or payment details. Reach the real service through an official app or a bookmark instead.',
  Critical: 'Leave this page now and do not enter anything. If you already submitted credentials here, change that password immediately.',
};

function evidenceCitations(request) {
  return request.signals.map((signal) => ({
    signalId: signal.id,
    description: signal.description,
    evidence: signal.evidence,
  }));
}

/**
 * Deterministic explanation generated exclusively from sanitized findings.
 */
export function localExplanation(request) {
  const reasons = request.signals
    .map((signal) => REASON_TEMPLATES[signal.id]?.(request))
    .filter(Boolean);
  if (reasons.length === 0) reasons.push('No phishing indicators were detected on this page.');

  const technical = request.signals.length
    ? 'Deterministic signals: ' +
      request.signals.map((s) => `${s.id} [${s.evidence}]`).join('; ') +
      `. Weighted sum with combination bonuses yields ${request.score}/100 (${request.classification}).`
    : `No signals fired; score ${request.score}/100 (${request.classification}).`;

  return {
    summary: SUMMARY_BY_CLASS[request.classification](request),
    reasons: reasons.slice(0, 6),
    recommendedAction: ACTION_BY_CLASS[request.classification],
    technicalExplanation: technical,
    limitations: [
      'PhishLens only sees the current page; it does not check domain age, hosting reputation, or email origin.',
      'A low score does not guarantee a site is safe, and sophisticated phishing can evade rule-based detection.',
      'This explanation was generated from the detected signals only.',
    ],
    citations: evidenceCitations(request),
  };
}

/**
 * Builds the prompt sent to Ollama. Only fixed, already-sanitized template
 * strings (the same `reasons` a user would see without an LLM at all) plus
 * score/classification/domain/brand are included — never raw signal
 * evidence or page text — so there is nothing in the prompt for an attacker
 * to inject instructions into.
 */
function buildOllamaPrompt(request, reasons) {
  const lines = [
    'You are writing a short summary for a browser phishing-detection tool.',
    'Use ONLY the facts listed below. Do not invent new claims and do not change the risk level.',
    `Domain: ${request.domain || '(unknown)'}`,
    `Risk classification: ${request.classification} (score ${request.score}/100)`,
  ];
  if (request.suspectedBrand) lines.push(`Impersonated brand: ${request.suspectedBrand}`);
  lines.push(
    reasons.length
      ? `Detected reasons:\n- ${reasons.join('\n- ')}`
      : 'No phishing indicators were detected.',
    '',
    'Write exactly 2 short plain-English sentences (no more than 45 words total) summarizing ' +
      'this for a non-technical reader. No markdown.',
  );
  return lines.join('\n');
}

async function generateOllamaSummary(request, reasons, options = {}) {
  const ollamaUrl = String(options.ollamaUrl ?? process.env.OLLAMA_URL ?? '')
    .trim()
    .replace(/\/+$/, '');
  if (!ollamaUrl) return null;

  const ollamaModel = options.ollamaModel ?? process.env.OLLAMA_MODEL ?? DEFAULT_OLLAMA_MODEL;
  const timeoutMs = options.ollamaTimeoutMs ?? DEFAULT_OLLAMA_TIMEOUT_MS;
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  try {
    const response = await fetchImpl(`${ollamaUrl}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: ollamaModel,
        prompt: buildOllamaPrompt(request, reasons),
        stream: false,
        options: { temperature: 0.2, num_predict: 220 },
      }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!response.ok) return null;
    const body = await response.json();
    return typeof body?.response === 'string' ? sanitizeString(body.response) || null : null;
  } catch {
    return null;
  }
}

export async function explain(request, options = {}) {
  const sanitized = sanitizeRequest(request);
  const base = localExplanation(sanitized);
  const llmSummary = await generateOllamaSummary(sanitized, base.reasons, options);
  return llmSummary
    ? { ...base, summary: llmSummary, summarySource: 'ollama' }
    : { ...base, summarySource: 'local-template' };
}
