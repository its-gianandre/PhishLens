import type { BrandEntry, RiskClass, SignalId } from './types';

export const LIMITS = {
  visibleTextChars: 20_000,
  headings: 30,
  altTexts: 50,
  formsPerPage: 25,
  evidenceSnippetChars: 140,
  historyEntries: 50,
} as const;

/**
 * Points contributed by each signal (counted once per signal id).
 * Tuned against test-pages/EXPECTED.md — see tests/pipeline.test.ts.
 */
export const SIGNAL_WEIGHTS: Record<SignalId, number> = {
  'known-malware-url': 60,
  'known-malicious-url': 30,
  'external-form-action': 25,
  'brand-domain-mismatch': 20,
  'punycode-host': 12,
  'ip-address-host': 12,
  'userinfo-in-url': 10,
  'brand-in-hostname': 10,
  'insecure-form-action': 10,
  'suspicious-url-keyword': 8,
  'account-threat-language': 7,
  'excessive-subdomains': 6,
  'url-shortener': 6,
  'suspicious-port': 6,
  'insecure-scheme': 6,
  'sensitive-field': 6,
  'hidden-sensitive-field': 6,
  'credential-request-language': 6,
  'financial-pressure-language': 6,
  'password-field': 5,
  'urgency-language': 5,
  'authority-language': 5,
  'excessive-hyphens': 4,
  'long-url': 4,
  'js-intercepted-form': 4,
  'reward-language': 4,
};

export interface PairCombo {
  requires: [SignalId, SignalId];
  bonus: number;
  label: string;
}

/** Bonuses for dangerous signal groups. */
export const PAIR_COMBOS: PairCombo[] = [
  {
    requires: ['brand-domain-mismatch', 'password-field'],
    bonus: 35,
    label: 'Brand impersonation combined with password collection',
  },
  {
    requires: ['password-field', 'external-form-action'],
    bonus: 15,
    label: 'Password submitted to an external destination',
  },
  {
    requires: ['known-malicious-url', 'password-field'],
    bonus: 20,
    label: 'Known-malicious site collecting a password',
  },
];

export const COMBO_BRAND_PLUS_LANGUAGE = {
  bonus: 10,
  label: 'Brand impersonation combined with manipulative language',
} as const;

export const COMBO_MULTI_LANGUAGE = {
  minCategories: 3,
  bonus: 10,
  label: 'Multiple social-engineering tactics on one page',
} as const;

export const LANGUAGE_SIGNAL_IDS = new Set<SignalId>([
  'urgency-language',
  'account-threat-language',
  'credential-request-language',
  'financial-pressure-language',
  'authority-language',
  'reward-language',
]);

/** Classification bands, checked top-down. */
export const RISK_BANDS: Array<{ min: number; classification: RiskClass }> = [
  { min: 80, classification: 'Critical' },
  { min: 60, classification: 'High' },
  { min: 30, classification: 'Caution' },
  { min: 0, classification: 'Low' },
];

export const RECOMMENDED_ACTIONS: Record<RiskClass, string> = {
  Low: 'No strong phishing indicators were found. Verify the address before signing in or entering sensitive information.',
  Caution:
    'Some suspicious indicators were found. Double-check the address bar before entering any personal information.',
  High:
    'Do not enter passwords, codes, or payment details on this page. Verify the site through an official app or bookmark instead.',
  Critical:
    'Leave this page. It shows strong signs of a phishing attack. Never enter credentials here.',
};

/** Commonly impersonated brands. Keywords are matched fuzzily (case/split tolerant). */
export const BRANDS: BrandEntry[] = [
  {
    name: 'Microsoft',
    keywords: ['microsoft', 'office 365', 'office365', 'outlook', 'onedrive', 'sharepoint', 'azure'],
    domains: ['microsoft.com', 'microsoftonline.com', 'live.com', 'outlook.com', 'office.com', 'azure.com', 'sharepoint.com', 'windows.net', 'msn.com', 'skype.com'],
  },
  {
    name: 'Google',
    keywords: ['google', 'gmail', 'google drive', 'google account'],
    domains: ['google.com', 'gmail.com', 'youtube.com', 'googleusercontent.com', 'withgoogle.com'],
  },
  {
    name: 'Apple',
    keywords: ['apple id', 'icloud', 'app store', 'itunes', 'apple account'],
    domains: ['apple.com', 'icloud.com'],
    hostTokens: ['appleid', 'icloud', 'apple'],
  },
  {
    name: 'PayPal',
    keywords: ['paypal'],
    domains: ['paypal.com', 'paypal.me'],
  },
  {
    name: 'Amazon',
    keywords: ['amazon', 'amazon prime', 'aws'],
    domains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazonaws.com', 'primevideo.com'],
  },
  {
    name: 'GitHub',
    keywords: ['github'],
    domains: ['github.com', 'github.io', 'githubusercontent.com'],
  },
  {
    name: 'Discord',
    keywords: ['discord', 'discord nitro'],
    domains: ['discord.com', 'discord.gg', 'discordapp.com'],
  },
  {
    name: 'Facebook',
    keywords: ['facebook'],
    domains: ['facebook.com', 'fb.com', 'messenger.com'],
  },
  {
    name: 'Instagram',
    keywords: ['instagram'],
    domains: ['instagram.com'],
  },
  {
    name: 'Netflix',
    keywords: ['netflix'],
    domains: ['netflix.com'],
  },
  {
    name: 'LinkedIn',
    keywords: ['linkedin'],
    domains: ['linkedin.com'],
  },
  {
    name: 'Chase',
    keywords: ['chase bank', 'jpmorgan chase', 'chase online'],
    domains: ['chase.com', 'jpmorganchase.com'],
    hostTokens: ['chasebank', 'jpmorgan'],
  },
  {
    name: 'Bank of America',
    keywords: ['bank of america', 'bankofamerica'],
    domains: ['bankofamerica.com', 'bofa.com'],
    hostTokens: ['bankofamerica', 'bofa-'],
  },
  {
    name: 'Wells Fargo',
    keywords: ['wells fargo', 'wellsfargo'],
    domains: ['wellsfargo.com'],
    hostTokens: ['wellsfargo'],
  },
  {
    name: 'Steam',
    keywords: ['steam community', 'steamcommunity', 'steampowered', 'steam account'],
    domains: ['steampowered.com', 'steamcommunity.com'],
    hostTokens: ['steamcommunity', 'steampowered'],
  },
];

export const SUSPICIOUS_URL_KEYWORDS = [
  'login', 'signin', 'sign-in', 'logon', 'verify', 'verification', 'secure',
  'account', 'update', 'confirm', 'password', 'banking', 'wallet', 'recovery',
  'unlock', 'suspended', 'invoice',
];

export const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly', 'ow.ly',
  'rb.gy', 'cutt.ly', 'shorturl.at',
]);

/** Second-level public suffixes for simplified registrable-domain extraction. */
export const MULTI_PART_TLDS = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk',
  'com.au', 'net.au', 'org.au',
  'co.nz', 'co.jp', 'or.jp', 'ne.jp',
  'com.br', 'com.mx', 'com.ar',
  'co.in', 'co.za', 'com.sg', 'com.my', 'com.hk', 'com.tw', 'com.cn',
  'com.tr', 'co.kr',
]);

export interface LanguageRule {
  signal: SignalId;
  description: string;
  patterns: RegExp[];
}

export const LANGUAGE_RULES: LanguageRule[] = [
  {
    signal: 'urgency-language',
    description: 'Uses urgency or time pressure',
    patterns: [
      /act (now|immediately|fast)/i,
      /immediate(ly)? (action|attention)/i,
      /within (the next )?\d+ (hours?|minutes?)/i,
      /right away|as soon as possible/i,
      /\burgent(ly)?\b/i,
      /expires? (today|soon|in \d+)/i,
      /final (notice|warning|reminder)/i,
    ],
  },
  {
    signal: 'account-threat-language',
    description: 'Threatens account suspension, closure, or lockout',
    patterns: [
      /account (will be|has been|is being|is) (suspended|closed|locked|disabled|restricted|terminated|deactivated)/i,
      /(suspend|close|lock|disable|restrict|terminate|deactivat)\w* (of )?your account/i,
      /suspicious (activity|sign[-\s]?in|login)/i,
      /unusual (activity|sign[-\s]?in|login)/i,
      /unauthorized (access|activity|attempt)/i,
      /permanently (deleted|disabled|lost)/i,
      /avoid (account )?(suspension|closure|termination)/i,
    ],
  },
  {
    signal: 'credential-request-language',
    description: 'Asks the reader to provide or confirm credentials',
    patterns: [
      /verify your (password|identity|account|credentials|information)/i,
      /(confirm|update|re-?enter|validate) your (password|payment|billing|card|account details)/i,
      /enter your (authentication|verification|security) code/i,
      /provide your (password|pin|social security|card)/i,
      /re-?authenticate/i,
    ],
  },
  {
    signal: 'financial-pressure-language',
    description: 'Applies financial pressure (refunds, failed payments, invoices)',
    patterns: [
      /refund (is )?(pending|waiting|available)/i,
      /payment (failed|declined|was declined|problem|issue|method has expired)/i,
      /billing (problem|issue|error|information)/i,
      /invoice (attached|overdue|due)/i,
      /outstanding (balance|payment)/i,
      /charged? (to )?your (account|card)/i,
    ],
  },
  {
    signal: 'authority-language',
    description: 'Impersonates an authority (security team, government, legal)',
    patterns: [
      /(security|fraud|billing|support|compliance) (team|department|center|centre)/i,
      /official (notice|notification|communication)/i,
      /legal action|law enforcement/i,
      /\b(irs|hmrc|interpol|fbi)\b/i,
    ],
  },
  {
    signal: 'reward-language',
    description: 'Promises a prize, reward, or gift',
    patterns: [
      /you('| ha)ve (won|been selected)/i,
      /congratulations.{0,40}(selected|won|chosen|winner)/i,
      /claim your (prize|reward|gift|voucher)/i,
      /free (gift|prize|reward|iphone|giveaway)/i,
    ],
  },
];

export interface SensitiveFieldRule {
  label: string;
  pattern: RegExp;
}

/** Matched against a field's name/id/autocomplete/placeholder/aria-label. */
export const SENSITIVE_FIELD_RULES: SensitiveFieldRule[] = [
  { label: 'password', pattern: /passw(or)?d|passcode/i },
  { label: 'mfa-code', pattern: /(^|[^a-z0-9])(otp|mfa|2fa|totp)([^a-z0-9]|$)|one[-\s_]?time[-\s_]?(code|password|pin)|auth(entication)?[-\s_]?code|verification[-\s_]?code/i },
  { label: 'card-number', pattern: /card[-\s_]?(number|no)\b|\bcc[-\s_]?(num|number)\b|credit[-\s_]?card|cc-number/i },
  { label: 'card-security-code', pattern: /\b(cvv|cvc|csc)\b|security[-\s_]?code/i },
  { label: 'ssn', pattern: /\bssn\b|social[-\s_]?security/i },
  { label: 'recovery-code', pattern: /recovery[-\s_]?(code|key|phrase)/i },
  { label: 'seed-phrase', pattern: /seed[-\s_]?phrase|mnemonic|secret[-\s_]?(recovery[-\s_]?)?phrase/i },
  { label: 'api-key', pattern: /api[-\s_]?key/i },
  { label: 'access-token', pattern: /\b(access|auth|bearer)[-\s_]?token\b/i },
];

/** Short human labels for signal ids (popup + breakdown display). */
export const SIGNAL_LABELS: Record<SignalId, string> = {
  'ip-address-host': 'IP address used as domain',
  'punycode-host': 'Punycode (look-alike) domain',
  'excessive-subdomains': 'Excessive subdomains',
  'long-url': 'Unusually long URL',
  'suspicious-url-keyword': 'Suspicious keyword in URL',
  'excessive-hyphens': 'Many hyphens in domain',
  'brand-in-hostname': 'Brand name embedded in hostname',
  'insecure-scheme': 'Page served over HTTP',
  'url-shortener': 'URL-shortening service',
  'suspicious-port': 'Non-standard port',
  'userinfo-in-url': 'Username embedded before @ in URL',
  'brand-domain-mismatch': 'Brand-domain mismatch',
  'password-field': 'Password field on page',
  'sensitive-field': 'Requests other sensitive data',
  'external-form-action': 'Form submits to external domain',
  'insecure-form-action': 'Form submits over insecure HTTP',
  'hidden-sensitive-field': 'Hidden sensitive form field',
  'js-intercepted-form': 'JavaScript-intercepted form',
  'urgency-language': 'Urgency language',
  'account-threat-language': 'Account-threat language',
  'credential-request-language': 'Credential-request language',
  'financial-pressure-language': 'Financial-pressure language',
  'authority-language': 'Authority-impersonation language',
  'reward-language': 'Reward/prize language',
  'known-malicious-url': 'Known malicious URL',
  'known-malware-url': 'Known active malware URL',
};
