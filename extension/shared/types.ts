// Shared schemas for evidence, signals, and analysis output.
// Detectors produce Signal[]; only scoring/calculate-risk.ts turns signals into a score.

export type DetectorName = 'url' | 'brand' | 'form' | 'language' | 'threat-intel';

export type SignalId =
  // URL detector
  | 'ip-address-host'
  | 'punycode-host'
  | 'excessive-subdomains'
  | 'long-url'
  | 'suspicious-url-keyword'
  | 'excessive-hyphens'
  | 'brand-in-hostname'
  | 'insecure-scheme'
  | 'url-shortener'
  | 'suspicious-port'
  | 'userinfo-in-url'
  // Brand detector
  | 'brand-domain-mismatch'
  // Form detector
  | 'password-field'
  | 'sensitive-field'
  | 'external-form-action'
  | 'insecure-form-action'
  | 'hidden-sensitive-field'
  | 'js-intercepted-form'
  // Language detector
  | 'urgency-language'
  | 'account-threat-language'
  | 'credential-request-language'
  | 'financial-pressure-language'
  | 'authority-language'
  | 'reward-language'
  // Threat intel
  | 'known-malicious-url';

export type Severity = 'low' | 'medium' | 'high';

export interface Signal {
  id: SignalId;
  detector: DetectorName;
  severity: Severity;
  /** Human-readable statement of what was found. */
  description: string;
  /** The concrete matched value or snippet backing the signal (truncated). */
  evidence: string;
}

export interface FormEvidence {
  /** Resolved absolute submission URL ('' when unresolvable). */
  action: string;
  method: string;
  hasPassword: boolean;
  /** Sensitive field labels present as visible fields (e.g. 'password', 'mfa-code'). */
  sensitiveFields: string[];
  /** Sensitive field labels present as type="hidden" inputs. */
  hiddenSensitiveFields: string[];
  pageDomain: string;
  actionDomain: string;
  crossDomain: boolean;
  secureSubmission: boolean;
  jsIntercepted: boolean;
}

/**
 * Everything the content script collects. Deliberately excludes entered
 * values, cookies, auth tokens, and full page HTML.
 */
export interface PageEvidence {
  url: string;
  title: string;
  visibleText: string;
  headings: string[];
  imageAltText: string[];
  metaDescription: string;
  faviconUrl: string;
  passwordFieldCount: number;
  emailFieldCount: number;
  forms: FormEvidence[];
}

export type RiskClass = 'Low' | 'Caution' | 'High' | 'Critical';

export interface BrandMatch {
  brand: string;
  /** 0..1 — how strongly the page claims to be this brand. */
  confidence: number;
  officialDomains: string[];
}

export interface ScoreLine {
  label: string;
  points: number;
}

export type ThreatIntelProvider = 'phishtank';
export type ThreatMatchType = 'exact-url' | 'hostname' | 'registrable-domain';

export interface ThreatIntelFinding {
  provider: ThreatIntelProvider;
  available: boolean;
  matched: boolean;
  category: 'phishing' | null;
  matchType: ThreatMatchType | null;
  confidence: 'high' | 'medium' | 'low' | null;
  targetBrand: string | null;
  referenceUrl: string | null;
  verificationTime: string | null;
  submissionTime: string | null;
}

export interface ThreatIntelSummary {
  status: 'disabled' | 'pending' | 'complete' | 'unavailable';
  checkedAt: number | null;
  findings: ThreatIntelFinding[];
}

export interface AnalysisResult {
  /** Unique generation token used to discard late asynchronous enrichments. */
  analysisId: string;
  url: string;
  /** Registrable domain of the page (eTLD+1). */
  domain: string;
  score: number;
  classification: RiskClass;
  suspectedBrand: string | null;
  brandConfidence: number | null;
  signals: Signal[];
  scoreBreakdown: ScoreLine[];
  recommendedAction: string;
  /** True when an approved-domain override suppressed analysis. */
  overridden: boolean;
  threatIntel: ThreatIntelSummary;
  analyzedAt: number;
}

export interface BrandEntry {
  name: string;
  /** Text keywords that indicate the page claims this brand. */
  keywords: string[];
  /** Official registrable domains for the brand. */
  domains: string[];
  /** Tokens checked inside hostnames (defaults derived from name). */
  hostTokens?: string[];
}

export interface Settings {
  technicalMode: boolean;
  explanations: boolean;
  saveHistory: boolean;
  submissionWarnings: boolean;
  threatIntel: boolean;
  /** Show in-page banner at or above this score. */
  bannerThreshold: number;
  /** Intercept sensitive submissions at or above this score. */
  guardThreshold: number;
  approvedDomains: string[];
}

export interface HistoryEntry {
  url: string;
  domain: string;
  score: number;
  classification: RiskClass;
  analyzedAt: number;
}

// ---- Messaging ----

export interface AnalyzeMessage { type: 'ANALYZE'; evidence: PageEvidence; }
export interface GetResultMessage { type: 'GET_RESULT'; tabId: number; }
export interface ClearDataMessage { type: 'CLEAR_DATA'; }
export interface GetHistoryMessage { type: 'GET_HISTORY'; }
export interface ResultUpdatedMessage {
  type: 'RESULT_UPDATED';
  tabId: number;
  result: AnalysisResult;
}
export type ExtensionMessage =
  | AnalyzeMessage
  | GetResultMessage
  | ClearDataMessage
  | GetHistoryMessage
  | ResultUpdatedMessage;

export interface ContentConfig {
  bannerThreshold: number;
  guardThreshold: number;
  submissionWarnings: boolean;
}

export interface AnalyzeResponse { result: AnalysisResult; config: ContentConfig; }

// ---- Local explanation backend contract ----

export interface ExplainRequest {
  score: number;
  classification: RiskClass;
  domain: string;
  suspectedBrand: string | null;
  signals: Array<Pick<Signal, 'id' | 'description' | 'evidence'>>;
  scoreBreakdown: ScoreLine[];
}

export interface ExplainCitation {
  signalId: SignalId;
  description: string;
  evidence: string;
}

export interface ExplainResponse {
  summary: string;
  reasons: string[];
  recommendedAction: string;
  technicalExplanation: string;
  limitations: string[];
  /** Detector-owned evidence copied directly from the validated findings. */
  citations: ExplainCitation[];
}
