import { describe, expect, it } from 'vitest';
import { detectBrand } from '../extension/detectors/brand-detector';
import { makeEvidence } from './helpers';

describe('detectBrand', () => {
  it('detects a claimed brand and flags the domain mismatch', () => {
    const result = detectBrand(makeEvidence({
      url: 'https://login-verify.example.net/',
      title: 'Sign in to your Microsoft account',
      headings: ['Microsoft', 'Sign in'],
      visibleText: 'Use your Microsoft account to continue to Outlook.',
    }));
    expect(result.match?.brand).toBe('Microsoft');
    expect(result.signals.map((s) => s.id)).toContain('brand-domain-mismatch');
  });

  it('does not flag the brand on its official domain', () => {
    const result = detectBrand(makeEvidence({
      url: 'https://login.microsoftonline.com/',
      title: 'Sign in to your Microsoft account',
      headings: ['Microsoft'],
      visibleText: 'Use your Microsoft account.',
    }));
    expect(result.match?.brand).toBe('Microsoft');
    expect(result.signals).toHaveLength(0);
  });

  it('needs enough confidence before flagging a mismatch', () => {
    const result = detectBrand(makeEvidence({
      url: 'https://blog.example.com/',
      visibleText: 'I wrote about microsoft once in this post.',
    }));
    expect(result.signals).toHaveLength(0);
  });

  it('picks the strongest brand when several appear', () => {
    const result = detectBrand(makeEvidence({
      url: 'https://evil.example.com/',
      title: 'PayPal — confirm your account',
      headings: ['PayPal security check'],
      visibleText: 'Sign in with PayPal. You can also use your Google account.',
    }));
    expect(result.match?.brand).toBe('PayPal');
  });

  it('reads brand claims from image alt text', () => {
    const result = detectBrand(makeEvidence({
      url: 'https://evil.example.com/',
      title: 'Account verification',
      imageAltText: ['PayPal logo', 'PayPal secure checkout'],
      visibleText: 'Please verify below.',
    }));
    expect(result.match?.brand).toBe('PayPal');
  });
});
