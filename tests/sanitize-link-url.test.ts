import { describe, expect, it } from 'vitest';
import { sanitizeLinkUrl } from '../extension/shared/sanitize-link-url';

describe('link lookup URL sanitization', () => {
  it('removes userinfo, fragments, trackers, and sensitive query values', () => {
    const sanitized = sanitizeLinkUrl(
      'https://user:password@example.com/prize?utm_source=feed&email=person%40example.com&campaign=summer#details',
    );
    expect(sanitized).toBe('https://example.com/prize?email=REDACTED&campaign=summer');
  });

  it('redacts high-entropy values even when the parameter name is generic', () => {
    const sanitized = sanitizeLinkUrl(
      `https://example.com/open?id=${'aB3_'.repeat(16)}&item=42`,
    );
    expect(sanitized).toBe('https://example.com/open?id=REDACTED&item=42');
  });

  it('rejects non-web and malformed destinations', () => {
    expect(sanitizeLinkUrl('javascript:alert(1)')).toBeNull();
    expect(sanitizeLinkUrl('not a url')).toBeNull();
  });
});
