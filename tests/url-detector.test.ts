import { describe, expect, it } from 'vitest';
import { detectUrlSignals } from '../extension/detectors/url-detector';
import type { SignalId } from '../extension/shared/types';

function ids(url: string): SignalId[] {
  return detectUrlSignals(url).map((s) => s.id);
}

describe('detectUrlSignals', () => {
  it('flags IP-address hosts', () => {
    expect(ids('http://192.168.10.5/login')).toContain('ip-address-host');
  });

  it('flags punycode hosts', () => {
    expect(ids('https://xn--pypal-4ve.com/')).toContain('punycode-host');
  });

  it('flags excessive subdomains', () => {
    expect(ids('https://a.b.c.d.example.com/')).toContain('excessive-subdomains');
  });

  it('flags suspicious keywords, long URLs, and hyphens', () => {
    const url = 'https://secure-account-verify-update.com/login?next=' + 'x'.repeat(80);
    const found = ids(url);
    expect(found).toContain('suspicious-url-keyword');
    expect(found).toContain('long-url');
    expect(found).toContain('excessive-hyphens');
  });

  it('flags HTTP, shorteners, ports, and userinfo tricks', () => {
    expect(ids('http://example.com/')).toContain('insecure-scheme');
    expect(ids('https://bit.ly/abc')).toContain('url-shortener');
    expect(ids('https://example.com:8443/')).toContain('suspicious-port');
    expect(ids('https://paypal.com%40evil.com@evil.com/')).toContain('userinfo-in-url');
  });

  it('flags a brand embedded in a non-official hostname', () => {
    expect(ids('https://paypal-secure.com/')).toContain('brand-in-hostname');
    expect(ids('https://microsoft.evil-domain.net/')).toContain('brand-in-hostname');
  });

  it('does not flag official brand domains', () => {
    expect(ids('https://accounts.google.com/signin')).not.toContain('brand-in-hostname');
    expect(ids('https://login.microsoftonline.com/')).not.toContain('brand-in-hostname');
  });

  it('exempts loopback hosts from scheme and port signals', () => {
    const found = ids('http://localhost:8000/normal-login.html');
    expect(found).not.toContain('insecure-scheme');
    expect(found).not.toContain('suspicious-port');
  });

  it('returns nothing for unparseable or non-http URLs', () => {
    expect(ids('not a url')).toEqual([]);
    expect(ids('chrome://extensions')).toEqual([]);
  });
});
