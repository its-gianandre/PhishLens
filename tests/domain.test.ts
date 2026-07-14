import { describe, expect, it } from 'vitest';
import { getRegistrableDomain, isIpAddress, isLoopback, subdomainDepth } from '../extension/shared/domain';

describe('getRegistrableDomain', () => {
  it('extracts eTLD+1 for ordinary domains', () => {
    expect(getRegistrableDomain('www.example.com')).toBe('example.com');
    expect(getRegistrableDomain('a.b.c.example.com')).toBe('example.com');
    expect(getRegistrableDomain('example.com')).toBe('example.com');
  });

  it('handles multi-part public suffixes', () => {
    expect(getRegistrableDomain('www.bbc.co.uk')).toBe('bbc.co.uk');
    expect(getRegistrableDomain('shop.amazon.com.au')).toBe('amazon.com.au');
  });

  it('passes through bare hosts and IPs', () => {
    expect(getRegistrableDomain('localhost')).toBe('localhost');
    expect(getRegistrableDomain('192.168.1.10')).toBe('192.168.1.10');
  });

  it('keeps punycode labels intact', () => {
    expect(getRegistrableDomain('login.xn--pypal-4ve.com')).toBe('xn--pypal-4ve.com');
  });
});

describe('isIpAddress', () => {
  it('detects IPv4 and IPv6', () => {
    expect(isIpAddress('10.0.0.1')).toBe(true);
    expect(isIpAddress('[2001:db8::1]')).toBe(true);
    expect(isIpAddress('example.com')).toBe(false);
  });
});

describe('isLoopback', () => {
  it('covers localhost variants', () => {
    expect(isLoopback('localhost')).toBe(true);
    expect(isLoopback('127.0.0.1')).toBe(true);
    expect(isLoopback('app.localhost')).toBe(true);
    expect(isLoopback('example.com')).toBe(false);
  });
});

describe('subdomainDepth', () => {
  it('counts labels before the registrable domain', () => {
    expect(subdomainDepth('example.com')).toBe(0);
    expect(subdomainDepth('a.b.c.example.com')).toBe(3);
  });
});
