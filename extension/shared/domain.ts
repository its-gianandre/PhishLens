import { getDomain } from 'tldts';

export function isIpAddress(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, '');
  if (host.includes(':') && /^[0-9a-f:]+$/i.test(host)) return true; // IPv6
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}

export function isLoopback(hostname: string): boolean {
  const host = hostname.toLowerCase();
  return (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host === '::1' ||
    host === '[::1]' ||
    /^127\./.test(host)
  );
}

/** Resolve eTLD+1 with the full Public Suffix List, including private suffixes. */
export function getRegistrableDomain(hostname: string): string {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (!host || isIpAddress(host)) return host;
  return getDomain(host, { allowPrivateDomains: true }) ?? host;
}

/** Number of subdomain labels in front of the registrable domain. */
export function subdomainDepth(hostname: string): number {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (isIpAddress(host)) return 0;
  const registrable = getRegistrableDomain(host);
  return Math.max(0, host.split('.').length - registrable.split('.').length);
}
