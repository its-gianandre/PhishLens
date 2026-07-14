import { MULTI_PART_TLDS } from './constants';

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

/**
 * Simplified eTLD+1 extraction using a small multi-part-TLD list.
 * Good enough for the MVP; swap for the public-suffix list later if needed.
 */
export function getRegistrableDomain(hostname: string): string {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (!host || isIpAddress(host)) return host;
  const labels = host.split('.');
  if (labels.length <= 2) return host;
  const lastTwo = labels.slice(-2).join('.');
  const take = MULTI_PART_TLDS.has(lastTwo) ? 3 : 2;
  return labels.slice(-take).join('.');
}

/** Number of subdomain labels in front of the registrable domain. */
export function subdomainDepth(hostname: string): number {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (isIpAddress(host)) return 0;
  const registrable = getRegistrableDomain(host);
  return Math.max(0, host.split('.').length - registrable.split('.').length);
}
