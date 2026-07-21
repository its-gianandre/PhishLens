import { describe, expect, it } from 'vitest';
import { readFile } from 'node:fs/promises';
import {
  lookupBlockListProject,
  parseBlockListProjectSnapshot,
} from '../extension/threat-intel/blocklist-project';

describe('local Block List Project provider', () => {
  it('ships a populated, parseable snapshot with provenance metadata', async () => {
    const text = await readFile(
      new URL('../extension/data/blocklist-project-phishing.txt', import.meta.url),
      'utf8',
    );
    expect(text).toMatch(/^# Source: https:\/\/raw\.githubusercontent\.com/m);
    expect(text).toMatch(/^# Upstream-SHA256: [a-f0-9]{64}$/m);
    expect(parseBlockListProjectSnapshot(text).size).toBeGreaterThan(100_000);
  });

  it('parses normalized domains and skips malformed records', () => {
    const domains = parseBlockListProjectSnapshot([
      '# safe synthetic fixture',
      'PHISH.EXAMPLE.COM',
      'bad value',
      '192.0.2.1',
      'phish.example.com.',
    ].join('\n'));
    expect([...domains]).toEqual(['phish.example.com']);
  });

  it('reports exact-hostname and parent-domain phishing matches', () => {
    const domains = new Set(['phish.example.com', 'listed.example.net']);
    expect(lookupBlockListProject('https://phish.example.com/login', domains)).toMatchObject({
      provider: 'blocklist-project',
      available: true,
      matched: true,
      category: 'phishing',
      matchType: 'hostname',
      confidence: 'high',
    });
    expect(lookupBlockListProject('https://sub.listed.example.net/login', domains)).toMatchObject({
      matched: true,
      matchType: 'registrable-domain',
      confidence: 'medium',
    });
  });

  it('returns an available non-match for unrelated and malformed URLs', () => {
    const domains = new Set(['phish.example.com']);
    expect(lookupBlockListProject('https://clean.example/', domains)).toMatchObject({
      available: true,
      matched: false,
    });
    expect(lookupBlockListProject('not a URL', domains)).toMatchObject({
      available: true,
      matched: false,
    });
  });
});
