import { JSDOM } from 'jsdom';
import { describe, expect, it } from 'vitest';
import { collectExternalLinks } from '../extension/content/link-protection';

describe('external link collection', () => {
  it('scans visible external links, skips internal/hidden links, and deduplicates trackers', () => {
    const dom = new JSDOM(`<!doctype html><body>
      <article>Claim your free giveaway now
        <a href="https://bit.ly/prize?utm_source=one">first</a>
        <a href="https://bit.ly/prize?utm_source=two">repeated</a>
      </article>
      <a href="/account">internal</a>
      <a href="https://hidden.example/" hidden>hidden</a>
      <a href="mailto:help@example.com">mail</a>
    </body>`, { url: 'https://social.example/feed' });

    const links = collectExternalLinks(
      dom.window.document as unknown as Document,
      dom.window.location.href,
    );
    expect(links).toHaveLength(1);
    expect(links[0].anchors).toHaveLength(2);
    expect(links[0].candidate.lookupUrl).toBe('https://bit.ly/prize');
    expect(links[0].candidate.urlSignalIds).toContain('url-shortener');
    expect(links[0].candidate.contextSignalIds).toContain('reward-language');
  });

  it('never includes raw query secrets in the candidate sent for analysis', () => {
    const dom = new JSDOM(
      '<a href="https://outside.example/open?access_token=top-secret&item=2">open</a>',
      { url: 'https://inside.example/' },
    );
    const [link] = collectExternalLinks(
      dom.window.document as unknown as Document,
      dom.window.location.href,
    );
    expect(link.candidate.lookupUrl).toBe(
      'https://outside.example/open?access_token=REDACTED&item=2',
    );
    expect(JSON.stringify(link.candidate)).not.toContain('top-secret');
  });
});
