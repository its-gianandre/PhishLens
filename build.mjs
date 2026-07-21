import { build } from 'esbuild';
import { cp, mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = dirname(fileURLToPath(import.meta.url));
const fromRoot = (...parts) => join(projectRoot, ...parts);
const outdir = fromRoot('dist');
await mkdir(outdir, { recursive: true });

await build({
  entryPoints: {
    'service-worker': fromRoot('extension', 'background', 'service-worker.ts'),
    content: fromRoot('extension', 'content', 'index.ts'),
    popup: fromRoot('extension', 'popup', 'popup.ts'),
  },
  bundle: true,
  format: 'iife',
  target: 'chrome120',
  outdir,
  sourcemap: false,
  logLevel: 'info',
});

await cp(fromRoot('extension', 'manifest.json'), join(outdir, 'manifest.json'));
await cp(fromRoot('extension', 'popup', 'popup.html'), join(outdir, 'popup.html'));
await cp(fromRoot('extension', 'popup', 'popup.css'), join(outdir, 'popup.css'));
await cp(fromRoot('extension', 'data'), join(outdir, 'data'), { recursive: true });

console.log('Built extension into ./dist — load it via chrome://extensions → "Load unpacked" → select the dist folder.');
