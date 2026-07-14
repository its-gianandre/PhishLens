import { build } from 'esbuild';
import { cp, mkdir } from 'node:fs/promises';

const outdir = 'dist';
await mkdir(outdir, { recursive: true });

await build({
  entryPoints: {
    'service-worker': 'extension/background/service-worker.ts',
    content: 'extension/content/index.ts',
    popup: 'extension/popup/popup.ts',
  },
  bundle: true,
  format: 'iife',
  target: 'chrome120',
  outdir,
  sourcemap: false,
  logLevel: 'info',
});

await cp('extension/manifest.json', `${outdir}/manifest.json`);
await cp('extension/popup/popup.html', `${outdir}/popup.html`);
await cp('extension/popup/popup.css', `${outdir}/popup.css`);

console.log('Built extension into ./dist — load it via chrome://extensions → "Load unpacked" → select the dist folder.');
