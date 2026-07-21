# PhishLens setup guide

## Prerequisites

Install:

- Node.js 20 or newer, including npm
- Google Chrome 120 or newer
- Git, if you are cloning the repository

Confirm Node.js and npm are available:

```text
node --version
npm --version
```

On Windows PowerShell, use `npm.cmd` instead of `npm` if script execution is
blocked. For example, run `npm.cmd ci`.

## Install and build

Open a terminal in the repository folder containing `package.json`, then run:

```text
npm ci
npm run typecheck
npm test
npm run build
```

The completed extension is written to `dist/`.

## Load the extension in Chrome

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Select **Load unpacked**.
4. Choose the repository's `dist` folder.
5. Pin PhishLens from Chrome's Extensions menu if desired.

After changing extension code:

1. Run `npm run build`.
2. Reload PhishLens on `chrome://extensions`.
3. Refresh the webpage being tested.

Chrome internal pages and the Chrome Web Store cannot be analyzed by the
extension. Use a regular `http://` or `https://` page.

## Run the test pages

Start the harmless local presentation pages:

```text
npm run test-pages
```

Keep that terminal open, then visit:

```text
http://localhost:8000/
```

The gallery includes:

- Original Low, Caution, High, and Critical detector examples
- Individual PhishTank, URLhaus, OpenPhish, and Block List Project examples
- A combined page where all four threat-intelligence providers display a match
- A proactive link-protection demonstration

Useful direct links:

| Scenario | URL |
| --- | --- |
| All four providers | `http://intel-showcase.localhost:8000/threat-intel-showcase.html` |
| PhishTank | `http://signin-portal.localhost:8000/verified-apple-id.html` |
| URLhaus | `http://software-update.localhost:8000/critical-browser-update.html` |
| OpenPhish | `http://localhost:8000/openphish-demo.html` |
| Block List Project | `http://blocklist-demo.localhost:8000/blocklist-demo.html` |
| Link protection | `http://social-feed.localhost:8000/link-protection.html` |

All test pages and presentation matches are safe local fixtures. Do not enter
real credentials when testing form warnings.

Detailed expected behavior is documented in
[`test-pages/EXPECTED.md`](test-pages/EXPECTED.md).

## Backend configuration — optional

Page analysis and scoring run locally in the extension. The backend provides
explanations and the normal PhishTank, URLhaus, and OpenPhish indexes. Block
List Project and Public Suffix List checks run inside the extension.

The configured backend address is `BACKEND_ORIGIN` in:

```text
extension/shared/constants.ts
```

To run the backend locally:

```text
npm run backend
```

It listens on `http://127.0.0.1:8787` by default. Check its status at:

```text
http://127.0.0.1:8787/health
```

To use the local backend from the extension:

1. Change `BACKEND_ORIGIN` to `http://127.0.0.1:8787`.
2. Run `npm run build`.
3. Reload the extension.
4. Refresh the test page.

The backend reads environment variables directly and does not automatically
load a `.env` file.

| Variable | Default | Purpose |
| --- | --- | --- |
| `HOST` | `127.0.0.1` | Backend listening address |
| `PORT` | `8787` | Backend port |
| `OLLAMA_URL` | Unset | Ollama base URL without `/api/generate` |
| `OLLAMA_MODEL` | `llama3.2:3b` | Ollama model name |
| `URLHAUS_AUTH_KEY` | Unset | Optional backend-only URLhaus key |

PowerShell example:

```powershell
$env:OLLAMA_URL = 'http://127.0.0.1:11434'
$env:OLLAMA_MODEL = 'llama3.2:3b'
npm run backend
```

Ollama is optional. If the backend can run but Ollama is unavailable, PhishLens
uses its deterministic template explanation. Never expose Ollama directly to
the public internet; use a private connection between Ollama and the backend.

## Threat-intelligence datasets

- **Block List Project** is bundled and checked locally. It requires no API key
  or AWS access.
- **Public Suffix List** is bundled through `tldts` and supports correct domain
  parsing. It is not itself a threat feed.
- **PhishTank** uses the committed snapshot under `backend/threat-intel/data/`.
- **OpenPhish** requires no API key and is refreshed by the backend.
- **URLhaus** requires an Auth-Key only when refreshing its backend feed.

Refresh the local Block List Project snapshot deliberately with:

```text
npm run datasets:update
npm test
npm run build
```

Verify the committed PhishTank snapshot with:

```text
npm run threat-intel:test-feed
```

Never place provider keys in extension code, popup settings, test pages, or
committed files.

## Common commands

| Command | Purpose |
| --- | --- |
| `npm ci` | Install the locked dependency versions |
| `npm run typecheck` | Check TypeScript |
| `npm test` | Run the complete test suite |
| `npm run test:watch` | Run tests continuously while editing |
| `npm run build` | Build the extension into `dist/` |
| `npm run test-pages` | Serve test pages on port 8000 |
| `npm run backend` | Start the optional backend on port 8787 |
| `npm run datasets:update` | Refresh the Block List Project snapshot |
| `npm run threat-intel:test-feed` | Verify the PhishTank snapshot |

## Troubleshooting

### A recent change does not appear

Run the build, reload the extension on `chrome://extensions`, and refresh the
webpage—in that order.

### The popup says no analysis is available

Confirm the page uses HTTP or HTTPS, reload the extension, and refresh the page.

### Threat intelligence shows no provider cards

- Confirm **Known-threat lookup** is enabled in Settings.
- Wait briefly for the asynchronous lookup.
- Check the backend `/health` page for server-side providers.
- Providers without a match are intentionally hidden.
- Rebuild after changing Block List Project data.

### Explanations do not appear

Confirm the configured backend is reachable. For Ollama-polished summaries,
also confirm `OLLAMA_URL` is configured and the selected model exists.

### A `.localhost` page does not open

Confirm `npm run test-pages` is still running and that a proxy or DNS override
is not intercepting `.localhost`. The main gallery should remain available at
`http://localhost:8000/`.

## Safety notes

- Use only fake values on test pages.
- Do not commit API keys, `.env` files, or downloaded feed caches.
- Use HTTPS for the backend outside local demonstrations.
- A Low score or a threat-feed no-match does not guarantee that a page is safe.

See [`README.md`](README.md) for architecture, privacy details, and known
limitations.
