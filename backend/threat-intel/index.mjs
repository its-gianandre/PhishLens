import { fileURLToPath } from 'node:url';
import { readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { buildPhishTankIndex, loadPhishTankFeed } from './parser.mjs';
import {
  createPhishTankProvider,
  unavailablePhishTankFinding,
} from './providers/phishtank.mjs';
import { fetchUrlhausRecentCsv } from './urlhaus/download.mjs';
import { buildUrlhausIndex, loadUrlhausFeed } from './urlhaus/parser.mjs';
import {
  createUrlhausProvider,
  unavailableUrlhausFinding,
} from './urlhaus/provider.mjs';

export const DEFAULT_FEED_PATH = fileURLToPath(
  new URL('./data/phishtank-snapshot-2026-07-16.json.gz', import.meta.url),
);
export const DEFAULT_URLHAUS_CACHE_PATH = fileURLToPath(
  new URL('./data/urlhaus-recent.csv', import.meta.url),
);
const DEMO_PHISHTANK_PATH = new URL('./data/demo-phishtank.json', import.meta.url);
const DEMO_URLHAUS_PATH = fileURLToPath(
  new URL('./data/demo-urlhaus.csv', import.meta.url),
);
export const SNAPSHOT_DATE = '2026-07-16';

function mergeIndexes(base, overlay) {
  if (!base) return overlay;
  if (!overlay) return base;

  return {
    exactUrls: new Map([...base.exactUrls, ...overlay.exactUrls]),
    hostnames: new Map([...base.hostnames, ...overlay.hostnames]),
    rawRecordCount: base.rawRecordCount + overlay.rawRecordCount,
    acceptedRecordCount: base.acceptedRecordCount + overlay.acceptedRecordCount,
    exactUrlCount: new Set([...base.exactUrls.keys(), ...overlay.exactUrls.keys()]).size,
    hostnameCount: new Set([...base.hostnames.keys(), ...overlay.hostnames.keys()]).size,
  };
}

async function loadDemoIndexes() {
  const [phishtankJson, urlhausCsv] = await Promise.all([
    readFile(DEMO_PHISHTANK_PATH, 'utf8'),
    readFile(DEMO_URLHAUS_PATH, 'utf8'),
  ]);
  return {
    phishtank: buildPhishTankIndex(JSON.parse(phishtankJson)),
    urlhaus: buildUrlhausIndex(urlhausCsv),
  };
}

function emptyProviderState(provider) {
  return {
    available: false,
    index: null,
    provider,
    initializedAt: null,
    updatedAt: null,
    source: null,
    error: null,
  };
}

let state = {
  initializedAt: null,
  phishtank: emptyProviderState(createPhishTankProvider(null)),
  urlhaus: emptyProviderState(createUrlhausProvider(null)),
};

async function initializePhishTank(feedPath, initializedAt, records, demoIndex) {
  try {
    const baseIndex = records === undefined
      ? await loadPhishTankFeed(feedPath)
      : buildPhishTankIndex(records);
    const index = mergeIndexes(baseIndex, demoIndex);
    const baseSource = records === undefined ? 'bundled-snapshot' : 'configured-records';
    state.phishtank = {
      available: true,
      index,
      provider: createPhishTankProvider(index),
      initializedAt,
      updatedAt: initializedAt,
      source: demoIndex ? `${baseSource}+demo-fixtures` : baseSource,
      error: null,
    };
  } catch (error) {
    if (demoIndex) {
      state.phishtank = {
        available: true,
        index: demoIndex,
        provider: createPhishTankProvider(demoIndex),
        initializedAt,
        updatedAt: initializedAt,
        source: 'demo-fixtures-fallback',
        error: String(error?.message ?? error),
      };
      return;
    }
    if (!state.phishtank.available) {
      state.phishtank = {
        ...emptyProviderState(createPhishTankProvider(null)),
        initializedAt,
        error: String(error?.message ?? error),
      };
    } else {
      state.phishtank = { ...state.phishtank, error: String(error?.message ?? error) };
    }
  }
}

function validateUrlhausIndex(index) {
  if (!index || index.exactUrlCount < 1) {
    throw new Error('URLhaus feed contains no valid URL records');
  }
  return index;
}

async function writeUrlhausCache(cachePath, csv) {
  const temporaryPath = `${cachePath}.${process.pid}.${Date.now()}.tmp`;
  try {
    await writeFile(temporaryPath, csv, 'utf8');
    await rename(temporaryPath, cachePath);
  } finally {
    await unlink(temporaryPath).catch(() => undefined);
  }
}

async function loadUrlhausCache(cachePath) {
  return validateUrlhausIndex(await loadUrlhausFeed(cachePath));
}

async function initializeUrlhaus(options, initializedAt, demoIndex) {
  const cachePath = options.urlhausFeedPath ?? DEFAULT_URLHAUS_CACHE_PATH;
  const authKey = options.urlhausAuthKey ?? process.env.URLHAUS_AUTH_KEY;

  try {
    let index;
    let source;
    let warning = null;
    if (authKey) {
      try {
        const csv = await fetchUrlhausRecentCsv(authKey, options.fetchImpl);
        index = validateUrlhausIndex(buildUrlhausIndex(csv));
        source = 'authenticated-download';
        if (!options.urlhausFeedPath) {
          try {
            await writeUrlhausCache(cachePath, csv);
          } catch {
            warning = 'URLhaus feed loaded, but the local cache could not be updated';
          }
        }
      } catch (downloadError) {
        try {
          index = await loadUrlhausCache(cachePath);
          source = 'local-cache-fallback';
          warning = String(downloadError?.message ?? downloadError);
        } catch {
          throw new Error('URLhaus download failed and no valid local cache is available');
        }
      }
    } else {
      index = await loadUrlhausCache(cachePath);
      source = options.urlhausFeedPath ? 'configured-file' : 'local-cache';
    }

    index = mergeIndexes(index, demoIndex);
    state.urlhaus = {
      available: true,
      index,
      provider: createUrlhausProvider(index),
      initializedAt,
      updatedAt: initializedAt,
      source: demoIndex ? `${source}+demo-fixtures` : source,
      error: warning,
    };
  } catch (error) {
    if (demoIndex) {
      state.urlhaus = {
        available: true,
        index: demoIndex,
        provider: createUrlhausProvider(demoIndex),
        initializedAt,
        updatedAt: initializedAt,
        source: 'demo-fixtures-fallback',
        error: String(error?.message ?? error),
      };
      return;
    }
    if (!state.urlhaus.available) {
      state.urlhaus = {
        ...emptyProviderState(createUrlhausProvider(null)),
        initializedAt,
        error: authKey
          ? String(error?.message ?? error)
          : 'URLHAUS_AUTH_KEY is not configured and no local cache is available',
      };
    } else {
      state.urlhaus = { ...state.urlhaus, error: String(error?.message ?? error) };
    }
  }
}

export async function initializeThreatIntel(options = {}) {
  const initializedAt = Date.now();
  const demoIndexes = options.includeDemoFixtures ? await loadDemoIndexes() : null;
  state.initializedAt = initializedAt;
  await Promise.all([
    initializePhishTank(
      options.feedPath ?? DEFAULT_FEED_PATH,
      initializedAt,
      options.phishtankRecords,
      demoIndexes?.phishtank,
    ),
    initializeUrlhaus(options, initializedAt, demoIndexes?.urlhaus),
  ]);
  return getThreatIntelService().health();
}

function providerHealth(providerState, extra = {}) {
  return {
    available: providerState.available,
    records: providerState.index?.exactUrlCount ?? 0,
    hostnames: providerState.index?.hostnameCount ?? 0,
    initializedAt: providerState.initializedAt,
    updatedAt: providerState.updatedAt,
    source: providerState.source,
    error: providerState.error,
    ...extra,
  };
}

export function getThreatIntelService() {
  return {
    health() {
      const phishtank = providerHealth(state.phishtank, { snapshotDate: SNAPSHOT_DATE });
      const urlhaus = providerHealth(state.urlhaus);
      return {
        available: phishtank.available || urlhaus.available,
        records: phishtank.records + urlhaus.records,
        hostnames: phishtank.hostnames + urlhaus.hostnames,
        initializedAt: state.initializedAt,
        providers: { phishtank, urlhaus },
      };
    },

    lookup(rawUrl) {
      const checkedAt = Date.now();
      const findings = [];
      try {
        findings.push(state.phishtank.provider.lookup(rawUrl));
      } catch {
        findings.push(unavailablePhishTankFinding());
      }
      try {
        findings.push(state.urlhaus.provider.lookup(rawUrl));
      } catch {
        findings.push(unavailableUrlhausFinding());
      }
      return {
        status: findings.some((finding) => finding.available) ? 'complete' : 'unavailable',
        checkedAt,
        findings,
      };
    },
  };
}

export function resetThreatIntelForTests() {
  state = {
    initializedAt: null,
    phishtank: emptyProviderState(createPhishTankProvider(null)),
    urlhaus: emptyProviderState(createUrlhausProvider(null)),
  };
}
