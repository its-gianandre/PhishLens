import { fileURLToPath } from 'node:url';
import { rename, unlink, writeFile } from 'node:fs/promises';
import { loadPhishTankFeed } from './parser.mjs';
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
export const SNAPSHOT_DATE = '2026-07-16';

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

async function initializePhishTank(feedPath, initializedAt) {
  try {
    const index = await loadPhishTankFeed(feedPath);
    state.phishtank = {
      available: true,
      index,
      provider: createPhishTankProvider(index),
      initializedAt,
      updatedAt: initializedAt,
      source: 'bundled-snapshot',
      error: null,
    };
  } catch (error) {
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

async function initializeUrlhaus(options, initializedAt) {
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

    state.urlhaus = {
      available: true,
      index,
      provider: createUrlhausProvider(index),
      initializedAt,
      updatedAt: initializedAt,
      source,
      error: warning,
    };
  } catch (error) {
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
  state.initializedAt = initializedAt;
  await Promise.all([
    initializePhishTank(options.feedPath ?? DEFAULT_FEED_PATH, initializedAt),
    initializeUrlhaus(options, initializedAt),
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
