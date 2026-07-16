import { fileURLToPath } from 'node:url';
import { loadPhishTankFeed } from './parser.mjs';
import {
  createPhishTankProvider,
  unavailablePhishTankFinding,
} from './providers/phishtank.mjs';

export const DEFAULT_FEED_PATH = fileURLToPath(
  new URL('./data/phishtank-snapshot-2026-07-16.json.gz', import.meta.url),
);
export const SNAPSHOT_DATE = '2026-07-16';

let state = {
  available: false,
  index: null,
  provider: createPhishTankProvider(null),
  initializedAt: null,
  error: null,
};

export async function initializeThreatIntel(options = {}) {
  const feedPath = options.feedPath ?? DEFAULT_FEED_PATH;
  const initializedAt = Date.now();

  try {
    const index = await loadPhishTankFeed(feedPath);
    state = {
      available: true,
      index,
      provider: createPhishTankProvider(index),
      initializedAt,
      error: null,
    };
  } catch (error) {
    // A reload failure must not discard an index that is already serving lookups.
    if (!state.available) {
      state = {
        available: false,
        index: null,
        provider: createPhishTankProvider(null),
        initializedAt,
        error: String(error?.message ?? error),
      };
    } else {
      state = { ...state, error: String(error?.message ?? error) };
    }
  }

  return getThreatIntelService().health();
}

export function getThreatIntelService() {
  return {
    health() {
      return {
        available: state.available,
        provider: 'phishtank',
        records: state.index?.exactUrlCount ?? 0,
        hostnames: state.index?.hostnameCount ?? 0,
        snapshotDate: SNAPSHOT_DATE,
        initializedAt: state.initializedAt,
      };
    },

    lookup(rawUrl) {
      const checkedAt = Date.now();
      if (!state.available) {
        return {
          status: 'unavailable',
          checkedAt,
          findings: [unavailablePhishTankFinding()],
        };
      }

      try {
        return {
          status: 'complete',
          checkedAt,
          findings: [state.provider.lookup(rawUrl)],
        };
      } catch {
        return {
          status: 'unavailable',
          checkedAt,
          findings: [unavailablePhishTankFinding()],
        };
      }
    },
  };
}

export function resetThreatIntelForTests() {
  state = {
    available: false,
    index: null,
    provider: createPhishTankProvider(null),
    initializedAt: null,
    error: null,
  };
}
