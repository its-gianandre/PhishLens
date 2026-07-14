import type { Settings } from './types';

export const DEFAULT_SETTINGS: Settings = {
  technicalMode: false,
  aiExplanations: true,
  saveHistory: false,
  submissionWarnings: true,
  threatIntel: true,
  bannerThreshold: 60,
  guardThreshold: 45,
  approvedDomains: [],
};

export async function loadSettings(): Promise<Settings> {
  const { settings } = await chrome.storage.sync.get('settings');
  return { ...DEFAULT_SETTINGS, ...(settings ?? {}) };
}

export async function saveSettings(patch: Partial<Settings>): Promise<Settings> {
  const current = await loadSettings();
  const next = { ...current, ...patch };
  await chrome.storage.sync.set({ settings: next });
  return next;
}
