import type { WorldIdSession } from "./api";

const legacyWorldIdAppId = (import.meta.env.VITE_WORLD_ID_APP_ID || "").trim();
const legacyWorldIdAction = (import.meta.env.VITE_WORLD_ID_ACTION || "").trim();
const miniWorldIdAppId = (import.meta.env.VITE_WORLD_ID_MINI_APP_ID || legacyWorldIdAppId).trim();
const miniWorldIdAction = (import.meta.env.VITE_WORLD_ID_MINI_ACTION || legacyWorldIdAction).trim();
const externalWorldIdAppId = (import.meta.env.VITE_WORLD_ID_EXTERNAL_APP_ID || legacyWorldIdAppId).trim();
const externalWorldIdAction = (import.meta.env.VITE_WORLD_ID_EXTERNAL_ACTION || legacyWorldIdAction).trim();

export interface WorldIdClientConfig {
  appId: string;
  action: string;
  configured: boolean;
}

export interface WorldIdConfig {
  mini: WorldIdClientConfig;
  external: WorldIdClientConfig;
}

function buildClientConfig(appId: string, action: string): WorldIdClientConfig {
  return {
    appId,
    action,
    configured: appId.length > 0 && action.length > 0
  };
}

const worldIdConfig: WorldIdConfig = {
  mini: buildClientConfig(miniWorldIdAppId, miniWorldIdAction),
  external: buildClientConfig(externalWorldIdAppId, externalWorldIdAction)
};

function buildSessionStorageKey(walletAddress: string): string {
  return `cre:world-id:session:${walletAddress.trim().toLowerCase()}`;
}

export function isWorldIdConfigured(): boolean {
  return worldIdConfig.mini.configured || worldIdConfig.external.configured;
}

export function getWorldIdConfig(): WorldIdConfig {
  return worldIdConfig;
}

export function saveWorldIdSession(walletAddress: string, session: WorldIdSession): void {
  if (!walletAddress || !session?.token) {
    return;
  }
  window.localStorage.setItem(buildSessionStorageKey(walletAddress), JSON.stringify(session));
}

export function clearWorldIdSession(walletAddress: string): void {
  if (!walletAddress) {
    return;
  }
  window.localStorage.removeItem(buildSessionStorageKey(walletAddress));
}

export function loadWorldIdSession(walletAddress: string): WorldIdSession | null {
  if (!walletAddress) {
    return null;
  }
  const raw = window.localStorage.getItem(buildSessionStorageKey(walletAddress));
  if (!raw) {
    return null;
  }
  try {
    const parsed = JSON.parse(raw) as WorldIdSession;
    if (!parsed.token || !parsed.expiresAt) {
      clearWorldIdSession(walletAddress);
      return null;
    }
    const expiresAt = Date.parse(parsed.expiresAt);
    if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
      clearWorldIdSession(walletAddress);
      return null;
    }
    return parsed;
  } catch {
    clearWorldIdSession(walletAddress);
    return null;
  }
}
