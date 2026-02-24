import type { WorldIdSession } from "./api";

const worldIdAppId = (import.meta.env.VITE_WORLD_ID_APP_ID || "").trim();
const worldIdAction = (import.meta.env.VITE_WORLD_ID_ACTION || "").trim();

function buildSessionStorageKey(walletAddress: string): string {
  return `cre:world-id:session:${walletAddress.trim().toLowerCase()}`;
}

export function isWorldIdConfigured(): boolean {
  return worldIdAppId.length > 0 && worldIdAction.length > 0;
}

export function getWorldIdConfig(): { appId: string; action: string } {
  return {
    appId: worldIdAppId,
    action: worldIdAction
  };
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
