export type WorldAppRuntimeMode = "miniapp" | "web";

function readRawWorldApp(): Record<string, unknown> | null {
  if (typeof window === "undefined") {
    return null;
  }
  const maybe = (window as Window & { WorldApp?: unknown }).WorldApp;
  if (!maybe || typeof maybe !== "object" || Array.isArray(maybe)) {
    return null;
  }
  return maybe as Record<string, unknown>;
}

export function getWorldAppRuntimeMode(): WorldAppRuntimeMode {
  return readRawWorldApp() ? "miniapp" : "web";
}

export function isWorldAppMiniRuntime(): boolean {
  return getWorldAppRuntimeMode() === "miniapp";
}

function isTruthy(value: string | null | undefined): boolean {
  if (!value) {
    return false;
  }
  const normalized = value.trim().toLowerCase();
  return normalized === "1" || normalized === "true" || normalized === "yes" || normalized === "on";
}

export function isWorldIdSimulatorContext(): boolean {
  if (typeof window === "undefined") {
    return false;
  }

  const search = new URLSearchParams(window.location.search);
  if (
    isTruthy(search.get("worldid_simulator")) ||
    isTruthy(search.get("world_id_simulator")) ||
    isTruthy(search.get("simulator"))
  ) {
    return true;
  }

  const referrer = document.referrer?.trim() ?? "";
  if (!referrer) {
    return false;
  }

  try {
    const url = new URL(referrer);
    return /(^|\.)simulator\.worldcoin\.org$/i.test(url.hostname);
  } catch {
    return referrer.includes("simulator.worldcoin.org");
  }
}
