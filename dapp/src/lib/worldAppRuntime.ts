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

