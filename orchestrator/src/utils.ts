import { createHash, randomBytes } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const THIS_FILE = fileURLToPath(import.meta.url);
const THIS_DIR = path.dirname(THIS_FILE);
const ROOT_DIR = path.resolve(THIS_DIR, "..");

export function getProjectRoot(): string {
  return ROOT_DIR;
}

export function resolveProjectPath(...parts: string[]): string {
  return path.join(ROOT_DIR, ...parts);
}

export async function ensureDir(dirPath: string): Promise<void> {
  await mkdir(dirPath, { recursive: true });
}

export function nowIso(): string {
  return new Date().toISOString();
}

export function normalizeHex(input: string): string {
  return input.startsWith("0x") ? input.toLowerCase() : `0x${input.toLowerCase()}`;
}

export function sha256Hex(input: string): string {
  return `0x${createHash("sha256").update(input).digest("hex")}`;
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }

  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, val]) => [key, canonicalize(val)]);
    return Object.fromEntries(entries);
  }

  return value;
}

export function stableStringify(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

export function hashObject(value: unknown): string {
  return sha256Hex(stableStringify(value));
}

export function generateRequestId(): string {
  const entropy = `${Date.now()}:${randomBytes(16).toString("hex")}`;
  return sha256Hex(entropy);
}

export function clampNumber(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

export async function readJsonFile<T>(filePath: string, fallback: T): Promise<T> {
  try {
    const content = await readFile(filePath, "utf8");
    return JSON.parse(content) as T;
  } catch (error) {
    const asNodeError = error as NodeJS.ErrnoException;
    if (asNodeError.code === "ENOENT") {
      return fallback;
    }
    throw error;
  }
}

export async function writeJsonFileAtomic(filePath: string, value: unknown): Promise<void> {
  const dirPath = path.dirname(filePath);
  await ensureDir(dirPath);

  const tempPath = `${filePath}.tmp`;
  const payload = `${JSON.stringify(value, null, 2)}\n`;

  await writeFile(tempPath, payload, "utf8");
  await rename(tempPath, filePath);
}
