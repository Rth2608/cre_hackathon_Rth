import type { StoredRequest } from "./types";
import { ensureDir, nowIso, readJsonFile, resolveProjectPath, writeJsonFileAtomic } from "./utils";

const REQUESTS_DB_PATH = resolveProjectPath("data", "requests.json");

interface RequestDbSchema {
  requests: Record<string, StoredRequest>;
}

async function loadDb(): Promise<RequestDbSchema> {
  await ensureDir(resolveProjectPath("data"));
  return readJsonFile<RequestDbSchema>(REQUESTS_DB_PATH, { requests: {} });
}

async function saveDb(db: RequestDbSchema): Promise<void> {
  await writeJsonFileAtomic(REQUESTS_DB_PATH, db);
}

export async function saveRequest(record: StoredRequest): Promise<void> {
  const db = await loadDb();
  db.requests[record.requestId] = {
    ...record,
    updatedAt: nowIso()
  };
  await saveDb(db);
}

export async function getRequest(requestId: string): Promise<StoredRequest | null> {
  const db = await loadDb();
  return db.requests[requestId] ?? null;
}

export async function listRequests(): Promise<StoredRequest[]> {
  const db = await loadDb();
  return Object.values(db.requests).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}
