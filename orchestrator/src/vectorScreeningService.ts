import { createHash } from "node:crypto";
import path from "node:path";
import { nowIso, readJsonFile, resolveProjectPath, writeJsonFileAtomic } from "./utils";
import type { MarketRequestInput, RequestStatus, StoredRequest } from "./types";

type VectorStatus = NonNullable<StoredRequest["vectorSync"]>["vectorStatus"];
type VectorStoreBackend = "file" | "qdrant";

interface VectorIndexRecord {
  requestId: string;
  vectorStatus: VectorStatus;
  canonicalText: string;
  textHash: string;
  embedding: number[];
  createdAt: string;
  updatedAt: string;
}

interface VectorIndexStore {
  version: 1;
  updatedAt: string;
  records: Record<string, VectorIndexRecord>;
}

interface ExistingScreeningRecord {
  requestId: string;
  status?: RequestStatus;
  question?: string;
  description?: string;
  sourceUrls?: string[];
  resolutionCriteria?: string;
  submitterAddress?: string;
}

interface SearchMatch {
  requestId: string;
  similarity: number;
}

interface SearchResult {
  comparedCount: number;
  bestMatch: SearchMatch | null;
}

interface OpenAiEmbeddingApiResponse {
  data?: Array<{
    embedding?: number[];
  }>;
}

interface QdrantPoint {
  id?: unknown;
  score?: number;
  payload?: Record<string, unknown>;
}

interface QdrantCountResponse {
  result?: {
    count?: number;
  };
}

const KNOWN_VECTOR_STATUSES: VectorStatus[] = [
  "QUEUED",
  "VERIFYING",
  "APPROVED_PENDING_OPEN",
  "OPEN",
  "CLOSED",
  "REJECTED"
];
const DEFAULT_COMPARE_VECTOR_STATUSES: VectorStatus[] = ["QUEUED", "VERIFYING", "APPROVED_PENDING_OPEN", "OPEN"];
const ACTIVE_UPSERT_STATUSES = new Set<VectorStatus>(["QUEUED", "VERIFYING", "APPROVED_PENDING_OPEN", "OPEN"]);

let vectorStore: VectorIndexStore = {
  version: 1,
  updatedAt: nowIso(),
  records: {}
};
let qdrantCollectionReady = false;

const embeddingCache = new Map<string, number[]>();

function parseBooleanEnv(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (["1", "true", "yes", "y", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "n", "off"].includes(normalized)) return false;
  return fallback;
}

function resolvePort(): number {
  const raw = process.env.VECTOR_SCREENING_PORT?.trim();
  if (!raw) return 9888;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65_535) return 9888;
  return parsed;
}

function resolveAuthToken(): string | null {
  const token = process.env.VECTOR_SCREENING_AUTH_TOKEN?.trim();
  return token ? token : null;
}

function resolveStoreBackend(): VectorStoreBackend {
  const raw = process.env.VECTOR_SCREENING_STORE_BACKEND?.trim().toLowerCase();
  if (raw === "qdrant") return "qdrant";
  if (raw === "file") return "file";
  return "file";
}

function resolveStorePath(): string {
  const raw = process.env.VECTOR_SCREENING_STORE_PATH?.trim();
  if (!raw) return resolveProjectPath("data", "vector-screening-index.json");
  return path.isAbsolute(raw) ? raw : resolveProjectPath(raw);
}

function resolveEmbeddingMode(): "openai" | "hash" {
  const raw = process.env.VECTOR_SCREENING_EMBEDDING_MODE?.trim().toLowerCase();
  if (raw === "hash") return "hash";
  return "openai";
}

function resolveOpenAiApiKey(): string | null {
  const primary = process.env.VECTOR_SCREENING_OPENAI_API_KEY?.trim();
  if (primary) return primary;
  const fallback = process.env.OPENAI_API_KEY?.trim();
  return fallback ? fallback : null;
}

function resolveOpenAiEmbeddingUrl(): string {
  return process.env.VECTOR_SCREENING_OPENAI_EMBEDDING_URL?.trim() || "https://api.openai.com/v1/embeddings";
}

function resolveOpenAiEmbeddingModel(): string {
  return process.env.VECTOR_SCREENING_OPENAI_EMBEDDING_MODEL?.trim() || "text-embedding-3-small";
}

function resolveSimilarityThreshold(): number {
  const raw = Number(process.env.VECTOR_SCREENING_SIMILARITY_THRESHOLD);
  if (!Number.isFinite(raw)) return 0.92;
  return Math.min(1, Math.max(-1, raw));
}

function resolveDuplicateThreshold(): number {
  const raw = Number(process.env.VECTOR_SCREENING_DUPLICATE_THRESHOLD);
  if (!Number.isFinite(raw)) return 0.985;
  return Math.min(1, Math.max(-1, raw));
}

function resolveCompareVectorStatuses(): Set<VectorStatus> {
  const raw = process.env.VECTOR_SCREENING_COMPARE_STATUSES?.trim();
  if (!raw) return new Set(DEFAULT_COMPARE_VECTOR_STATUSES);
  const resolved = raw
    .split(",")
    .map((value) => value.trim().toUpperCase())
    .filter((value): value is VectorStatus => KNOWN_VECTOR_STATUSES.includes(value as VectorStatus));
  if (resolved.length === 0) return new Set(DEFAULT_COMPARE_VECTOR_STATUSES);
  return new Set(resolved);
}

function resolveRequireIndexedVectorsOnly(): boolean {
  return parseBooleanEnv(process.env.VECTOR_SCREENING_REQUIRE_INDEXED_VECTORS, true);
}

function resolveUpsertTimeoutMs(): number {
  const raw = process.env.VECTOR_SCREENING_UPSERT_TIMEOUT_MS?.trim();
  if (!raw) return 15_000;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed < 500 || parsed > 120_000) return 15_000;
  return parsed;
}

function resolveScreenTimeoutMs(): number {
  const raw = process.env.VECTOR_SCREENING_SCREEN_TIMEOUT_MS?.trim();
  if (!raw) return 20_000;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed < 500 || parsed > 120_000) return 20_000;
  return parsed;
}

function resolveQdrantUrl(): string {
  return (process.env.VECTOR_SCREENING_QDRANT_URL?.trim() || "http://127.0.0.1:6333").replace(/\/+$/, "");
}

function resolveQdrantApiKey(): string | null {
  const token = process.env.VECTOR_SCREENING_QDRANT_API_KEY?.trim();
  return token ? token : null;
}

function resolveQdrantCollection(): string {
  return process.env.VECTOR_SCREENING_QDRANT_COLLECTION?.trim() || "request_screening";
}

function resolveDefaultVectorSizeForEmbeddingMode(): number {
  if (resolveEmbeddingMode() === "hash") return 256;
  const model = resolveOpenAiEmbeddingModel();
  if (model.includes("3-large")) return 3072;
  return 1536;
}

function resolveQdrantVectorSize(): number {
  const raw = process.env.VECTOR_SCREENING_QDRANT_VECTOR_SIZE?.trim();
  if (!raw) return resolveDefaultVectorSizeForEmbeddingMode();
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed < 8 || parsed > 16384) return resolveDefaultVectorSizeForEmbeddingMode();
  return parsed;
}

function resolveQdrantDistance(): "Cosine" | "Dot" | "Euclid" {
  const raw = process.env.VECTOR_SCREENING_QDRANT_DISTANCE?.trim().toLowerCase();
  if (raw === "dot") return "Dot";
  if (raw === "euclid") return "Euclid";
  return "Cosine";
}

function resolveQdrantSearchLimit(): number {
  const raw = process.env.VECTOR_SCREENING_QDRANT_SEARCH_LIMIT?.trim();
  if (!raw) return 64;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 2000) return 64;
  return parsed;
}

function normalizeText(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

function normalizeUrls(urls: string[]): string[] {
  return [...urls]
    .map((value) => value.trim())
    .filter(Boolean)
    .sort((a, b) => a.localeCompare(b));
}

function textHash(input: string): string {
  return `0x${createHash("sha256").update(input).digest("hex")}`;
}

export function requestIdToPointId(requestId: string): string {
  const hex = createHash("sha256").update(requestId.toLowerCase()).digest("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

export function buildCanonicalTextForVector(input: MarketRequestInput): string {
  return [
    `question=${normalizeText(input.question)}`,
    `description=${normalizeText(input.description)}`,
    `resolutionCriteria=${normalizeText(input.resolutionCriteria)}`,
    `sourceUrls=${normalizeUrls(input.sourceUrls).join("|")}`,
    `submitterAddress=${input.submitterAddress.trim().toLowerCase()}`
  ].join("\n");
}

function toUnitVector(raw: number[]): number[] {
  const magnitude = Math.sqrt(raw.reduce((sum, value) => sum + value * value, 0));
  if (!Number.isFinite(magnitude) || magnitude <= 0) return raw.map(() => 0);
  return raw.map((value) => value / magnitude);
}

function buildHashEmbedding(text: string, dimensions = 256): number[] {
  const values: number[] = [];
  let block = createHash("sha256").update(text).digest();
  let counter = 0;
  while (values.length < dimensions) {
    for (const byte of block) {
      const centered = byte / 127.5 - 1;
      values.push(centered);
      if (values.length >= dimensions) break;
    }
    counter += 1;
    block = createHash("sha256").update(block).update(String(counter)).digest();
  }
  return toUnitVector(values);
}

function buildCandidateInput(value: unknown): MarketRequestInput | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const sourceUrls = Array.isArray(record.sourceUrls) ? record.sourceUrls.map((entry) => String(entry)).filter(Boolean) : [];
  const question = String(record.question ?? "").trim();
  const description = String(record.description ?? "").trim();
  const resolutionCriteria = String(record.resolutionCriteria ?? "").trim();
  const submitterAddress = String(record.submitterAddress ?? "").trim();
  if (!question || !description || !resolutionCriteria || !submitterAddress) return null;
  return {
    question,
    description,
    sourceUrls,
    resolutionCriteria,
    submitterAddress
  };
}

function buildExistingInput(value: ExistingScreeningRecord): MarketRequestInput | null {
  const question = String(value.question ?? "").trim();
  const description = String(value.description ?? "").trim();
  const resolutionCriteria = String(value.resolutionCriteria ?? "").trim();
  if (!question || !resolutionCriteria) return null;
  return {
    question,
    description,
    sourceUrls: Array.isArray(value.sourceUrls) ? value.sourceUrls.map((entry) => String(entry)) : [],
    resolutionCriteria,
    submitterAddress: String(value.submitterAddress ?? "0x0000000000000000000000000000000000000000")
  };
}

async function fetchOpenAiEmbedding(text: string, timeoutMs: number): Promise<number[]> {
  const apiKey = resolveOpenAiApiKey();
  if (!apiKey) throw new Error("vector_screening_missing_openai_api_key");
  const response = await fetch(resolveOpenAiEmbeddingUrl(), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`
    },
    body: JSON.stringify({
      model: resolveOpenAiEmbeddingModel(),
      input: text
    }),
    signal: AbortSignal.timeout(timeoutMs)
  });
  if (!response.ok) {
    const detail = (await response.text()).trim().slice(0, 300);
    throw new Error(`vector_screening_openai_http_${response.status}${detail ? `:${detail}` : ""}`);
  }
  const decoded = (await response.json()) as OpenAiEmbeddingApiResponse;
  const embedding = decoded.data?.[0]?.embedding;
  if (!Array.isArray(embedding) || embedding.length === 0 || embedding.some((value) => typeof value !== "number")) {
    throw new Error("vector_screening_openai_invalid_embedding");
  }
  return toUnitVector(embedding);
}

async function resolveEmbedding(text: string, timeoutMs: number): Promise<number[]> {
  const hash = textHash(text);
  const cached = embeddingCache.get(hash);
  if (cached) return cached;
  const mode = resolveEmbeddingMode();
  const embedding = mode === "hash" ? buildHashEmbedding(text) : await fetchOpenAiEmbedding(text, timeoutMs);
  embeddingCache.set(hash, embedding);
  return embedding;
}

function toVectorStatus(value: unknown): VectorStatus | null {
  const normalized = String(value ?? "").trim().toUpperCase();
  if (!KNOWN_VECTOR_STATUSES.includes(normalized as VectorStatus)) return null;
  return normalized as VectorStatus;
}

export function cosineSimilarity(left: number[], right: number[]): number {
  if (left.length === 0 || right.length === 0) return 0;
  const shared = Math.min(left.length, right.length);
  let dot = 0;
  let leftNorm = 0;
  let rightNorm = 0;
  for (let index = 0; index < shared; index += 1) {
    const a = left[index] ?? 0;
    const b = right[index] ?? 0;
    dot += a * b;
    leftNorm += a * a;
    rightNorm += b * b;
  }
  if (leftNorm <= 0 || rightNorm <= 0) return 0;
  return dot / Math.sqrt(leftNorm * rightNorm);
}

export function pickBestMatch(matches: SearchMatch[]): SearchMatch | null {
  if (matches.length === 0) return null;
  let best = matches[0]!;
  for (let index = 1; index < matches.length; index += 1) {
    const candidate = matches[index]!;
    if (candidate.similarity > best.similarity) {
      best = candidate;
    }
  }
  return best;
}

export function decideSimilarityAction(args: {
  similarity: number;
  matchedRequestId: string;
  conflictThreshold: number;
  duplicateThreshold: number;
}): {
  decision: "allow" | "reject_duplicate" | "reject_conflict";
  reason?: string;
} {
  const similarityRounded = args.similarity.toFixed(4);
  if (args.similarity >= args.duplicateThreshold) {
    return {
      decision: "reject_duplicate",
      reason: `vector_duplicate_of_request:${args.matchedRequestId}:similarity=${similarityRounded}`
    };
  }
  if (args.similarity >= args.conflictThreshold) {
    return {
      decision: "reject_conflict",
      reason: `vector_conflict_with_request:${args.matchedRequestId}:similarity=${similarityRounded}`
    };
  }
  return { decision: "allow" };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization"
    }
  });
}

function corsPreflight(): Response {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization"
    }
  });
}

async function parseJsonBody(req: Request): Promise<Record<string, unknown>> {
  const raw = await req.text();
  if (!raw) return {};
  return JSON.parse(raw) as Record<string, unknown>;
}

function ensureAuthorized(req: Request): Response | null {
  const token = resolveAuthToken();
  if (!token) return null;
  const actual = req.headers.get("authorization")?.trim() ?? "";
  if (actual !== `Bearer ${token}`) {
    return jsonResponse(
      {
        ok: false,
        error: "unauthorized"
      },
      401
    );
  }
  return null;
}

function parseUpsertInput(body: Record<string, unknown>): { requestId: string; vectorStatus: VectorStatus; input: MarketRequestInput } | null {
  const requestId = String(body.requestId ?? "").trim();
  const vectorStatus = toVectorStatus(body.vectorStatus);
  if (!requestId || !vectorStatus) return null;
  const input = buildCandidateInput({
    question: body.question,
    description: body.description,
    sourceUrls: body.sourceUrls,
    resolutionCriteria: body.resolutionCriteria,
    submitterAddress: body.submitterAddress
  });
  if (!input) return null;
  return { requestId, vectorStatus, input };
}

function parseExistingRecords(body: Record<string, unknown>): ExistingScreeningRecord[] {
  if (!Array.isArray(body.existing)) return [];
  const results: ExistingScreeningRecord[] = [];
  for (const entry of body.existing) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) continue;
    const record = entry as Record<string, unknown>;
    const requestId = String(record.requestId ?? "").trim();
    if (!requestId) continue;
    const sourceUrls = Array.isArray(record.sourceUrls) ? record.sourceUrls.map((value) => String(value)) : undefined;
    results.push({
      requestId,
      status: typeof record.status === "string" ? (record.status as RequestStatus) : undefined,
      question: typeof record.question === "string" ? record.question : undefined,
      description: typeof record.description === "string" ? record.description : undefined,
      sourceUrls,
      resolutionCriteria: typeof record.resolutionCriteria === "string" ? record.resolutionCriteria : undefined,
      submitterAddress: typeof record.submitterAddress === "string" ? record.submitterAddress : undefined
    });
  }
  return results;
}

async function loadStore(): Promise<void> {
  const fallback: VectorIndexStore = {
    version: 1,
    updatedAt: nowIso(),
    records: {}
  };
  const loaded = await readJsonFile<VectorIndexStore>(resolveStorePath(), fallback);
  if (!loaded || typeof loaded !== "object" || !loaded.records || typeof loaded.records !== "object") {
    vectorStore = fallback;
    return;
  }
  vectorStore = {
    version: 1,
    updatedAt: typeof loaded.updatedAt === "string" ? loaded.updatedAt : nowIso(),
    records: loaded.records
  };
}

async function persistStore(): Promise<void> {
  vectorStore.updatedAt = nowIso();
  await writeJsonFileAtomic(resolveStorePath(), vectorStore);
}

async function qdrantRequest(args: {
  path: string;
  method: "GET" | "POST" | "PUT";
  timeoutMs: number;
  body?: unknown;
  allowStatuses?: number[];
}): Promise<{ status: number; data: unknown; text: string }> {
  const allowStatuses = args.allowStatuses ?? [200];
  const headers: Record<string, string> = {};
  if (args.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  const apiKey = resolveQdrantApiKey();
  if (apiKey) {
    headers["api-key"] = apiKey;
  }

  const response = await fetch(`${resolveQdrantUrl()}${args.path}`, {
    method: args.method,
    headers,
    body: args.body !== undefined ? JSON.stringify(args.body) : undefined,
    signal: AbortSignal.timeout(args.timeoutMs)
  });
  const text = await response.text();
  let data: unknown = null;
  if (text) {
    try {
      data = JSON.parse(text) as unknown;
    } catch {
      data = text;
    }
  }
  if (!allowStatuses.includes(response.status)) {
    throw new Error(`vector_screening_qdrant_http_${response.status}${text ? `:${text.slice(0, 240)}` : ""}`);
  }
  return {
    status: response.status,
    data,
    text
  };
}

async function ensureQdrantCollection(timeoutMs: number): Promise<void> {
  if (qdrantCollectionReady) return;
  const collection = encodeURIComponent(resolveQdrantCollection());
  const check = await qdrantRequest({
    path: `/collections/${collection}`,
    method: "GET",
    timeoutMs,
    allowStatuses: [200, 404]
  });
  if (check.status === 404) {
    await qdrantRequest({
      path: `/collections/${collection}`,
      method: "PUT",
      timeoutMs,
      body: {
        vectors: {
          size: resolveQdrantVectorSize(),
          distance: resolveQdrantDistance()
        }
      },
      allowStatuses: [200]
    });
  }
  qdrantCollectionReady = true;
}

async function upsertQdrantRecord(args: {
  requestId: string;
  vectorStatus: VectorStatus;
  canonicalText: string;
  embedding: number[];
  textHash: string;
  now: string;
  timeoutMs: number;
}): Promise<void> {
  const collection = encodeURIComponent(resolveQdrantCollection());
  await ensureQdrantCollection(args.timeoutMs);
  await qdrantRequest({
    path: `/collections/${collection}/points?wait=true`,
    method: "PUT",
    timeoutMs: args.timeoutMs,
    body: {
      points: [
        {
          id: requestIdToPointId(args.requestId),
          vector: args.embedding,
          payload: {
            requestId: args.requestId,
            vectorStatus: args.vectorStatus,
            canonicalText: args.canonicalText,
            textHash: args.textHash,
            updatedAt: args.now
          }
        }
      ]
    }
  });
}

async function removeQdrantRecord(requestId: string, timeoutMs: number): Promise<void> {
  const collection = encodeURIComponent(resolveQdrantCollection());
  await ensureQdrantCollection(timeoutMs);
  await qdrantRequest({
    path: `/collections/${collection}/points/delete?wait=true`,
    method: "POST",
    timeoutMs,
    body: {
      points: [requestIdToPointId(requestId)]
    }
  });
}

function parseQdrantSearchPoints(payload: unknown): QdrantPoint[] {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return [];
  const root = payload as Record<string, unknown>;
  const result = root.result;
  if (Array.isArray(result)) return result as QdrantPoint[];
  if (result && typeof result === "object" && !Array.isArray(result)) {
    const nested = (result as Record<string, unknown>).points;
    if (Array.isArray(nested)) return nested as QdrantPoint[];
  }
  return [];
}

async function findBestMatchInQdrant(args: {
  candidateEmbedding: number[];
  existingIds: Set<string>;
  allowedStatuses: Set<VectorStatus>;
  timeoutMs: number;
}): Promise<SearchResult> {
  const collection = encodeURIComponent(resolveQdrantCollection());
  await ensureQdrantCollection(args.timeoutMs);
  const baseLimit = resolveQdrantSearchLimit();
  const limit =
    args.existingIds.size > 0 ? Math.min(Math.max(baseLimit, args.existingIds.size * 3), 2000) : baseLimit;

  let response;
  try {
    response = await qdrantRequest({
      path: `/collections/${collection}/points/search`,
      method: "POST",
      timeoutMs: args.timeoutMs,
      body: {
        vector: args.candidateEmbedding,
        limit,
        with_payload: true
      },
      allowStatuses: [200]
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!message.includes("vector_screening_qdrant_http_404")) {
      throw error;
    }
    response = await qdrantRequest({
      path: `/collections/${collection}/points/query`,
      method: "POST",
      timeoutMs: args.timeoutMs,
      body: {
        query: args.candidateEmbedding,
        limit,
        with_payload: true
      },
      allowStatuses: [200]
    });
  }

  const points = parseQdrantSearchPoints(response.data);
  const matches: SearchMatch[] = [];
  for (const point of points) {
    const payload = point.payload ?? {};
    const requestIdRaw = String(payload.requestId ?? point.id ?? "").trim();
    if (!requestIdRaw) continue;
    if (args.existingIds.size > 0 && !args.existingIds.has(requestIdRaw)) continue;
    const vectorStatus = toVectorStatus(payload.vectorStatus);
    if (!vectorStatus || !args.allowedStatuses.has(vectorStatus)) continue;
    const similarity = Number(point.score);
    if (!Number.isFinite(similarity)) continue;
    matches.push({
      requestId: requestIdRaw,
      similarity
    });
  }
  return {
    comparedCount: matches.length,
    bestMatch: pickBestMatch(matches)
  };
}

async function findBestMatchInFileStore(args: {
  candidateEmbedding: number[];
  existing: ExistingScreeningRecord[];
  allowedStatuses: Set<VectorStatus>;
  timeoutMs: number;
}): Promise<SearchResult> {
  const matches: SearchMatch[] = [];
  for (const record of args.existing) {
    const indexed = vectorStore.records[record.requestId];
    if (indexed && args.allowedStatuses.has(indexed.vectorStatus)) {
      matches.push({
        requestId: record.requestId,
        similarity: cosineSimilarity(args.candidateEmbedding, indexed.embedding)
      });
      continue;
    }
    if (resolveRequireIndexedVectorsOnly()) {
      continue;
    }
    const fallbackInput = buildExistingInput(record);
    if (!fallbackInput) continue;
    const fallbackEmbedding = await resolveEmbedding(buildCanonicalTextForVector(fallbackInput), args.timeoutMs);
    matches.push({
      requestId: record.requestId,
      similarity: cosineSimilarity(args.candidateEmbedding, fallbackEmbedding)
    });
  }
  return {
    comparedCount: matches.length,
    bestMatch: pickBestMatch(matches)
  };
}

async function queryQdrantRecordCount(timeoutMs: number): Promise<number | null> {
  try {
    const collection = encodeURIComponent(resolveQdrantCollection());
    await ensureQdrantCollection(timeoutMs);
    const response = await qdrantRequest({
      path: `/collections/${collection}/points/count`,
      method: "POST",
      timeoutMs,
      body: {
        exact: false
      }
    });
    const decoded = response.data as QdrantCountResponse;
    const count = Number(decoded.result?.count);
    if (!Number.isFinite(count) || count < 0) return null;
    return Math.floor(count);
  } catch {
    return null;
  }
}

async function handleUpsert(body: Record<string, unknown>): Promise<Response> {
  const parsed = parseUpsertInput(body);
  if (!parsed) {
    return jsonResponse(
      {
        ok: false,
        error: "invalid_upsert_payload"
      },
      400
    );
  }

  const now = nowIso();
  const backend = resolveStoreBackend();
  const timeoutMs = resolveUpsertTimeoutMs();
  if (!ACTIVE_UPSERT_STATUSES.has(parsed.vectorStatus)) {
    if (backend === "qdrant") {
      await removeQdrantRecord(parsed.requestId, timeoutMs);
    } else if (vectorStore.records[parsed.requestId]) {
      delete vectorStore.records[parsed.requestId];
      await persistStore();
    }
    return jsonResponse({
      ok: true,
      removed: true,
      requestId: parsed.requestId,
      vectorStatus: parsed.vectorStatus,
      backend,
      timestamp: now
    });
  }

  const canonicalText = buildCanonicalTextForVector(parsed.input);
  const embedding = await resolveEmbedding(canonicalText, timeoutMs);
  const hash = textHash(canonicalText);
  if (backend === "qdrant") {
    await upsertQdrantRecord({
      requestId: parsed.requestId,
      vectorStatus: parsed.vectorStatus,
      canonicalText,
      embedding,
      textHash: hash,
      now,
      timeoutMs
    });
  } else {
    const existing = vectorStore.records[parsed.requestId];
    vectorStore.records[parsed.requestId] = {
      requestId: parsed.requestId,
      vectorStatus: parsed.vectorStatus,
      canonicalText,
      textHash: hash,
      embedding,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now
    };
    await persistStore();
  }

  return jsonResponse({
    ok: true,
    upserted: true,
    requestId: parsed.requestId,
    vectorStatus: parsed.vectorStatus,
    backend,
    embeddingDims: embedding.length,
    timestamp: now
  });
}

async function handleScreen(body: Record<string, unknown>): Promise<Response> {
  const candidate = buildCandidateInput(body.candidate);
  if (!candidate) {
    return jsonResponse(
      {
        ok: false,
        error: "invalid_screen_candidate"
      },
      400
    );
  }

  const existing = parseExistingRecords(body);
  if (existing.length === 0) {
    return jsonResponse({
      decision: "allow",
      reason: "vector_screening_no_existing_records",
      comparedCount: 0
    });
  }

  const timeoutMs = resolveScreenTimeoutMs();
  const candidateEmbedding = await resolveEmbedding(buildCanonicalTextForVector(candidate), timeoutMs);
  const backend = resolveStoreBackend();
  const allowedStatuses = resolveCompareVectorStatuses();
  const result =
    backend === "qdrant"
      ? await findBestMatchInQdrant({
          candidateEmbedding,
          existingIds: new Set(existing.map((value) => value.requestId)),
          allowedStatuses,
          timeoutMs
        })
      : await findBestMatchInFileStore({
          candidateEmbedding,
          existing,
          allowedStatuses,
          timeoutMs
        });

  if (!result.bestMatch) {
    return jsonResponse({
      decision: "allow",
      reason: "vector_screening_no_comparable_vectors",
      backend,
      comparedCount: result.comparedCount
    });
  }

  const decision = decideSimilarityAction({
    similarity: result.bestMatch.similarity,
    matchedRequestId: result.bestMatch.requestId,
    conflictThreshold: resolveSimilarityThreshold(),
    duplicateThreshold: resolveDuplicateThreshold()
  });

  return jsonResponse({
    ...decision,
    backend,
    comparedCount: result.comparedCount,
    matchedRequestId: result.bestMatch.requestId,
    similarity: Number(result.bestMatch.similarity.toFixed(6))
  });
}

async function buildHealthSnapshot(): Promise<Record<string, unknown>> {
  const backend = resolveStoreBackend();
  const base = {
    ok: true,
    service: "vector-screening-service",
    timestamp: nowIso(),
    backend,
    embeddingMode: resolveEmbeddingMode(),
    embeddingModel: resolveOpenAiEmbeddingModel(),
    compareVectorStatuses: Array.from(resolveCompareVectorStatuses()),
    requireIndexedVectors: resolveRequireIndexedVectorsOnly()
  };
  if (backend === "qdrant") {
    const count = await queryQdrantRecordCount(2_000);
    return {
      ...base,
      qdrantUrl: resolveQdrantUrl(),
      qdrantCollection: resolveQdrantCollection(),
      qdrantDistance: resolveQdrantDistance(),
      qdrantVectorSize: resolveQdrantVectorSize(),
      records: count
    };
  }
  return {
    ...base,
    storePath: resolveStorePath(),
    records: Object.keys(vectorStore.records).length
  };
}

async function router(req: Request): Promise<Response> {
  if (req.method === "OPTIONS") {
    return corsPreflight();
  }

  const authError = ensureAuthorized(req);
  if (authError) {
    return authError;
  }

  const url = new URL(req.url);
  if (req.method === "GET" && url.pathname === "/healthz") {
    return jsonResponse(await buildHealthSnapshot());
  }

  if (req.method === "POST" && url.pathname === "/upsert") {
    try {
      const body = await parseJsonBody(req);
      return await handleUpsert(body);
    } catch (error) {
      return jsonResponse(
        {
          ok: false,
          error: error instanceof Error ? error.message : String(error)
        },
        500
      );
    }
  }

  if (req.method === "POST" && url.pathname === "/screen") {
    try {
      const body = await parseJsonBody(req);
      return await handleScreen(body);
    } catch (error) {
      return jsonResponse(
        {
          ok: false,
          error: error instanceof Error ? error.message : String(error)
        },
        500
      );
    }
  }

  return jsonResponse({ ok: false, error: "not_found" }, 404);
}

export async function startVectorScreeningService(): Promise<void> {
  if (resolveStoreBackend() === "file") {
    await loadStore();
  }
  const port = resolvePort();
  Bun.serve({
    port,
    fetch: router
  });
  const auth = resolveAuthToken();
  console.log(
    `[vector-screening-service] listening: ${JSON.stringify({
      port,
      backend: resolveStoreBackend(),
      storePath: resolveStorePath(),
      qdrantUrl: resolveQdrantUrl(),
      qdrantCollection: resolveQdrantCollection(),
      embeddingMode: resolveEmbeddingMode(),
      embeddingModel: resolveOpenAiEmbeddingModel(),
      similarityThreshold: resolveSimilarityThreshold(),
      duplicateThreshold: resolveDuplicateThreshold(),
      compareVectorStatuses: Array.from(resolveCompareVectorStatuses()),
      requireIndexedVectors: resolveRequireIndexedVectorsOnly(),
      authEnabled: Boolean(auth),
      authTokenLength: auth ? auth.length : 0
    })}`
  );
}

if (import.meta.main) {
  await startVectorScreeningService();
}
