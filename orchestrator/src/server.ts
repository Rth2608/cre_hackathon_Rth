import { readFile } from "node:fs/promises";
import { Interface, JsonRpcProvider, getAddress, hashMessage, toUtf8Bytes, verifyMessage } from "ethers";
import type { MarketRequestInput, OnchainReceipt, RequestStatus, StoredRequest } from "./types";
import { runCreWorkflow } from "./creRunner";
import { selectRuntimeNodesForRequest } from "./matcher";
import {
  activateNodeRegistrationChallenge,
  createNodeRegistrationChallenge,
  listRegisteredNodes,
  refreshNodeEndpointHealth,
  registerOrUpdateNode,
  touchNodeHeartbeat
} from "./nodeRegistry";
import { getRequestFromOnchain, listNodesFromOnchain, listRequestsFromOnchain } from "./onchainReader";
import { submitConsensusOnchain, submitNodeLifecycleOnchain, submitPorProofOnchain } from "./onchainWriter";
import { buildNextPorProofInput, getPorStatusSnapshot } from "./por";
import { getRequest, listRequests, saveRequest } from "./storage";
import { generateRequestId, hashObject, nowIso, resolveProjectPath } from "./utils";
import { ValidationError, validateMarketRequest } from "./validator";
import {
  consumeWorldIdSessionToken,
  issueWorldIdSessionFromProof,
  validateWorldIdSessionToken
} from "./worldId";
import { enforceX402Payment } from "./x402";

const PORT = Number.parseInt(process.env.PORT ?? "8787", 10);
const MAX_RUN_ATTEMPTS = 2;
const CORS_ALLOW_HEADERS =
  "Content-Type, X-Wallet-Address, X-Payment, Payment-Signature, X-World-ID-Token, X-Wallet-Auth-Signature, X-Wallet-Auth-Timestamp, X-Wallet-Auth-Siwe-Message, X-Wallet-Auth-Siwe-Signature, X-Wallet-Auth-Siwe-Address, X-Wallet-Auth-Siwe-Request-Id, X-Wallet-Auth-Siwe-Version";
const WALLET_AUTH_SIGNATURE_HEADER = "x-wallet-auth-signature";
const WALLET_AUTH_TIMESTAMP_HEADER = "x-wallet-auth-timestamp";
const WALLET_AUTH_SIWE_MESSAGE_HEADER = "x-wallet-auth-siwe-message";
const WALLET_AUTH_SIWE_SIGNATURE_HEADER = "x-wallet-auth-siwe-signature";
const WALLET_AUTH_SIWE_ADDRESS_HEADER = "x-wallet-auth-siwe-address";
const WALLET_AUTH_SIWE_REQUEST_ID_HEADER = "x-wallet-auth-siwe-request-id";
const WALLET_AUTH_SIWE_VERSION_HEADER = "x-wallet-auth-siwe-version";
const DEFAULT_WALLET_AUTH_MAX_AGE_MS = 5 * 60_000;
const STARTUP_SKIP_ENV_VALIDATION = parseBooleanEnv(process.env.SKIP_STARTUP_ENV_VALIDATION, false);
const EIP1271_MAGIC_VALUE = "0x1626ba7e";
const EIP1271_INTERFACE = new Interface([
  "function isValidSignature(bytes32,bytes) view returns (bytes4)",
  "function isValidSignature(bytes,bytes) view returns (bytes4)"
]);
const SAFE_OWNER_INTERFACE = new Interface(["function isOwner(address) view returns (bool)"]);

type ServerLogLevel = "info" | "warn" | "error";

function stringifyError(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

function logServerEvent(level: ServerLogLevel, event: string, payload: Record<string, unknown>): void {
  const line = `${nowIso()} ${event} ${JSON.stringify(payload)}`;
  if (level === "error") {
    console.error(line);
    return;
  }
  if (level === "warn") {
    console.warn(line);
    return;
  }
  console.log(line);
}

function logServerFailure(event: string, payload: Record<string, unknown>): void {
  logServerEvent("error", event, payload);
}

function buildRequestRunTraceId(requestId: string, runAttempt: number): string {
  return `${requestId}:run:${runAttempt}`;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": CORS_ALLOW_HEADERS
    }
  });
}

function corsPreflight(): Response {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": CORS_ALLOW_HEADERS
    }
  });
}

async function parseJsonBody<T>(req: Request): Promise<T> {
  const text = await req.text();
  if (!text) {
    throw new Error("Request body is empty");
  }
  return JSON.parse(text) as T;
}

function buildRequestResponse(record: StoredRequest): Record<string, unknown> {
  return {
    requestId: record.requestId,
    status: record.status,
    vectorSync: record.vectorSync,
    queuePriority: record.queuePriority,
    queueDecision: record.queueDecision,
    runAttempts: record.runAttempts,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    input: record.input,
    nodeReports: record.nodeReports,
    signedNodeReports: record.signedNodeReports,
    executionReceipts: record.executionReceipts,
    quorumValidation: record.quorumValidation,
    consensus: record.consensus,
    consensusBundle: record.consensusBundle,
    onchainReceipt: record.onchainReceipt,
    activeNodes: record.activeNodes,
    paymentReceipt: record.paymentReceipt,
    workflowStepLogs: record.workflowStepLogs,
    lastError: record.lastError
  };
}

function parseRequestIdFromPath(pathname: string, regex: RegExp): string | null {
  const matched = pathname.match(regex);
  return matched ? decodeURIComponent(matched[1]) : null;
}

function resolveRequestVerificationPrice(): string {
  return process.env.X402_PRICE_RUN_VERIFICATION?.trim() || process.env.X402_PRICE_REQUEST_CREATE?.trim() || "$0.05";
}

function resolveRequestRequireWorldIdOnCreate(): boolean {
  return parseBooleanEnv(process.env.REQUEST_REQUIRE_WORLD_ID_ON_CREATE, true);
}

function resolveRequestRejectConflictEnabled(): boolean {
  return parseBooleanEnv(process.env.REQUEST_REJECT_CONFLICT_ENABLED, true);
}

function resolveRequestScreeningServiceUrl(): string | null {
  const value = process.env.REQUEST_SCREENING_HTTP_URL?.trim();
  return value ? value : null;
}

function resolveRequestScreeningServiceTimeoutMs(): number {
  const raw = process.env.REQUEST_SCREENING_TIMEOUT_MS?.trim();
  if (!raw) {
    return 6000;
  }
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed < 500 || parsed > 30_000) {
    return 6000;
  }
  return parsed;
}

function resolveRequestVectorSyncServiceUrl(): string | null {
  const value = process.env.REQUEST_VECTOR_SYNC_HTTP_URL?.trim();
  return value ? value : null;
}

function resolveRequestVectorSyncEnabled(): boolean {
  const fallback = resolveRequestVectorSyncServiceUrl() !== null;
  return parseBooleanEnv(process.env.REQUEST_VECTOR_SYNC_ENABLED, fallback);
}

function resolveRequestVectorSyncTimeoutMs(): number {
  const raw = process.env.REQUEST_VECTOR_SYNC_TIMEOUT_MS?.trim();
  if (!raw) {
    return 6000;
  }
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed < 500 || parsed > 30_000) {
    return 6000;
  }
  return parsed;
}

function resolveRequestVectorSyncBlockOnFailure(): boolean {
  return parseBooleanEnv(process.env.REQUEST_VECTOR_SYNC_BLOCK_ON_FAILURE, true);
}

function mapRequestStatusToVectorStatus(
  status: RequestStatus
): NonNullable<StoredRequest["vectorSync"]>["vectorStatus"] {
  if (status === "PENDING") {
    return "QUEUED";
  }
  if (status === "RUNNING") {
    return "VERIFYING";
  }
  if (status === "FINALIZED") {
    return "APPROVED_PENDING_OPEN";
  }
  if (isRejectedRequestStatus(status)) {
    return "REJECTED";
  }
  return "REJECTED";
}

function isVectorSyncGateStatus(status: RequestStatus): boolean {
  return status === "FINALIZED" || isRejectedRequestStatus(status);
}

function isVectorSyncAppliedForStatus(record: StoredRequest, status: RequestStatus): boolean {
  if (!resolveRequestVectorSyncEnabled()) {
    return true;
  }
  const expected = mapRequestStatusToVectorStatus(status);
  return record.vectorSync?.state === "APPLIED" && record.vectorSync.vectorStatus === expected;
}

function buildVectorSyncPayload(record: StoredRequest, vectorStatus: NonNullable<StoredRequest["vectorSync"]>["vectorStatus"]) {
  return {
    requestId: record.requestId,
    requestStatus: record.status,
    vectorStatus,
    question: record.input.question,
    description: record.input.description,
    sourceUrls: record.input.sourceUrls,
    resolutionCriteria: record.input.resolutionCriteria,
    submitterAddress: record.input.submitterAddress,
    queuePriority: record.queuePriority,
    queueDecision: record.queueDecision,
    consensus: record.consensus
      ? {
          aggregateScoreBps: record.consensus.aggregateScoreBps,
          finalVerdict: record.consensus.finalVerdict,
          responders: record.consensus.responders,
          finalReportHash: record.consensus.finalReportHash
        }
      : undefined,
    onchainReceipt: record.onchainReceipt
      ? {
          txHash: record.onchainReceipt.txHash,
          chainId: record.onchainReceipt.chainId,
          blockNumber: record.onchainReceipt.blockNumber,
          simulated: record.onchainReceipt.simulated
        }
      : undefined,
    updatedAt: record.updatedAt,
    createdAt: record.createdAt
  };
}

async function syncRequestVectorStatus(
  record: StoredRequest,
  trigger: string
): Promise<StoredRequest> {
  if (!resolveRequestVectorSyncEnabled()) {
    return record;
  }

  const vectorStatus = mapRequestStatusToVectorStatus(record.status);
  if (record.vectorSync?.state === "APPLIED" && record.vectorSync.vectorStatus === vectorStatus) {
    return record;
  }

  const currentAttempts = record.vectorSync?.attempts ?? 0;
  const applyingRecord: StoredRequest = {
    ...record,
    vectorSync: {
      state: "APPLYING",
      vectorStatus,
      attempts: currentAttempts + 1,
      updatedAt: nowIso(),
      lastError: undefined
    }
  };
  await saveRequest(applyingRecord);

  const url = resolveRequestVectorSyncServiceUrl();
  if (!url) {
    const failedNoUrlRecord: StoredRequest = {
      ...applyingRecord,
      vectorSync: {
        ...applyingRecord.vectorSync!,
        state: "FAILED",
        updatedAt: nowIso(),
        lastError: "vector_sync_url_not_configured"
      }
    };
    await saveRequest(failedNoUrlRecord);
    return failedNoUrlRecord;
  }

  const timeoutController = new AbortController();
  const timeoutId = setTimeout(() => timeoutController.abort(), resolveRequestVectorSyncTimeoutMs());
  try {
    const headers: Record<string, string> = {
      "Content-Type": "application/json"
    };
    const token = process.env.REQUEST_VECTOR_SYNC_AUTH_TOKEN?.trim();
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }

    const response = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify(buildVectorSyncPayload(applyingRecord, vectorStatus)),
      signal: timeoutController.signal
    });

    if (!response.ok) {
      const detail = (await response.text()).trim().slice(0, 300);
      throw new Error(`vector_sync_http_${response.status}${detail ? `:${detail}` : ""}`);
    }

    const appliedRecord: StoredRequest = {
      ...applyingRecord,
      vectorSync: {
        ...applyingRecord.vectorSync!,
        state: "APPLIED",
        updatedAt: nowIso(),
        lastError: undefined
      }
    };
    await saveRequest(appliedRecord);
    logServerEvent("info", "request.vector_sync.applied", {
      requestId: appliedRecord.requestId,
      requestStatus: appliedRecord.status,
      vectorStatus,
      trigger
    });
    return appliedRecord;
  } catch (error) {
    const failedRecord: StoredRequest = {
      ...applyingRecord,
      vectorSync: {
        ...applyingRecord.vectorSync!,
        state: "FAILED",
        updatedAt: nowIso(),
        lastError: stringifyError(error)
      }
    };
    await saveRequest(failedRecord);
    logServerFailure("request.vector_sync.failed", {
      requestId: failedRecord.requestId,
      requestStatus: failedRecord.status,
      vectorStatus,
      trigger,
      error: failedRecord.vectorSync?.lastError
    });
    return failedRecord;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function ensureEarlierTerminalVectorSyncApplied(nextQueued: StoredRequest): Promise<boolean> {
  if (!resolveRequestVectorSyncEnabled()) {
    return true;
  }

  const records = await listRequests();
  const blockers = records
    .filter((record) => record.requestId !== nextQueued.requestId)
    .filter((record) => record.createdAt.localeCompare(nextQueued.createdAt) <= 0)
    .filter((record) => isVectorSyncGateStatus(record.status))
    .filter((record) => !isVectorSyncAppliedForStatus(record, record.status))
    .sort((a, b) => a.createdAt.localeCompare(b.createdAt));

  for (const blocker of blockers) {
    const synced = await syncRequestVectorStatus(blocker, "queue_gate_before_next_verify");
    if (!isVectorSyncAppliedForStatus(synced, synced.status)) {
      return false;
    }
  }

  return true;
}

const CONFLICT_STOPWORDS = new Set([
  "the",
  "and",
  "for",
  "with",
  "from",
  "that",
  "this",
  "will",
  "would",
  "should",
  "could",
  "market",
  "prediction",
  "resolve",
  "resolution",
  "criteria",
  "before",
  "after",
  "over",
  "under",
  "than",
  "into",
  "about",
  "what",
  "when",
  "where",
  "which",
  "who",
  "why",
  "how"
]);

function normalizeMarketText(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function extractDomainList(urls: string[]): string[] {
  const domains = urls
    .map((value) => {
      try {
        return new URL(value).hostname.trim().toLowerCase();
      } catch {
        return "";
      }
    })
    .filter(Boolean);
  return Array.from(new Set(domains)).sort((a, b) => a.localeCompare(b));
}

function buildRequestDedupeKey(input: MarketRequestInput): string {
  return hashObject({
    question: normalizeMarketText(input.question),
    description: normalizeMarketText(input.description),
    resolutionCriteria: normalizeMarketText(input.resolutionCriteria),
    sourceDomains: extractDomainList(input.sourceUrls)
  });
}

function buildRequestConflictKey(input: MarketRequestInput): string {
  const normalized = normalizeMarketText(`${input.question} ${input.resolutionCriteria}`);
  const tokens = normalized
    .split(" ")
    .map((token) => token.trim())
    .filter((token) => token.length >= 3 && !CONFLICT_STOPWORDS.has(token) && !/^\d+$/.test(token));
  const stableTokens = Array.from(new Set(tokens)).sort((a, b) => a.localeCompare(b)).slice(0, 18);
  return hashObject({
    topicTokens: stableTokens
  });
}

function computeHeuristicQueuePriority(input: MarketRequestInput): number {
  const base = 100;
  const sourceBoost = Math.min(input.sourceUrls.length * 5, 25);
  const question = input.question.toLowerCase();
  const description = input.description.toLowerCase();
  const urgentBoost = /\b(urgent|breaking|asap|immediately)\b/.test(`${question} ${description}`) ? 30 : 0;
  const explicitDateBoost = /\b(20\d{2})\b/.test(question) ? 10 : 0;
  const score = base + sourceBoost + urgentBoost + explicitDateBoost;
  return Math.max(1, Math.min(score, 1000));
}

function isActiveRequestStatusForScreening(status: RequestStatus): boolean {
  return status === "PENDING" || status === "RUNNING" || status === "FINALIZED";
}

function isRejectedRequestStatus(status: RequestStatus): boolean {
  return status === "REJECTED_DUPLICATE" || status === "REJECTED_CONFLICT";
}

interface RequestQueueScreeningResult {
  decision: "allow" | "reject_duplicate" | "reject_conflict";
  reason?: string;
  queuePriority: number;
  dedupeKey: string;
  conflictKey: string;
  source: "heuristic" | "screening_service" | "heuristic+screening_service";
}

interface RequestScreeningServiceDecision {
  decision?: "allow" | "reject_duplicate" | "reject_conflict";
  reason?: string;
  queuePriority?: number;
}

function sanitizeScreeningServiceDecision(value: unknown): RequestScreeningServiceDecision | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  const record = value as Record<string, unknown>;
  const decisionRaw = typeof record.decision === "string" ? record.decision.trim().toLowerCase() : "";
  const decision =
    decisionRaw === "allow" || decisionRaw === "reject_duplicate" || decisionRaw === "reject_conflict"
      ? decisionRaw
      : undefined;
  const reason = typeof record.reason === "string" && record.reason.trim() ? record.reason.trim() : undefined;
  const priorityRaw = Number(record.queuePriority);
  const queuePriority = Number.isFinite(priorityRaw) && priorityRaw >= 1 && priorityRaw <= 1000 ? Math.floor(priorityRaw) : undefined;
  if (!decision && !reason && queuePriority === undefined) {
    return null;
  }
  return {
    decision,
    reason,
    queuePriority
  };
}

async function callRequestScreeningService(input: {
  candidate: MarketRequestInput;
  existing: StoredRequest[];
  dedupeKey: string;
  conflictKey: string;
  provisionalDecision: "allow" | "reject_conflict";
  provisionalReason?: string;
}): Promise<RequestScreeningServiceDecision | null> {
  const url = resolveRequestScreeningServiceUrl();
  if (!url) {
    return null;
  }

  const timeoutController = new AbortController();
  const timeoutId = setTimeout(() => timeoutController.abort(), resolveRequestScreeningServiceTimeoutMs());
  try {
    const headers: Record<string, string> = {
      "Content-Type": "application/json"
    };
    const token = process.env.REQUEST_SCREENING_HTTP_AUTH_TOKEN?.trim();
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }

    const response = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify({
        candidate: input.candidate,
        candidateKeys: {
          dedupeKey: input.dedupeKey,
          conflictKey: input.conflictKey
        },
        existing: input.existing
          .filter((record) => isActiveRequestStatusForScreening(record.status))
          .slice(0, 50)
          .map((record) => ({
            requestId: record.requestId,
            status: record.status,
            question: record.input.question,
            description: record.input.description,
            sourceUrls: record.input.sourceUrls,
            resolutionCriteria: record.input.resolutionCriteria,
            submitterAddress: record.input.submitterAddress,
            dedupeKey: buildRequestDedupeKey(record.input),
            conflictKey: buildRequestConflictKey(record.input)
          })),
        provisionalDecision: input.provisionalDecision,
        provisionalReason: input.provisionalReason
      }),
      signal: timeoutController.signal
    });
    if (!response.ok) {
      return null;
    }
    const parsed = (await response.json()) as unknown;
    return sanitizeScreeningServiceDecision(parsed);
  } catch {
    return null;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function evaluateRequestQueueScreening(input: {
  candidate: MarketRequestInput;
  existing: StoredRequest[];
  selfRequestId?: string;
}): Promise<RequestQueueScreeningResult> {
  const dedupeKey = buildRequestDedupeKey(input.candidate);
  const conflictKey = buildRequestConflictKey(input.candidate);
  const relevantRecords = input.existing.filter(
    (record) => record.requestId !== input.selfRequestId && isActiveRequestStatusForScreening(record.status)
  );

  const duplicate = relevantRecords.find((record) => buildRequestDedupeKey(record.input) === dedupeKey);
  if (duplicate) {
    return {
      decision: "reject_duplicate",
      reason: `duplicate_of_request:${duplicate.requestId}`,
      queuePriority: computeHeuristicQueuePriority(input.candidate),
      dedupeKey,
      conflictKey,
      source: "heuristic"
    };
  }

  const conflicting = relevantRecords.find((record) => {
    const recordConflictKey = buildRequestConflictKey(record.input);
    if (recordConflictKey !== conflictKey) {
      return false;
    }
    const recordDedupeKey = buildRequestDedupeKey(record.input);
    return recordDedupeKey !== dedupeKey;
  });

  const rejectConflictEnabled = resolveRequestRejectConflictEnabled();
  const provisionalDecision: "allow" | "reject_conflict" =
    conflicting && rejectConflictEnabled ? "reject_conflict" : "allow";
  const provisionalReason =
    conflicting && rejectConflictEnabled ? `conflict_with_request:${conflicting.requestId}` : undefined;
  let queuePriority = computeHeuristicQueuePriority(input.candidate);
  let decision: RequestQueueScreeningResult["decision"] = provisionalDecision;
  let reason = provisionalReason;
  let source: RequestQueueScreeningResult["source"] = "heuristic";

  const externalDecision = await callRequestScreeningService({
    candidate: input.candidate,
    existing: relevantRecords,
    dedupeKey,
    conflictKey,
    provisionalDecision,
    provisionalReason
  });
  if (externalDecision) {
    if (externalDecision.queuePriority !== undefined) {
      queuePriority = externalDecision.queuePriority;
    }
    if (
      externalDecision.decision === "allow" ||
      externalDecision.decision === "reject_conflict" ||
      externalDecision.decision === "reject_duplicate"
    ) {
      decision = externalDecision.decision;
    }
    if (externalDecision.reason) {
      reason = externalDecision.reason;
    }
    source = source === "heuristic" ? "heuristic+screening_service" : "screening_service";
  }

  return {
    decision,
    reason,
    queuePriority,
    dedupeKey,
    conflictKey,
    source
  };
}

function sortQueuedRequests(records: StoredRequest[]): StoredRequest[] {
  return [...records].sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

function resolveRequestAutoVerifyEnabled(): boolean {
  return parseBooleanEnv(process.env.REQUEST_AUTO_VERIFY_ENABLED, true);
}

function pickNextQueuedRequest(records: StoredRequest[]): StoredRequest | null {
  const queued = sortQueuedRequests(records.filter((record) => record.status === "PENDING"));
  return queued[0] ?? null;
}

let requestQueueProcessorRunning = false;
let requestQueueProcessorScheduled = false;

function scheduleRequestQueueProcessor(reason: string): void {
  if (!resolveRequestAutoVerifyEnabled()) {
    return;
  }
  if (requestQueueProcessorRunning || requestQueueProcessorScheduled) {
    return;
  }
  requestQueueProcessorScheduled = true;
  setTimeout(() => {
    requestQueueProcessorScheduled = false;
    void processQueuedRequests(reason);
  }, 0);
}

async function processQueuedRequests(reason: string): Promise<void> {
  if (!resolveRequestAutoVerifyEnabled()) {
    return;
  }
  if (requestQueueProcessorRunning) {
    return;
  }

  requestQueueProcessorRunning = true;
  let vectorSyncBlocked = false;
  logServerEvent("info", "request.queue.processor.start", { reason });
  try {
    while (true) {
      const all = await listRequests();
      const queued = pickNextQueuedRequest(all);
      if (!queued) {
        break;
      }

      const fresh = await getRequest(queued.requestId);
      if (!fresh || fresh.status !== "PENDING") {
        continue;
      }
      const traceId = buildRequestRunTraceId(fresh.requestId, fresh.runAttempts + 1);

      const gateReady = await ensureEarlierTerminalVectorSyncApplied(fresh);
      if (!gateReady) {
        vectorSyncBlocked = true;
        logServerFailure("request.queue.processor.blocked_vector_sync", {
          requestId: fresh.requestId,
          traceId
        });
        break;
      }

      const screened = await screenPendingRequestBeforeRun(fresh, traceId);
      if (screened.rejected || screened.record.status !== "PENDING") {
        continue;
      }

      if (!screened.record.paymentReceipt) {
        const failedRecord: StoredRequest = {
          ...screened.record,
          status: "FAILED_ONCHAIN_SUBMISSION",
          updatedAt: nowIso(),
          lastError: "auto_queue_missing_payment_receipt"
        };
        await saveRequest(failedRecord);
        await syncRequestVectorStatus(failedRecord, "queue_missing_payment_receipt");
        logServerFailure("request.queue.processor.failed_missing_payment_receipt", {
          requestId: failedRecord.requestId,
          traceId
        });
        continue;
      }

      const internalReq = new Request(
        `http://internal.local/api/requests/${encodeURIComponent(screened.record.requestId)}/run-verification`,
        { method: "POST" }
      );
      await executeVerificationForRecord(internalReq, screened.record, {
        paymentResource: "/api/requests",
        paymentPrice: resolveRequestVerificationPrice(),
        paymentReceipt: screened.record.paymentReceipt
      });
    }
  } catch (error) {
    logServerFailure("request.queue.processor.exception", {
      error: stringifyError(error)
    });
  } finally {
    requestQueueProcessorRunning = false;
    try {
      const remaining = await listRequests();
      if (remaining.some((record) => record.status === "PENDING")) {
        if (vectorSyncBlocked && resolveRequestVectorSyncBlockOnFailure()) {
          setTimeout(() => {
            scheduleRequestQueueProcessor("vector_sync_retry_after_block");
          }, 10_000);
        } else {
          scheduleRequestQueueProcessor("pending_remaining_after_drain");
        }
      }
    } catch (error) {
      logServerFailure("request.queue.processor.list_remaining_failed", {
        error: stringifyError(error)
      });
    }
  }
}

function resolveNodeRegistrationPrice(): string {
  return process.env.X402_PRICE_NODE_REGISTRATION?.trim() || "$0.01";
}

function resolveNodeLifecycleOnchainEnabled(): boolean {
  return parseBooleanEnv(process.env.NODE_LIFECYCLE_ONCHAIN_ENABLED, false);
}

function resolvePorAutoRecordEnabled(): boolean {
  return parseBooleanEnv(process.env.POR_ONCHAIN_AUTO_RECORD_ENABLED, true);
}

function resolvePorAutoRecordStrict(): boolean {
  return parseBooleanEnv(process.env.POR_ONCHAIN_AUTO_RECORD_STRICT, false);
}

function resolveOnchainReadEnabled(): boolean {
  return parseBooleanEnv(process.env.ONCHAIN_READ_ENABLED, true);
}

function resolveOnchainReadStrict(): boolean {
  return parseBooleanEnv(process.env.ONCHAIN_READ_STRICT, true);
}

function parseBooleanEnv(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (["true", "1", "yes", "y", "on"].includes(normalized)) return true;
  if (["false", "0", "no", "n", "off"].includes(normalized)) return false;
  return fallback;
}

function resolveWalletAuthEnabled(): boolean {
  return parseBooleanEnv(process.env.REQUIRE_WALLET_AUTH_SIGNATURE, true);
}

function resolveWalletAuthMaxAgeMs(): number {
  const raw = process.env.WALLET_AUTH_MAX_AGE_MS?.trim();
  if (!raw) return DEFAULT_WALLET_AUTH_MAX_AGE_MS;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed < 10_000 || parsed > 30 * 60_000) {
    return DEFAULT_WALLET_AUTH_MAX_AGE_MS;
  }
  return parsed;
}

function buildWalletAuthMessage(input: {
  walletAddress: string;
  method: string;
  path: string;
  timestamp: string;
}): string {
  const normalizedWallet = input.walletAddress.trim().toLowerCase();
  return [
    "CRE Wallet Auth v1",
    `wallet: ${normalizedWallet}`,
    `method: ${input.method.toUpperCase()}`,
    `path: ${input.path}`,
    `timestamp: ${input.timestamp}`
  ].join("\n");
}

function normalizeHexSignature(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return "";
  return trimmed.startsWith("0x") ? trimmed : `0x${trimmed}`;
}

function decodeBase64Utf8(value: string): string | null {
  try {
    return Buffer.from(value, "base64").toString("utf8");
  } catch {
    return null;
  }
}

function parseSiweAddress(message: string): string | null {
  const match = message.match(/wants you to sign in with your Ethereum account:\r?\n(0x[a-fA-F0-9]{40})/);
  return match?.[1] ?? null;
}

function parseSiweField(message: string, label: string): string | null {
  const escapedLabel = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = message.match(new RegExp(`^${escapedLabel}:\\s*(.+)$`, "mi"));
  return match?.[1]?.trim() ?? null;
}

function buildEip191PrefixedMessage(message: string): string {
  return `\x19Ethereum Signed Message:\n${message.length}${message}`;
}

function recoverWalletAuthCandidates(message: string, signature: string): string[] {
  const candidates = new Set<string>();
  const addCandidate = (value: string): void => {
    try {
      candidates.add(normalizeAddress(value));
    } catch {
      // Ignore invalid recovered values.
    }
  };

  try {
    addCandidate(verifyMessage(message, signature));
  } catch {
    // ignore
  }
  try {
    addCandidate(verifyMessage(buildEip191PrefixedMessage(message), signature));
  } catch {
    // ignore
  }

  return Array.from(candidates);
}

function resolveRpcUrl(): string | null {
  const value = process.env.RPC_URL?.trim();
  return value && value.length > 0 ? value : null;
}

async function validateEip1271Signature(input: {
  walletAddress: string;
  message: string;
  signature: string;
}): Promise<boolean> {
  const rpcUrl = resolveRpcUrl();
  if (!rpcUrl) {
    return false;
  }

  const provider = new JsonRpcProvider(rpcUrl);
  try {
    const code = await provider.getCode(input.walletAddress);
    if (!code || code === "0x") {
      return false;
    }
  } catch {
    return false;
  }

  const hash = hashMessage(input.message);
  try {
    const result = await provider.call({
      to: input.walletAddress,
      data: EIP1271_INTERFACE.encodeFunctionData("isValidSignature(bytes32,bytes)", [hash, input.signature])
    });
    const [magic] = EIP1271_INTERFACE.decodeFunctionResult("isValidSignature(bytes32,bytes)", result);
    if (typeof magic === "string" && magic.toLowerCase() === EIP1271_MAGIC_VALUE) {
      return true;
    }
  } catch {
    // Try bytes variant below.
  }

  try {
    const result = await provider.call({
      to: input.walletAddress,
      data: EIP1271_INTERFACE.encodeFunctionData("isValidSignature(bytes,bytes)", [
        toUtf8Bytes(input.message),
        input.signature
      ])
    });
    const [magic] = EIP1271_INTERFACE.decodeFunctionResult("isValidSignature(bytes,bytes)", result);
    return typeof magic === "string" && magic.toLowerCase() === EIP1271_MAGIC_VALUE;
  } catch {
    return false;
  }
}

async function validateSafeOwnerSignature(input: { walletAddress: string; ownerAddress: string }): Promise<boolean> {
  const rpcUrl = resolveRpcUrl();
  if (!rpcUrl) {
    return false;
  }

  const provider = new JsonRpcProvider(rpcUrl);
  try {
    const code = await provider.getCode(input.walletAddress);
    if (!code || code === "0x") {
      return false;
    }
  } catch {
    return false;
  }

  try {
    const result = await provider.call({
      to: input.walletAddress,
      data: SAFE_OWNER_INTERFACE.encodeFunctionData("isOwner", [input.ownerAddress])
    });
    const [isOwner] = SAFE_OWNER_INTERFACE.decodeFunctionResult("isOwner", result);
    return isOwner === true;
  } catch {
    return false;
  }
}

async function validateSiweWalletAuth(input: {
  expectedWalletAddress: string;
  message: string;
  signature: string;
  declaredAddress?: string;
  expectedNonce: string;
  expectedRequestId: string;
  siweVersion?: number;
}): Promise<{ ok: true } | { ok: false; detail: string }> {
  const siweAddressRaw = parseSiweAddress(input.message);
  if (!siweAddressRaw) {
    return { ok: false, detail: "siwe_address_missing" };
  }

  let normalizedSiweAddress: string;
  try {
    normalizedSiweAddress = normalizeAddress(siweAddressRaw);
  } catch (error) {
    return {
      ok: false,
      detail: `siwe_address_invalid: ${error instanceof Error ? error.message : String(error)}`
    };
  }

  if (normalizedSiweAddress !== input.expectedWalletAddress) {
    return {
      ok: false,
      detail: `siwe_address_mismatch: expected=${input.expectedWalletAddress}, siwe=${normalizedSiweAddress}`
    };
  }

  if (input.declaredAddress) {
    try {
      const normalizedDeclaredAddress = normalizeAddress(input.declaredAddress);
      if (normalizedDeclaredAddress !== normalizedSiweAddress) {
        return {
          ok: false,
          detail: `siwe_declared_address_mismatch: declared=${normalizedDeclaredAddress}, siwe=${normalizedSiweAddress}`
        };
      }
    } catch (error) {
      return {
        ok: false,
        detail: `siwe_declared_address_invalid: ${error instanceof Error ? error.message : String(error)}`
      };
    }
  }

  const siweNonce = parseSiweField(input.message, "Nonce");
  if (!siweNonce || siweNonce !== input.expectedNonce) {
    return {
      ok: false,
      detail: `siwe_nonce_mismatch: expected=${input.expectedNonce}, got=${siweNonce ?? "missing"}`
    };
  }

  const siweRequestId = parseSiweField(input.message, "Request ID");
  if (siweRequestId && siweRequestId !== input.expectedRequestId) {
    return {
      ok: false,
      detail: `siwe_request_id_mismatch: expected=${input.expectedRequestId}, got=${siweRequestId}`
    };
  }

  const siweIssuedAt = parseSiweField(input.message, "Issued At");
  if (siweIssuedAt) {
    const issuedAtMs = Date.parse(siweIssuedAt);
    if (!Number.isFinite(issuedAtMs)) {
      return {
        ok: false,
        detail: `siwe_issued_at_invalid: ${siweIssuedAt}`
      };
    }
    if (Math.abs(Date.now() - issuedAtMs) > resolveWalletAuthMaxAgeMs()) {
      return {
        ok: false,
        detail: "siwe_issued_at_expired"
      };
    }
  }

  const recoveredCandidates = recoverWalletAuthCandidates(input.message, input.signature);
  if (recoveredCandidates.includes(normalizedSiweAddress)) {
    return { ok: true };
  }

  let safeOwnerRecovered: string | null = null;
  for (const recovered of recoveredCandidates) {
    const isOwner = await validateSafeOwnerSignature({
      walletAddress: normalizedSiweAddress,
      ownerAddress: recovered
    });
    if (isOwner) {
      safeOwnerRecovered = recovered;
      break;
    }
  }
  const safeOwnerValid = safeOwnerRecovered !== null;
  if (safeOwnerValid) {
    return { ok: true };
  }

  const eip1271Valid = await validateEip1271Signature({
    walletAddress: normalizedSiweAddress,
    message: input.message,
    signature: input.signature
  });
  if (eip1271Valid) {
    return { ok: true };
  }

  const recoveredDetail = recoveredCandidates.length > 0 ? recoveredCandidates.join(",") : "none";
  return {
    ok: false,
    detail: `siwe_signature_mismatch: expected=${normalizedSiweAddress}, recovered=${recoveredDetail}, eip1271=${eip1271Valid}, safeOwner=${safeOwnerValid}, version=${input.siweVersion ?? "unknown"}`
  };
}

async function requireWalletRequestAuth(
  req: Request,
  expectedWalletAddress: string
): Promise<{ ok: true } | { ok: false; status: number; error: string; detail?: string }> {
  const headerWalletRaw = req.headers.get("x-wallet-address")?.trim() ?? "";
  if (!headerWalletRaw) {
    return {
      ok: false,
      status: 401,
      error: "wallet_header_missing",
      detail: "x-wallet-address header is required."
    };
  }

  let normalizedHeaderWallet: string;
  let normalizedExpectedWallet: string;
  try {
    normalizedHeaderWallet = normalizeAddress(headerWalletRaw);
    normalizedExpectedWallet = normalizeAddress(expectedWalletAddress);
  } catch (error) {
    return {
      ok: false,
      status: 400,
      error: "invalid_wallet_address",
      detail: error instanceof Error ? error.message : String(error)
    };
  }

  if (normalizedHeaderWallet !== normalizedExpectedWallet) {
    return {
      ok: false,
      status: 400,
      error: "wallet_header_mismatch",
      detail: "x-wallet-address must match walletAddress in request."
    };
  }

  if (!resolveWalletAuthEnabled()) {
    return { ok: true };
  }

  const timestampRaw = req.headers.get(WALLET_AUTH_TIMESTAMP_HEADER)?.trim() ?? "";
  if (!timestampRaw) {
    return {
      ok: false,
      status: 401,
      error: "wallet_auth_signature_required",
      detail: `set ${WALLET_AUTH_TIMESTAMP_HEADER} header`
    };
  }

  const timestamp = Number.parseInt(timestampRaw, 10);
  if (!Number.isInteger(timestamp)) {
    return {
      ok: false,
      status: 400,
      error: "wallet_auth_timestamp_invalid"
    };
  }

  if (Math.abs(Date.now() - timestamp) > resolveWalletAuthMaxAgeMs()) {
    return {
      ok: false,
      status: 401,
      error: "wallet_auth_expired",
      detail: "wallet auth signature is outside the allowed time window."
    };
  }

  const path = new URL(req.url).pathname;
  const siweMessageEncoded = req.headers.get(WALLET_AUTH_SIWE_MESSAGE_HEADER)?.trim() ?? "";
  const siweSignatureRaw = req.headers.get(WALLET_AUTH_SIWE_SIGNATURE_HEADER)?.trim() ?? "";
  const hasSiweAuth = Boolean(siweMessageEncoded || siweSignatureRaw);
  if (hasSiweAuth) {
    if (!siweMessageEncoded || !siweSignatureRaw) {
      return {
        ok: false,
        status: 401,
        error: "wallet_auth_siwe_required",
        detail: `set ${WALLET_AUTH_SIWE_MESSAGE_HEADER} and ${WALLET_AUTH_SIWE_SIGNATURE_HEADER} headers`
      };
    }
    const siweMessage = decodeBase64Utf8(siweMessageEncoded);
    if (!siweMessage || !siweMessage.trim()) {
      return {
        ok: false,
        status: 400,
        error: "wallet_auth_siwe_message_invalid"
      };
    }
    const siweSignature = normalizeHexSignature(siweSignatureRaw);
    if (!siweSignature) {
      return {
        ok: false,
        status: 400,
        error: "wallet_auth_siwe_signature_invalid"
      };
    }
    const expectedRequestId = `${req.method.toUpperCase()}:${path}`;
    const headerRequestId = req.headers.get(WALLET_AUTH_SIWE_REQUEST_ID_HEADER)?.trim() ?? "";
    const siweVersionRaw = req.headers.get(WALLET_AUTH_SIWE_VERSION_HEADER)?.trim() ?? "";
    const parsedSiweVersion = siweVersionRaw ? Number.parseInt(siweVersionRaw, 10) : Number.NaN;
    const siweVersion = Number.isInteger(parsedSiweVersion) && parsedSiweVersion > 0 ? parsedSiweVersion : undefined;
    if (headerRequestId && headerRequestId !== expectedRequestId) {
      return {
        ok: false,
        status: 401,
        error: "wallet_auth_siwe_request_id_mismatch",
        detail: `expected=${expectedRequestId}, got=${headerRequestId}`
      };
    }
    const siweValidation = await validateSiweWalletAuth({
      expectedWalletAddress: normalizedExpectedWallet,
      message: siweMessage,
      signature: siweSignature,
      declaredAddress: req.headers.get(WALLET_AUTH_SIWE_ADDRESS_HEADER)?.trim() ?? undefined,
      expectedNonce: timestampRaw,
      expectedRequestId,
      siweVersion
    });
    if (!siweValidation.ok) {
      return {
        ok: false,
        status: 401,
        error: "wallet_auth_siwe_invalid",
        detail: siweValidation.detail
      };
    }
    return { ok: true };
  }

  const signatureRaw = req.headers.get(WALLET_AUTH_SIGNATURE_HEADER)?.trim() ?? "";
  if (!signatureRaw) {
    return {
      ok: false,
      status: 401,
      error: "wallet_auth_signature_required",
      detail: `set ${WALLET_AUTH_SIGNATURE_HEADER} header`
    };
  }
  const signature = normalizeHexSignature(signatureRaw);
  if (!signature) {
    return {
      ok: false,
      status: 400,
      error: "wallet_auth_signature_invalid"
    };
  }

  const message = buildWalletAuthMessage({
    walletAddress: normalizedExpectedWallet,
    method: req.method,
    path,
    timestamp: String(timestamp)
  });

  let recovered: string;
  try {
    recovered = normalizeAddress(verifyMessage(message, signature));
  } catch {
    return {
      ok: false,
      status: 401,
      error: "wallet_auth_signature_invalid"
    };
  }

  if (recovered !== normalizedExpectedWallet) {
    const eip1271Valid = await validateEip1271Signature({
      walletAddress: normalizedExpectedWallet,
      message,
      signature
    });
    const safeOwnerValid = !eip1271Valid
      ? await validateSafeOwnerSignature({
          walletAddress: normalizedExpectedWallet,
          ownerAddress: recovered
        })
      : false;
    if (!eip1271Valid && !safeOwnerValid) {
      return {
        ok: false,
        status: 401,
        error: "wallet_auth_signature_mismatch",
        detail: `expected=${normalizedExpectedWallet}, recovered=${recovered}, eip1271=${eip1271Valid}, safeOwner=${safeOwnerValid}`
      };
    }
  }

  return { ok: true };
}

function resolveHeartbeatTtlSeconds(): number | undefined {
  const raw = process.env.NODE_HEARTBEAT_TTL_SECONDS?.trim();
  if (!raw) return undefined;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed < 30 || parsed > 86_400) {
    return undefined;
  }
  return parsed;
}

function resolveDistributedDonMode(): boolean {
  const fallback = process.env.USE_DON_SIGNED_REPORTS === "true" && process.env.NODE_ENDPOINT_VERIFY_ENABLED === "true";
  return parseBooleanEnv(process.env.DON_DISTRIBUTED_MODE, fallback);
}

function resolveRealRuntimeOnlyEnabled(): boolean {
  return parseBooleanEnv(process.env.REAL_RUNTIME_ONLY, true);
}

function resolveRequireRegisteredNodesForRuntime(distributedDonMode: boolean): boolean {
  return parseBooleanEnv(process.env.REQUIRE_REGISTERED_NODES, distributedDonMode);
}

function resolveNodeEndpointVerifyEnabledForRuntime(): boolean {
  return parseBooleanEnv(process.env.NODE_ENDPOINT_VERIFY_ENABLED, false);
}

function assertRealRuntimeGuard(input: {
  distributedDonMode: boolean;
  requireRegisteredNodes: boolean;
  requireEndpointUrl: boolean;
  requireHealthyEndpoint: boolean;
}): { ok: true } | { ok: false; reason: string } {
  if (!resolveRealRuntimeOnlyEnabled()) {
    return { ok: true };
  }

  if (!resolveNodeEndpointVerifyEnabledForRuntime()) {
    return { ok: false, reason: "NODE_ENDPOINT_VERIFY_ENABLED must be true when REAL_RUNTIME_ONLY=true." };
  }
  if (!input.distributedDonMode) {
    return { ok: false, reason: "DON_DISTRIBUTED_MODE must be true when REAL_RUNTIME_ONLY=true." };
  }
  if (!input.requireRegisteredNodes) {
    return { ok: false, reason: "REQUIRE_REGISTERED_NODES must be true when REAL_RUNTIME_ONLY=true." };
  }
  if (!input.requireEndpointUrl) {
    return { ok: false, reason: "REQUIRE_NODE_ENDPOINT_URL must be true when REAL_RUNTIME_ONLY=true." };
  }
  if (!input.requireHealthyEndpoint) {
    return { ok: false, reason: "REQUIRE_HEALTHY_NODE_ENDPOINTS must be true when REAL_RUNTIME_ONLY=true." };
  }

  return { ok: true };
}

function collectRequiredEnv(issues: string[], key: string): string {
  const value = process.env[key]?.trim() ?? "";
  if (!value) {
    issues.push(`${key} is required`);
  }
  return value;
}

function validatePositiveIntegerEnv(issues: string[], key: string): void {
  const value = process.env[key]?.trim() ?? "";
  if (!value) {
    issues.push(`${key} is required`);
    return;
  }
  const parsed = Number.parseInt(value, 10);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    issues.push(`${key} must be a positive integer`);
  }
}

function validateAddressEnv(issues: string[], key: string): void {
  const value = collectRequiredEnv(issues, key);
  if (!value) {
    return;
  }
  try {
    getAddress(value);
  } catch {
    issues.push(`${key} must be a valid EVM address`);
  }
}

function validateOptionalAddressEnv(issues: string[], key: string, value: string): void {
  if (!value) {
    return;
  }
  try {
    getAddress(value);
  } catch {
    issues.push(`${key} must be a valid EVM address`);
  }
}

function assertStartupConfigOrThrow(): void {
  if (STARTUP_SKIP_ENV_VALIDATION) {
    logServerEvent("warn", "startup.config.validation_skipped", {
      reason: "SKIP_STARTUP_ENV_VALIDATION=true"
    });
    return;
  }

  const issues: string[] = [];

  if (!Number.isInteger(PORT) || PORT <= 0 || PORT > 65535) {
    issues.push("PORT must be an integer between 1 and 65535");
  }

  const worldIdProfilesRaw = process.env.WORLD_ID_ALLOWED_PROFILES_JSON?.trim() ?? "";
  if (!worldIdProfilesRaw) {
    collectRequiredEnv(issues, "WORLD_ID_APP_ID");
    collectRequiredEnv(issues, "WORLD_ID_ACTION");
  } else {
    try {
      const parsed = JSON.parse(worldIdProfilesRaw);
      if (!Array.isArray(parsed) || parsed.length === 0) {
        issues.push("WORLD_ID_ALLOWED_PROFILES_JSON must be a non-empty JSON array");
      }
    } catch {
      issues.push("WORLD_ID_ALLOWED_PROFILES_JSON must be valid JSON");
    }
  }
  collectRequiredEnv(issues, "WORLD_ID_RP_ID");
  collectRequiredEnv(issues, "RPC_URL");
  validatePositiveIntegerEnv(issues, "CHAIN_ID");
  validateAddressEnv(issues, "CONTRACT_ADDRESS");

  const coordinatorPrivateKey = collectRequiredEnv(issues, "COORDINATOR_PRIVATE_KEY");
  if (coordinatorPrivateKey && !/^0x[0-9a-fA-F]{64}$/.test(coordinatorPrivateKey)) {
    issues.push("COORDINATOR_PRIVATE_KEY must be a 32-byte hex private key (0x...)");
  }

  const distributedDonMode = resolveDistributedDonMode();
  const requireRegisteredNodes = resolveRequireRegisteredNodesForRuntime(distributedDonMode);
  const requireEndpointUrl = parseBooleanEnv(process.env.REQUIRE_NODE_ENDPOINT_URL, distributedDonMode);
  const requireHealthyEndpoint = parseBooleanEnv(process.env.REQUIRE_HEALTHY_NODE_ENDPOINTS, distributedDonMode);
  const runtimeGuard = assertRealRuntimeGuard({
    distributedDonMode,
    requireRegisteredNodes,
    requireEndpointUrl,
    requireHealthyEndpoint
  });
  if (!runtimeGuard.ok) {
    issues.push(runtimeGuard.reason);
  }

  const signedReportsEnabled = parseBooleanEnv(process.env.USE_DON_SIGNED_REPORTS, false);
  if (signedReportsEnabled || distributedDonMode) {
    const verifierAddress = process.env.DON_VERIFIER_CONTRACT?.trim() || process.env.CONTRACT_ADDRESS?.trim() || "";
    if (!verifierAddress) {
      issues.push("DON_VERIFIER_CONTRACT (or CONTRACT_ADDRESS) is required when DON signing is enabled");
    } else {
      validateOptionalAddressEnv(issues, "DON_VERIFIER_CONTRACT", verifierAddress);
    }
    collectRequiredEnv(issues, "DON_DOMAIN_NAME");
    collectRequiredEnv(issues, "DON_DOMAIN_VERSION");
  }

  if (issues.length > 0) {
    throw new Error(`startup_config_invalid: ${issues.join(" | ")}`);
  }

  logServerEvent("info", "startup.config.validated", {
    realRuntimeOnly: resolveRealRuntimeOnlyEnabled(),
    distributedDonMode,
    signedReportsEnabled,
    requireRegisteredNodes,
    requireEndpointUrl,
    requireHealthyEndpoint
  });
}

async function requireWorldIdForWallet(
  req: Request,
  walletAddress: string,
  options?: { consumeToken?: boolean }
): Promise<{ ok: true } | { ok: false; status: number; error: string; detail?: string }> {
  const token = req.headers.get("x-world-id-token")?.trim() ?? "";
  if (!token) {
    return {
      ok: false,
      status: 403,
      error: "world_id_token_required",
      detail: "Verify with World ID first and resend with x-world-id-token header."
    };
  }

  const validation = options?.consumeToken
    ? await consumeWorldIdSessionToken({
        token,
        walletAddress
      })
    : await validateWorldIdSessionToken({
        token,
        walletAddress
      });
  if (!validation.ok) {
    return {
      ok: false,
      status: 403,
      error: "world_id_token_invalid",
      detail: validation.reason
    };
  }

  return { ok: true };
}

function normalizeAddress(value: string): string {
  return getAddress(value).toLowerCase();
}

function tryNormalizeAddress(value: string): string | null {
  try {
    return normalizeAddress(value);
  } catch {
    return null;
  }
}

function normalizeFamilyList(values: string[] | undefined): string[] {
  if (!Array.isArray(values)) {
    return [];
  }
  return Array.from(
    new Set(
      values
        .map((value) => value.trim().toLowerCase())
        .filter((value) => value === "gpt" || value === "gemini" || value === "claude" || value === "grok")
    )
  );
}

function resolveAutoModelName(walletAddress: string, selectedModelFamilies: string[], provided?: string): string {
  if (provided && provided.trim()) {
    return provided.trim();
  }
  const prefix = process.env.NODE_DEFAULT_MODEL_NAME_PREFIX?.trim() || "operator";
  const familyPart = selectedModelFamilies.length > 0 ? selectedModelFamilies.join("-") : "generic";
  const walletPart = walletAddress.slice(2, 8).toLowerCase();
  return `${prefix}-${familyPart}-${walletPart}`;
}

function parseNodeEndpointMap(): Record<string, string> {
  const raw = process.env.NODE_ENDPOINT_URL_MAP_JSON?.trim();
  if (!raw) {
    return {};
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return {};
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return {};
  }

  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
    if (typeof value !== "string") continue;
    const normalized = tryNormalizeAddress(key);
    if (!normalized) continue;
    result[normalized] = value.trim();
  }
  return result;
}

function parseNodeEndpointByFamilyMap(): Record<string, string> {
  const raw = process.env.NODE_ENDPOINT_URL_BY_FAMILY_JSON?.trim();
  if (!raw) {
    return {};
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return {};
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return {};
  }

  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
    if (typeof value !== "string") continue;
    const family = key.trim().toLowerCase();
    if (family !== "gpt" && family !== "gemini" && family !== "claude" && family !== "grok") {
      continue;
    }
    result[family] = value.trim();
  }

  return result;
}

function resolveAutoEndpointUrl(walletAddress: string, selectedModelFamilies: string[], provided?: string): string | undefined {
  if (provided && provided.trim()) {
    return provided.trim();
  }

  const map = parseNodeEndpointMap();
  const mapped = map[walletAddress];
  if (mapped) {
    return mapped;
  }

  const familyMap = parseNodeEndpointByFamilyMap();
  for (const family of selectedModelFamilies) {
    const byFamily = familyMap[family];
    if (byFamily) {
      return byFamily;
    }
  }

  const fallback = process.env.NODE_DEFAULT_ENDPOINT_URL?.trim();
  if (fallback) {
    return fallback;
  }

  return undefined;
}

function buildNodeHeartbeatMessage(input: { walletAddress: string; endpointUrl: string; timestamp: number }): string {
  return [
    "CRE Node Heartbeat",
    `walletAddress: ${input.walletAddress}`,
    `endpointUrl: ${input.endpointUrl}`,
    `timestamp: ${input.timestamp}`
  ].join("\n");
}

async function handleGetRequest(requestId: string): Promise<Response> {
  if (resolveOnchainReadEnabled()) {
    try {
      const onchainRecord = await getRequestFromOnchain(requestId);
      if (onchainRecord) {
        return jsonResponse({
          ok: true,
          data: buildRequestResponse(onchainRecord)
        });
      }
    } catch (error) {
      if (resolveOnchainReadStrict()) {
        return jsonResponse(
          {
            ok: false,
            error: "onchain_read_failed",
            detail: error instanceof Error ? error.message : String(error)
          },
          502
        );
      }
    }
  }

  const record = await getRequest(requestId);
  if (!record) {
    return jsonResponse({ ok: false, error: "request_not_found" }, 404);
  }

  return jsonResponse({
    ok: true,
    data: buildRequestResponse(record)
  });
}

async function screenPendingRequestBeforeRun(
  existing: StoredRequest,
  traceId?: string
): Promise<{ record: StoredRequest; rejected: boolean }> {
  if (existing.status !== "PENDING") {
    return { record: existing, rejected: false };
  }

  const screening = await evaluateRequestQueueScreening({
    candidate: existing.input,
    existing: await listRequests(),
    selfRequestId: existing.requestId
  });
  const now = nowIso();
  const screenedRecord: StoredRequest = {
    ...existing,
    queuePriority: screening.queuePriority,
    queueDecision: {
      ...screening,
      evaluatedAt: now
    },
    updatedAt: now
  };

  if (screening.decision === "reject_duplicate" || screening.decision === "reject_conflict") {
    const rejectedStatus: RequestStatus =
      screening.decision === "reject_duplicate" ? "REJECTED_DUPLICATE" : "REJECTED_CONFLICT";
    const rejectedRecord: StoredRequest = {
      ...screenedRecord,
      status: rejectedStatus,
      lastError: screening.reason ?? screening.decision
    };
    await saveRequest(rejectedRecord);
    await syncRequestVectorStatus(rejectedRecord, "screening_rejected_before_verify");
    if (traceId) {
      logServerFailure("request.run.screening_rejected", {
        traceId,
        requestId: rejectedRecord.requestId,
        status: rejectedRecord.status,
        reason: rejectedRecord.lastError
      });
    }
    return { record: rejectedRecord, rejected: true };
  }

  await saveRequest(screenedRecord);
  return { record: screenedRecord, rejected: false };
}

async function executeVerificationForRecord(
  req: Request,
  existing: StoredRequest,
  options?: {
    paymentResource?: string;
    paymentPrice?: string;
    paymentReceipt?: StoredRequest["paymentReceipt"];
  }
): Promise<Response> {
  const latest = await getRequest(existing.requestId);
  const current = latest ?? existing;

  if (current.runAttempts >= MAX_RUN_ATTEMPTS) {
    return jsonResponse(
      {
        ok: false,
        error: "max_attempts_exceeded",
        maxAttempts: MAX_RUN_ATTEMPTS
      },
      409
    );
  }

  if (current.status === "FINALIZED") {
    return jsonResponse({ ok: false, error: "already_finalized" }, 409);
  }

  if (current.status === "RUNNING") {
    return jsonResponse({ ok: false, error: "request_already_running" }, 409);
  }

  const requestId = current.requestId;
  const runAttempt = current.runAttempts + 1;
  const traceId = buildRequestRunTraceId(requestId, runAttempt);
  logServerEvent("info", "request.run.start", {
    traceId,
    requestId,
    runAttempt,
    submitterAddress: current.input.submitterAddress
  });

  const paymentResult =
    options?.paymentReceipt !== undefined
      ? {
          ok: true,
          receipt: options.paymentReceipt
        }
      : await enforceX402Payment(req, {
          resource: options?.paymentResource ?? `/api/requests/${requestId}/run-verification`,
          price: options?.paymentPrice ?? resolveRequestVerificationPrice(),
          walletAddress: current.input.submitterAddress
        });

  if (!paymentResult.ok || !paymentResult.receipt) {
    logServerFailure("request.run.payment_failed", {
      traceId,
      requestId,
      runAttempt
    });
    return paymentResult.response ?? jsonResponse({ ok: false, error: "payment_failed" }, 402);
  }

  const distributedDonMode = resolveDistributedDonMode();
  const minNodeStake = process.env.MIN_NODE_STAKE?.trim() || "0";
  const requireRegisteredNodes = resolveRequireRegisteredNodesForRuntime(distributedDonMode);
  const refreshHealthBeforeMatch = parseBooleanEnv(process.env.NODE_REFRESH_HEALTH_BEFORE_MATCH, false);
  const requireEndpointUrl = parseBooleanEnv(process.env.REQUIRE_NODE_ENDPOINT_URL, distributedDonMode);
  const requireHealthyEndpoint = parseBooleanEnv(process.env.REQUIRE_HEALTHY_NODE_ENDPOINTS, distributedDonMode);
  const heartbeatTtlSeconds = resolveHeartbeatTtlSeconds();
  const realRuntimeGuard = assertRealRuntimeGuard({
    distributedDonMode,
    requireRegisteredNodes,
    requireEndpointUrl,
    requireHealthyEndpoint
  });
  if (!realRuntimeGuard.ok) {
    logServerFailure("request.run.runtime_config_invalid", {
      traceId,
      requestId,
      runAttempt,
      detail: realRuntimeGuard.reason
    });
    return jsonResponse(
      {
        ok: false,
        error: "runtime_config_invalid",
        detail: realRuntimeGuard.reason
      },
      500
    );
  }

  const nodesSource = refreshHealthBeforeMatch
    ? await refreshNodeEndpointHealth()
    : await listRegisteredNodes({ status: "ACTIVE" });
  const activeNodes = nodesSource.filter((node) => node.status === "ACTIVE");
  const match = selectRuntimeNodesForRequest(activeNodes, {
    desiredNodes: 4,
    minStakeAmount: minNodeStake,
    requireEndpointUrl,
    requireHealthyEndpoint,
    heartbeatTtlSeconds
  });

  if (requireRegisteredNodes && match.selectedNodes.length < 3) {
    const failedRecord: StoredRequest = {
      ...current,
      runAttempts: runAttempt,
      status: "FAILED_NO_QUORUM",
      activeNodes: match.selectedNodes,
      paymentReceipt: paymentResult.receipt,
      workflowStepLogs: undefined,
      updatedAt: nowIso(),
      lastError: "insufficient_registered_nodes"
    };

    await saveRequest(failedRecord);
    await syncRequestVectorStatus(failedRecord, "verification_failed_insufficient_registered_nodes");
    logServerFailure("request.run.failed", {
      traceId,
      requestId,
      status: failedRecord.status,
      reason: failedRecord.lastError,
      selectedNodes: match.selectedNodes.length
    });

    return jsonResponse(
      {
        ok: false,
        error: "insufficient_registered_nodes",
        detail: "at least 3 ACTIVE/eligible registered nodes are required",
        traceId,
        data: buildRequestResponse(failedRecord)
      },
      409
    );
  }

  if (match.runtimeNodes.length < 3) {
    const failedRecord: StoredRequest = {
      ...current,
      runAttempts: runAttempt,
      status: "FAILED_NO_QUORUM",
      activeNodes: match.selectedNodes,
      paymentReceipt: paymentResult.receipt,
      workflowStepLogs: undefined,
      updatedAt: nowIso(),
      lastError: "insufficient_runtime_nodes"
    };
    await saveRequest(failedRecord);
    await syncRequestVectorStatus(failedRecord, "verification_failed_insufficient_runtime_nodes");
    logServerFailure("request.run.failed", {
      traceId,
      requestId,
      status: failedRecord.status,
      reason: failedRecord.lastError,
      selectedNodes: match.selectedNodes.length,
      runtimeNodes: match.runtimeNodes.length
    });

    return jsonResponse(
      {
        ok: false,
        error: "insufficient_runtime_nodes",
        detail: "matched runtime nodes are fewer than quorum (3)",
        traceId
      },
      409
    );
  }

  const runningRecord: StoredRequest = {
    ...current,
    runAttempts: runAttempt,
    status: "RUNNING",
    activeNodes: match.selectedNodes,
    paymentReceipt: paymentResult.receipt,
    workflowStepLogs: undefined,
    updatedAt: nowIso(),
    lastError: undefined
  };

  await saveRequest(runningRecord);
  void syncRequestVectorStatus(runningRecord, "verification_started").catch((error) => {
    logServerFailure("request.vector_sync.background_failed", {
      requestId: runningRecord.requestId,
      requestStatus: runningRecord.status,
      trigger: "verification_started",
      error: stringifyError(error)
    });
  });
  logServerEvent("info", "request.run.matched_nodes", {
    traceId,
    requestId,
    runAttempt,
    selectedNodes: match.selectedNodes.length,
    runtimeNodes: match.runtimeNodes.length,
    usedDefaultNodes: match.usedDefaultNodes
  });

  try {
    const workflow = await runCreWorkflow({
      requestId,
      input: current.input,
      activeNodes: match.selectedNodes,
      runtimeNodes: match.runtimeNodes,
      usedDefaultNodes: match.usedDefaultNodes,
      paymentReceipt: paymentResult.receipt,
      submitOnchain: submitConsensusOnchain
    });

    const finalStatus: RequestStatus = workflow.finalStatus;
    let porOnchainReceipt: OnchainReceipt | undefined;
    let porOnchainError: string | undefined;

    if (finalStatus === "FINALIZED" && resolvePorAutoRecordEnabled()) {
      try {
        const nextPorProof = await buildNextPorProofInput({
          requestId,
          verificationTxHash: workflow.onchainReceipt?.txHash
        });
        porOnchainReceipt = await submitPorProofOnchain(nextPorProof);
      } catch (error) {
        porOnchainError = error instanceof Error ? error.message : String(error);
        if (resolvePorAutoRecordStrict()) {
          throw error;
        }
      }
    }

    const finalized: StoredRequest = {
      ...runningRecord,
      status: finalStatus,
      nodeReports: workflow.nodeReports,
      signedNodeReports: workflow.signedNodeReports,
      executionReceipts: workflow.executionReceipts,
      quorumValidation: workflow.quorumValidation,
      consensus: workflow.consensus,
      consensusBundle: workflow.consensusBundle,
      onchainReceipt: workflow.onchainReceipt,
      activeNodes: match.selectedNodes,
      paymentReceipt: paymentResult.receipt,
      workflowStepLogs: workflow.stepLogs,
      updatedAt: nowIso(),
      lastError: finalStatus === "FAILED_ONCHAIN_SUBMISSION" ? "onchain submission failed" : undefined
    };

    await saveRequest(finalized);
    const finalizedWithVectorSync = await syncRequestVectorStatus(finalized, "verification_completed");
    if (finalStatus !== "FINALIZED") {
      logServerFailure("request.run.failed", {
        traceId,
        requestId,
        status: finalStatus,
        reason: finalizedWithVectorSync.lastError ?? "workflow_non_finalized"
      });
    }

    return jsonResponse({
      ok: true,
      data: {
        ...buildRequestResponse(finalizedWithVectorSync),
        traceId,
        workflow: {
          traceId,
          artifactDir: workflow.artifactDir,
          reportPath: workflow.reportPath,
          stepLogs: workflow.stepLogs,
          quorumValidation: workflow.quorumValidation,
          consensusBundle: workflow.consensusBundle,
          externalCreOutput: workflow.externalCreOutput,
          porOnchainReceipt,
          porOnchainError
        }
      }
    });
  } catch (error) {
    const errorMessage = stringifyError(error);
    logServerFailure("request.run.exception", {
      traceId,
      requestId,
      error: errorMessage
    });
    const failed: StoredRequest = {
      ...runningRecord,
      status: "FAILED_ONCHAIN_SUBMISSION",
      activeNodes: match.selectedNodes,
      paymentReceipt: paymentResult.receipt,
      updatedAt: nowIso(),
      lastError: errorMessage
    };
    await saveRequest(failed);
    const failedWithVectorSync = await syncRequestVectorStatus(failed, "verification_exception");

    return jsonResponse(
      {
        ok: false,
        error: "verification_failed",
        detail: errorMessage,
        traceId
      },
      500
    );
  }
}

async function handleCreateRequest(req: Request): Promise<Response> {
  try {
    const body = await parseJsonBody<MarketRequestInput>(req);
    const validated = await validateMarketRequest(body);

    const walletAuth = await requireWalletRequestAuth(req, validated.submitterAddress);
    if (!walletAuth.ok) {
      return jsonResponse(
        {
          ok: false,
          error: walletAuth.error,
          detail: walletAuth.detail
        },
        walletAuth.status
      );
    }

    if (resolveRequestRequireWorldIdOnCreate()) {
      const worldIdConsumeAuth = await requireWorldIdForWallet(req, validated.submitterAddress, { consumeToken: true });
      if (!worldIdConsumeAuth.ok) {
        return jsonResponse(
          {
            ok: false,
            error: worldIdConsumeAuth.error,
            detail: worldIdConsumeAuth.detail
          },
          worldIdConsumeAuth.status
        );
      }
    }

    const timestamp = nowIso();
    const screening = await evaluateRequestQueueScreening({
      candidate: validated,
      existing: await listRequests()
    });
    let status: RequestStatus = "PENDING";
    if (screening.decision === "reject_duplicate") {
      status = "REJECTED_DUPLICATE";
    } else if (screening.decision === "reject_conflict") {
      status = "REJECTED_CONFLICT";
    }
    const rejectedReason = screening.reason ?? screening.decision;
    let paymentReceipt: StoredRequest["paymentReceipt"] | undefined;
    if (status === "PENDING") {
      const paymentResult = await enforceX402Payment(req, {
        resource: "/api/requests",
        price: resolveRequestVerificationPrice(),
        walletAddress: validated.submitterAddress
      });
      if (!paymentResult.ok || !paymentResult.receipt) {
        return paymentResult.response ?? jsonResponse({ ok: false, error: "payment_failed" }, 402);
      }
      paymentReceipt = paymentResult.receipt;
    }

    const record: StoredRequest = {
      requestId: generateRequestId(),
      input: validated,
      createdAt: timestamp,
      updatedAt: timestamp,
      status,
      vectorSync: resolveRequestVectorSyncEnabled()
        ? {
            state: "PENDING",
            vectorStatus: mapRequestStatusToVectorStatus(status),
            attempts: 0,
            updatedAt: timestamp
          }
        : undefined,
      queuePriority: screening.queuePriority,
      queueDecision: {
        ...screening,
        evaluatedAt: timestamp
      },
      runAttempts: 0,
      paymentReceipt,
      lastError:
        status === "REJECTED_DUPLICATE" || status === "REJECTED_CONFLICT"
          ? rejectedReason
          : undefined
    };

    await saveRequest(record);
    void syncRequestVectorStatus(record, "request_created").catch((error) => {
      logServerFailure("request.vector_sync.background_failed", {
        requestId: record.requestId,
        requestStatus: record.status,
        trigger: "request_created",
        error: stringifyError(error)
      });
    });
    if (record.status === "PENDING") {
      scheduleRequestQueueProcessor("request_created");
    }

    return jsonResponse(
      {
        ok: true,
        data: buildRequestResponse(record)
      },
      201
    );
  } catch (error) {
    if (error instanceof ValidationError) {
      return jsonResponse(
        {
          ok: false,
          error: "validation_failed",
          issues: error.issues
        },
        400
      );
    }

    return jsonResponse(
      {
        ok: false,
        error: error instanceof Error ? error.message : String(error)
      },
      400
    );
  }
}

async function handleRunVerification(req: Request, requestId: string): Promise<Response> {
  let existing = await getRequest(requestId);
  if (!existing) {
    return jsonResponse({ ok: false, error: "request_not_found" }, 404);
  }

  if (isRejectedRequestStatus(existing.status)) {
    return jsonResponse(
      {
        ok: false,
        error: "request_rejected",
        detail: existing.lastError ?? existing.status,
        data: buildRequestResponse(existing)
      },
      409
    );
  }

  const traceId = buildRequestRunTraceId(requestId, existing.runAttempts + 1);

  const walletAuth = await requireWalletRequestAuth(req, existing.input.submitterAddress);
  if (!walletAuth.ok) {
    return jsonResponse(
      {
        ok: false,
        error: walletAuth.error,
        detail: walletAuth.detail
      },
      walletAuth.status
    );
  }

  if (existing.status === "PENDING") {
    const screened = await screenPendingRequestBeforeRun(existing, traceId);
    if (screened.rejected) {
      return jsonResponse(
        {
          ok: false,
          error: "request_rejected_in_verify_stage",
          detail: screened.record.lastError,
          traceId,
          data: buildRequestResponse(screened.record)
        },
        409
      );
    }
    existing = screened.record;
  }

  const worldIdConsumeAuth = await requireWorldIdForWallet(req, existing.input.submitterAddress, { consumeToken: true });
  if (!worldIdConsumeAuth.ok) {
    logServerFailure("request.run_verification.world_id_denied", {
      traceId,
      requestId,
      walletAddress: existing.input.submitterAddress,
      error: worldIdConsumeAuth.error,
      detail: worldIdConsumeAuth.detail ?? null
    });
    return jsonResponse(
      {
        ok: false,
        error: worldIdConsumeAuth.error,
        detail: worldIdConsumeAuth.detail,
        traceId
      },
      worldIdConsumeAuth.status
    );
  }

  return executeVerificationForRecord(req, existing);
}

async function handleGetReport(requestId: string): Promise<Response> {
  const record = await getRequest(requestId);
  if (!record) {
    return jsonResponse({ ok: false, error: "request_not_found" }, 404);
  }

  const reportPath = resolveProjectPath("reports", `${requestId}.json`);

  try {
    const raw = await readFile(reportPath, "utf8");
    const report = JSON.parse(raw) as unknown;

    return jsonResponse({
      ok: true,
      data: report
    });
  } catch {
    return jsonResponse({ ok: false, error: "report_not_found" }, 404);
  }
}

interface VerifyWorldIdBody {
  walletAddress: string;
  proof: unknown;
  appId?: string;
  action?: string;
  clientSource?: string;
}

async function handleVerifyWorldId(req: Request): Promise<Response> {
  let body: VerifyWorldIdBody;
  try {
    body = await parseJsonBody<VerifyWorldIdBody>(req);
  } catch (error) {
    return jsonResponse(
      {
        ok: false,
        error: "invalid_json",
        detail: error instanceof Error ? error.message : String(error)
      },
      400
    );
  }

  try {
    const normalizedWalletAddress = normalizeAddress(body.walletAddress);
    const walletAuth = await requireWalletRequestAuth(req, normalizedWalletAddress);
    if (!walletAuth.ok) {
      return jsonResponse(
        {
          ok: false,
          error: walletAuth.error,
          detail: walletAuth.detail
        },
        walletAuth.status
      );
    }

    const session = await issueWorldIdSessionFromProof({
      walletAddress: normalizedWalletAddress,
      rawProof: (body.proof ?? {}) as Record<string, unknown>,
      appId: body.appId,
      action: body.action,
      clientSource: body.clientSource
    });

    return jsonResponse({
      ok: true,
      data: {
        session
      }
    });
  } catch (error) {
    return jsonResponse(
      {
        ok: false,
        error: "world_id_verify_failed",
        detail: error instanceof Error ? error.message : String(error)
      },
      400
    );
  }
}

interface RegisterNodeBody {
  walletAddress: string;
  selectedModelFamilies: string[];
  modelName?: string;
  endpointUrl?: string;
  peerId?: string;
  tlsCertFingerprint?: string;
  stakeAmount?: string;
  participationEnabled?: boolean;
}

async function handleRegisterNode(req: Request): Promise<Response> {
  let body: RegisterNodeBody;

  try {
    body = await parseJsonBody<RegisterNodeBody>(req);
  } catch (error) {
    return jsonResponse(
      {
        ok: false,
        error: "invalid_json",
        detail: error instanceof Error ? error.message : String(error)
      },
      400
    );
  }

  let normalizedWalletAddress: string;
  try {
    normalizedWalletAddress = normalizeAddress(body.walletAddress);
  } catch (error) {
    return jsonResponse(
      {
        ok: false,
        error: "invalid_wallet_address",
        detail: error instanceof Error ? error.message : String(error)
      },
      400
    );
  }

  const walletAuth = await requireWalletRequestAuth(req, normalizedWalletAddress);
  if (!walletAuth.ok) {
    logServerFailure("node.register.auth_failed", {
      walletAddress: normalizedWalletAddress,
      error: walletAuth.error,
      detail: walletAuth.detail ?? null
    });
    return jsonResponse(
      {
        ok: false,
        error: walletAuth.error,
        detail: walletAuth.detail
      },
      walletAuth.status
    );
  }

  const worldIdAuth = await requireWorldIdForWallet(req, normalizedWalletAddress);
  if (!worldIdAuth.ok) {
    logServerFailure("node.register.world_id_failed", {
      walletAddress: normalizedWalletAddress,
      error: worldIdAuth.error,
      detail: worldIdAuth.detail ?? null
    });
    return jsonResponse(
      {
        ok: false,
        error: worldIdAuth.error,
        detail: worldIdAuth.detail
      },
      worldIdAuth.status
    );
  }

  const paymentResult = await enforceX402Payment(req, {
    resource: "/api/nodes/register",
    price: resolveNodeRegistrationPrice(),
    walletAddress: normalizedWalletAddress
  });
  if (!paymentResult.ok) {
    logServerFailure("node.register.payment_failed", {
      walletAddress: normalizedWalletAddress
    });
    return paymentResult.response ?? jsonResponse({ ok: false, error: "payment_failed" }, 402);
  }

  try {
    const normalizedFamilies = normalizeFamilyList(body.selectedModelFamilies);
    const modelName = resolveAutoModelName(normalizedWalletAddress, normalizedFamilies, body.modelName);
    const endpointUrl = resolveAutoEndpointUrl(normalizedWalletAddress, normalizedFamilies, body.endpointUrl);

    const node = await registerOrUpdateNode({
      walletAddress: normalizedWalletAddress,
      selectedModelFamilies: normalizedFamilies,
      modelName,
      endpointUrl,
      peerId: body.peerId,
      tlsCertFingerprint: body.tlsCertFingerprint,
      stakeAmount: body.stakeAmount,
      participationEnabled: body.participationEnabled,
      worldIdVerified: true
    });

    return jsonResponse(
      {
        ok: true,
        data: {
          node,
          paymentReceipt: paymentResult.receipt
        }
      },
      201
    );
  } catch (error) {
    logServerFailure("node.register.failed", {
      walletAddress: normalizedWalletAddress,
      error: stringifyError(error)
    });
    return jsonResponse(
      {
        ok: false,
        error: "node_registration_failed",
        detail: stringifyError(error)
      },
      400
    );
  }
}

interface CreateNodeChallengeBody {
  walletAddress: string;
  selectedModelFamilies: string[];
  modelName?: string;
  endpointUrl?: string;
  peerId?: string;
  tlsCertFingerprint?: string;
  stakeAmount?: string;
  participationEnabled?: boolean;
}

async function handleCreateNodeChallenge(req: Request): Promise<Response> {
  let body: CreateNodeChallengeBody;
  try {
    body = await parseJsonBody<CreateNodeChallengeBody>(req);
  } catch (error) {
    return jsonResponse(
      {
        ok: false,
        error: "invalid_json",
        detail: error instanceof Error ? error.message : String(error)
      },
      400
    );
  }

  let normalizedWalletAddress: string;
  try {
    normalizedWalletAddress = normalizeAddress(body.walletAddress);
  } catch (error) {
    return jsonResponse(
      {
        ok: false,
        error: "invalid_wallet_address",
        detail: error instanceof Error ? error.message : String(error)
      },
      400
    );
  }

  const walletAuth = await requireWalletRequestAuth(req, normalizedWalletAddress);
  if (!walletAuth.ok) {
    logServerFailure("node.challenge.auth_failed", {
      walletAddress: normalizedWalletAddress,
      error: walletAuth.error,
      detail: walletAuth.detail ?? null
    });
    return jsonResponse(
      {
        ok: false,
        error: walletAuth.error,
        detail: walletAuth.detail
      },
      walletAuth.status
    );
  }

  const worldIdAuth = await requireWorldIdForWallet(req, normalizedWalletAddress);
  if (!worldIdAuth.ok) {
    logServerFailure("node.challenge.world_id_failed", {
      walletAddress: normalizedWalletAddress,
      error: worldIdAuth.error,
      detail: worldIdAuth.detail ?? null
    });
    return jsonResponse(
      {
        ok: false,
        error: worldIdAuth.error,
        detail: worldIdAuth.detail
      },
      worldIdAuth.status
    );
  }

  const paymentResult = await enforceX402Payment(req, {
    resource: "/api/nodes/challenge",
    price: resolveNodeRegistrationPrice(),
    walletAddress: normalizedWalletAddress
  });
  if (!paymentResult.ok) {
    logServerFailure("node.challenge.payment_failed", {
      walletAddress: normalizedWalletAddress
    });
    return paymentResult.response ?? jsonResponse({ ok: false, error: "payment_failed" }, 402);
  }

  try {
    const normalizedFamilies = normalizeFamilyList(body.selectedModelFamilies);
    const modelName = resolveAutoModelName(normalizedWalletAddress, normalizedFamilies, body.modelName);
    const endpointUrl = resolveAutoEndpointUrl(normalizedWalletAddress, normalizedFamilies, body.endpointUrl);
    if (!endpointUrl) {
      return jsonResponse(
        {
          ok: false,
          error: "endpoint_not_configured_for_wallet",
          detail:
            "set NODE_ENDPOINT_URL_MAP_JSON, NODE_ENDPOINT_URL_BY_FAMILY_JSON, or NODE_DEFAULT_ENDPOINT_URL"
        },
        400
      );
    }

    const challenge = await createNodeRegistrationChallenge({
      walletAddress: normalizedWalletAddress,
      selectedModelFamilies: normalizedFamilies,
      modelName,
      endpointUrl,
      peerId: body.peerId,
      tlsCertFingerprint: body.tlsCertFingerprint,
      stakeAmount: body.stakeAmount,
      participationEnabled: body.participationEnabled,
      worldIdVerified: true
    });

    return jsonResponse(
      {
        ok: true,
        data: {
          challenge,
          paymentReceipt: paymentResult.receipt
        }
      },
      201
    );
  } catch (error) {
    logServerFailure("node.challenge.failed", {
      walletAddress: normalizedWalletAddress,
      error: stringifyError(error)
    });
    return jsonResponse(
      {
        ok: false,
        error: "node_challenge_failed",
        detail: stringifyError(error)
      },
      400
    );
  }
}

interface ActivateNodeChallengeBody {
  challengeId: string;
  walletAddress: string;
  signature: string;
}

async function handleActivateNodeChallenge(req: Request): Promise<Response> {
  let body: ActivateNodeChallengeBody;
  try {
    body = await parseJsonBody<ActivateNodeChallengeBody>(req);
  } catch (error) {
    return jsonResponse(
      {
        ok: false,
        error: "invalid_json",
        detail: error instanceof Error ? error.message : String(error)
      },
      400
    );
  }

  try {
    const walletAuth = await requireWalletRequestAuth(req, body.walletAddress);
    if (!walletAuth.ok) {
      logServerFailure("node.activate.auth_failed", {
        walletAddress: body.walletAddress,
        challengeId: body.challengeId,
        error: walletAuth.error,
        detail: walletAuth.detail ?? null
      });
      return jsonResponse(
        {
          ok: false,
          error: walletAuth.error,
          detail: walletAuth.detail
        },
        walletAuth.status
      );
    }

    const result = await activateNodeRegistrationChallenge({
      challengeId: body.challengeId,
      walletAddress: body.walletAddress,
      signature: body.signature
    });

    const lifecycleOnchainReceipt =
      resolveNodeLifecycleOnchainEnabled() && result.node.endpointUrl
        ? await submitNodeLifecycleOnchain({
            nodeId: result.node.walletAddress,
            action: "ACTIVATED",
            endpointUrl: result.node.endpointUrl,
            payloadHash: result.challenge.challengeId,
            payloadUri: `node://challenge/${result.challenge.challengeId}`,
            lifecycleId: hashObject({
              kind: "ACTIVATED",
              challengeId: result.challenge.challengeId
            })
          })
        : undefined;

    return jsonResponse(
      {
        ok: true,
        data: {
          ...result,
          lifecycleOnchainReceipt
        }
      },
      200
    );
  } catch (error) {
    logServerFailure("node.activate.failed", {
      walletAddress: body.walletAddress,
      challengeId: body.challengeId,
      error: stringifyError(error)
    });
    return jsonResponse(
      {
        ok: false,
        error: "node_activation_failed",
        detail: stringifyError(error)
      },
      400
    );
  }
}

interface NodeHeartbeatBody {
  walletAddress: string;
  endpointUrl?: string;
  timestamp: number;
  signature: string;
}

async function handleNodeHeartbeat(req: Request): Promise<Response> {
  let body: NodeHeartbeatBody;
  try {
    body = await parseJsonBody<NodeHeartbeatBody>(req);
  } catch (error) {
    return jsonResponse(
      {
        ok: false,
        error: "invalid_json",
        detail: error instanceof Error ? error.message : String(error)
      },
      400
    );
  }

  const timestamp = Number.isFinite(body.timestamp) ? Math.trunc(body.timestamp) : NaN;
  if (!Number.isFinite(timestamp)) {
    return jsonResponse({ ok: false, error: "invalid_heartbeat_timestamp" }, 400);
  }

  const nowMs = Date.now();
  if (Math.abs(nowMs - timestamp) > 5 * 60_000) {
    return jsonResponse({ ok: false, error: "heartbeat_timestamp_out_of_window" }, 400);
  }

  const endpointUrl = body.endpointUrl?.trim() || "";
  if (endpointUrl.length === 0) {
    return jsonResponse({ ok: false, error: "endpointUrl_required" }, 400);
  }

  try {
    const normalizedWallet = normalizeAddress(body.walletAddress);
    const walletAuth = await requireWalletRequestAuth(req, normalizedWallet);
    if (!walletAuth.ok) {
      logServerFailure("node.heartbeat.auth_failed", {
        walletAddress: normalizedWallet,
        endpointUrl,
        error: walletAuth.error,
        detail: walletAuth.detail ?? null
      });
      return jsonResponse(
        {
          ok: false,
          error: walletAuth.error,
          detail: walletAuth.detail
        },
        walletAuth.status
      );
    }

    const heartbeatMessage = buildNodeHeartbeatMessage({
      walletAddress: normalizedWallet,
      endpointUrl,
      timestamp
    });
    const recovered = normalizeAddress(verifyMessage(heartbeatMessage, body.signature));
    if (recovered !== normalizedWallet) {
      logServerFailure("node.heartbeat.signature_invalid", {
        walletAddress: normalizedWallet,
        endpointUrl,
        timestamp
      });
      return jsonResponse({ ok: false, error: "heartbeat_signature_invalid" }, 401);
    }

    const result = await touchNodeHeartbeat({
      walletAddress: normalizedWallet,
      endpointUrl
    });

    const lifecycleOnchainReceipt =
      resolveNodeLifecycleOnchainEnabled() && result.node.endpointUrl
        ? await submitNodeLifecycleOnchain({
            nodeId: result.node.walletAddress,
            action: "HEARTBEAT",
            endpointUrl: result.node.endpointUrl,
            payloadHash: hashObject({
              walletAddress: normalizedWallet,
              endpointUrl,
              timestamp,
              signature: body.signature
            }),
            payloadUri: `node://heartbeat/${normalizedWallet}/${timestamp}`,
            lifecycleId: hashObject({
              kind: "HEARTBEAT",
              walletAddress: normalizedWallet,
              endpointUrl,
              timestamp
            })
          })
        : undefined;

    return jsonResponse({
      ok: true,
      data: {
        node: result.node,
        endpointProbe: result.endpointProbe,
        heartbeatMessage,
        lifecycleOnchainReceipt
      }
    });
  } catch (error) {
    logServerFailure("node.heartbeat.failed", {
      walletAddress: body.walletAddress,
      endpointUrl,
      error: stringifyError(error)
    });
    return jsonResponse(
      {
        ok: false,
        error: "node_heartbeat_failed",
        detail: stringifyError(error)
      },
      400
    );
  }
}

async function handleListNodes(): Promise<Response> {
  if (resolveOnchainReadEnabled()) {
    try {
      const nodes = await listNodesFromOnchain();
      return jsonResponse({
        ok: true,
        data: nodes
      });
    } catch (error) {
      if (resolveOnchainReadStrict()) {
        return jsonResponse(
          {
            ok: false,
            error: "onchain_read_failed",
            detail: error instanceof Error ? error.message : String(error)
          },
          502
        );
      }
    }
  }

  const localNodes = await listRegisteredNodes();
  return jsonResponse({
    ok: true,
    data: localNodes
  });
}

async function router(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const { pathname } = url;
  const requestPathRegex = /^\/api\/requests\/([^/]+)$/;
  const runPathRegex = /^\/api\/requests\/([^/]+)\/run-verification$/;
  const reportPathRegex = /^\/api\/requests\/([^/]+)\/report$/;

  if (req.method === "OPTIONS") {
    return corsPreflight();
  }

  if (req.method === "GET" && pathname === "/healthz") {
    return jsonResponse({ ok: true, service: "orchestrator", timestamp: nowIso() });
  }

  if (req.method === "GET" && pathname === "/api/requests") {
    let items: StoredRequest[];
    if (resolveOnchainReadEnabled()) {
      try {
        items = await listRequestsFromOnchain();
      } catch (error) {
        if (resolveOnchainReadStrict()) {
          return jsonResponse(
            {
              ok: false,
              error: "onchain_read_failed",
              detail: error instanceof Error ? error.message : String(error)
            },
            502
          );
        }
        items = await listRequests();
      }
    } else {
      items = await listRequests();
    }
    const queued = sortQueuedRequests(items.filter((record) => record.status === "PENDING"));
    const nonQueued = items
      .filter((record) => record.status !== "PENDING")
      .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
    return jsonResponse({
      ok: true,
      data: [...queued, ...nonQueued].map((record) => buildRequestResponse(record))
    });
  }

  if (req.method === "GET" && pathname === "/api/por/status") {
    try {
      const status = await getPorStatusSnapshot();
      return jsonResponse({
        ok: true,
        data: status
      });
    } catch (error) {
      return jsonResponse(
        {
          ok: false,
          error: "por_status_unavailable",
          detail: stringifyError(error)
        },
        503
      );
    }
  }

  if (req.method === "GET" && pathname === "/api/nodes") {
    return handleListNodes();
  }

  if (req.method === "POST" && pathname === "/api/world-id/verify") {
    return handleVerifyWorldId(req);
  }

  if (req.method === "POST" && pathname === "/api/nodes/register") {
    return handleRegisterNode(req);
  }

  if (req.method === "POST" && pathname === "/api/nodes/challenge") {
    return handleCreateNodeChallenge(req);
  }

  if (req.method === "POST" && pathname === "/api/nodes/activate") {
    return handleActivateNodeChallenge(req);
  }

  if (req.method === "POST" && pathname === "/api/nodes/heartbeat") {
    return handleNodeHeartbeat(req);
  }

  if (req.method === "POST" && pathname === "/api/requests") {
    return handleCreateRequest(req);
  }

  if (req.method === "GET") {
    const requestId = parseRequestIdFromPath(pathname, requestPathRegex);
    if (requestId) {
      return handleGetRequest(requestId);
    }
  }

  if (req.method === "POST") {
    const requestId = parseRequestIdFromPath(pathname, runPathRegex);
    if (requestId) {
      return handleRunVerification(req, requestId);
    }
  }

  if (req.method === "GET") {
    const requestId = parseRequestIdFromPath(pathname, reportPathRegex);
    if (requestId) {
      return handleGetReport(requestId);
    }
  }

  return jsonResponse({ ok: false, error: "not_found" }, 404);
}

assertStartupConfigOrThrow();

Bun.serve({
  port: PORT,
  fetch: async (req: Request) => {
    try {
      return await router(req);
    } catch (error) {
      const url = new URL(req.url);
      const detail = stringifyError(error);
      logServerFailure("http.unhandled_exception", {
        method: req.method,
        path: url.pathname,
        error: detail
      });
      return jsonResponse(
        {
          ok: false,
          error: "internal_server_error",
          detail
        },
        500
      );
    }
  }
});

logServerEvent("info", "startup.server.listening", {
  port: PORT
});

scheduleRequestQueueProcessor("startup");
