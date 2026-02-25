import { randomBytes } from "node:crypto";
import { getAddress } from "ethers";
import { ensureDir, nowIso, readJsonFile, resolveProjectPath, writeJsonFileAtomic } from "./utils";

const DEFAULT_WORLD_ID_VERIFY_API_V2_BASE = "https://developer.worldcoin.org/api/v2/verify";
const DEFAULT_WORLD_ID_VERIFY_API_V4_BASE = "https://developer.world.org/api/v4/verify";
const WORLD_ID_DB_PATH = resolveProjectPath("data", "world-id-sessions.json");

interface WorldIdSessionDbSchema {
  sessions: Record<string, StoredWorldIdSession>;
  nullifierWalletMap: Record<string, string>;
}

interface StoredWorldIdSession {
  token: string;
  walletAddress: string;
  nullifierHash: string;
  appId: string;
  action: string;
  verificationLevel?: string;
  profileId?: string;
  clientSource?: WorldIdClientSource;
  issuedAt: string;
  expiresAt: string;
  source: "world_id_cloud" | "assume";
}

export interface WorldIdSession {
  token: string;
  walletAddress: string;
  nullifierHash: string;
  appId: string;
  action: string;
  verificationLevel?: string;
  profileId?: string;
  clientSource?: WorldIdClientSource;
  issuedAt: string;
  expiresAt: string;
  source: "world_id_cloud" | "assume";
}

export interface WorldIdProofInput {
  // Legacy v3 payload
  merkle_root?: unknown;
  nullifier_hash?: unknown;
  proof?: unknown;
  verification_level?: unknown;
  signal_hash?: unknown;
  action?: unknown;

  // IDKit result payload fallback
  responses?: unknown;
  protocol_version?: unknown;
  nonce?: unknown;
  signal?: unknown;
  max_age?: unknown;
  metadata?: unknown;
  status?: unknown;
  created_at?: unknown;
  updated_at?: unknown;
  result?: unknown;
}

interface ParsedWorldIdLegacyProofPayload {
  kind: "legacy";
  merkleRoot: string;
  nullifierHash: string;
  proof: string | string[];
  verificationLevel?: string;
  signalHash?: string;
  action?: string;
}

interface ParsedWorldIdV4ProofPayload {
  kind: "v4";
  rawPayload: Record<string, unknown>;
  nullifierHash: string;
  verificationLevel?: string;
  action?: string;
  legacyFallback: ParsedWorldIdLegacyProofPayload | null;
}

type ParsedWorldIdProofPayload = ParsedWorldIdLegacyProofPayload | ParsedWorldIdV4ProofPayload;

export type WorldIdClientSource = "miniapp" | "external" | "manual";

interface WorldIdProfile {
  id: string;
  appId: string;
  action: string;
  allowedClientSources: WorldIdClientSource[];
}

interface VerifyApiSuccess {
  success: true;
  [key: string]: unknown;
}

interface VerifyApiFailure {
  success?: false;
  code?: string;
  detail?: string;
  [key: string]: unknown;
}

interface VerifyApiResult {
  ok: boolean;
  status: number;
  payload: VerifyApiSuccess | VerifyApiFailure | null;
}

function normalizeAddress(value: string): string {
  return getAddress(value).toLowerCase();
}

function normalizeClientSource(value: unknown): WorldIdClientSource | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const normalized = value.trim().toLowerCase();
  if (normalized === "miniapp" || normalized === "external" || normalized === "manual") {
    return normalized;
  }
  return undefined;
}

function toTrimmedString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function normalizeHexStringMaybe(value: string | undefined): string | undefined {
  if (!value) return undefined;
  if (value.startsWith("0x") || value.startsWith("0X")) {
    return `0x${value.slice(2).toLowerCase()}`;
  }
  return `0x${value.toLowerCase()}`;
}

function normalizeProofArray(value: unknown): string[] | null {
  if (!Array.isArray(value) || value.length === 0) {
    return null;
  }
  const proofItems: string[] = [];
  for (const item of value) {
    if (typeof item !== "string") {
      return null;
    }
    const trimmed = item.trim();
    if (!trimmed) {
      return null;
    }
    proofItems.push(trimmed);
  }
  return proofItems;
}

function toRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function readFirstResponseRecord(value: unknown): Record<string, unknown> | null {
  if (!Array.isArray(value) || value.length === 0) {
    return null;
  }
  return toRecord(value[0]);
}

function parseLegacyWorldIdProof(rawInput: WorldIdProofInput): ParsedWorldIdLegacyProofPayload {
  const directMerkleRoot = toTrimmedString(rawInput.merkle_root);
  const directNullifierHash = toTrimmedString(rawInput.nullifier_hash);
  const directVerificationLevel = toTrimmedString(rawInput.verification_level);
  const directSignalHash = toTrimmedString(rawInput.signal_hash);
  const directAction = toTrimmedString(rawInput.action);

  let proofValue = rawInput.proof;
  let merkleRoot = directMerkleRoot;
  let nullifierHash = directNullifierHash;
  let verificationLevel = directVerificationLevel;
  let signalHash = directSignalHash;
  let action = directAction;

  // Support IDKit result-like payload shape by reading first response entry.
  if (
    (!proofValue || !merkleRoot || !nullifierHash) &&
    Array.isArray(rawInput.responses) &&
    rawInput.responses.length > 0 &&
    rawInput.responses[0] &&
    typeof rawInput.responses[0] === "object"
  ) {
    const firstResponse = rawInput.responses[0] as Record<string, unknown>;
    proofValue = proofValue ?? firstResponse.proof;
    merkleRoot = merkleRoot ?? toTrimmedString(firstResponse.merkle_root);
    nullifierHash =
      nullifierHash ??
      toTrimmedString(firstResponse.nullifier_hash) ??
      toTrimmedString(firstResponse.nullifier);
    signalHash = signalHash ?? toTrimmedString(firstResponse.signal_hash);
  }

  if (typeof proofValue === "string" && proofValue.trim().length > 0) {
    const normalizedProof = proofValue.trim();
    return {
      kind: "legacy",
      merkleRoot: normalizeHexStringMaybe(merkleRoot) ?? "",
      nullifierHash: normalizeHexStringMaybe(nullifierHash) ?? "",
      proof: normalizedProof,
      verificationLevel,
      signalHash: normalizeHexStringMaybe(signalHash),
      action
    };
  }

  const proofArray = normalizeProofArray(proofValue);
  if (proofArray) {
    // v4 arrays often contain merkle root at index 4.
    const derivedMerkleRoot =
      merkleRoot ?? (proofArray.length >= 5 ? normalizeHexStringMaybe(proofArray[4]) : undefined);
    return {
      kind: "legacy",
      merkleRoot: derivedMerkleRoot ?? "",
      nullifierHash: normalizeHexStringMaybe(nullifierHash) ?? "",
      proof: proofArray,
      verificationLevel,
      signalHash: normalizeHexStringMaybe(signalHash),
      action
    };
  }

  throw new Error("invalid_world_id_proof_shape");
}

function looksLikeWorldIdV4Payload(raw: Record<string, unknown>): boolean {
  if (typeof raw.protocol_version === "string") {
    return true;
  }
  if (typeof raw.nonce === "string") {
    return true;
  }
  if (typeof raw.status === "string") {
    return true;
  }
  if (Array.isArray(raw.responses)) {
    return true;
  }
  const result = toRecord(raw.result);
  if (!result) {
    return false;
  }
  return Boolean(toTrimmedString(result.proof) || toTrimmedString(result.nullifier_hash) || toTrimmedString(result.merkle_root));
}

function buildLegacyFallbackFromV4(raw: Record<string, unknown>): ParsedWorldIdLegacyProofPayload | null {
  const result = toRecord(raw.result);
  const firstResponse = readFirstResponseRecord(raw.responses);

  try {
    return parseLegacyWorldIdProof({
      merkle_root: raw.merkle_root ?? result?.merkle_root ?? firstResponse?.merkle_root,
      nullifier_hash:
        raw.nullifier_hash ??
        result?.nullifier_hash ??
        firstResponse?.nullifier_hash ??
        firstResponse?.nullifier,
      proof: raw.proof ?? result?.proof ?? firstResponse?.proof,
      verification_level:
        raw.verification_level ?? result?.verification_level ?? firstResponse?.verification_level,
      signal_hash: raw.signal_hash ?? firstResponse?.signal_hash,
      action: raw.action
    });
  } catch {
    return null;
  }
}

function parseWorldIdV4Proof(rawInput: WorldIdProofInput): ParsedWorldIdV4ProofPayload | null {
  const rootRecord = toRecord(rawInput);
  if (!rootRecord) {
    return null;
  }

  const nestedResult = toRecord(rootRecord.result);
  const v4Record =
    looksLikeWorldIdV4Payload(rootRecord) ? rootRecord : nestedResult && looksLikeWorldIdV4Payload(nestedResult) ? nestedResult : null;

  if (!v4Record) {
    return null;
  }

  const result = toRecord(v4Record.result);
  const firstResponse = readFirstResponseRecord(v4Record.responses);

  const nullifierHash = normalizeHexStringMaybe(
    toTrimmedString(v4Record.nullifier_hash) ??
      toTrimmedString(result?.nullifier_hash) ??
      toTrimmedString(firstResponse?.nullifier_hash) ??
      toTrimmedString(firstResponse?.nullifier)
  );
  const verificationLevel =
    toTrimmedString(v4Record.verification_level) ??
    toTrimmedString(result?.verification_level) ??
    toTrimmedString(firstResponse?.verification_level);
  const action = toTrimmedString(v4Record.action);

  return {
    kind: "v4",
    rawPayload: v4Record,
    nullifierHash: nullifierHash ?? "",
    verificationLevel,
    action,
    legacyFallback: buildLegacyFallbackFromV4(v4Record)
  };
}

function parseWorldIdProof(rawInput: WorldIdProofInput): ParsedWorldIdProofPayload {
  return parseWorldIdV4Proof(rawInput) ?? parseLegacyWorldIdProof(rawInput);
}

function assertParsedProofValid(payload: ParsedWorldIdProofPayload): void {
  if (!payload.nullifierHash) {
    throw new Error("missing_nullifier_hash");
  }
  if (payload.kind === "legacy") {
    if (!payload.merkleRoot) {
      throw new Error("missing_merkle_root");
    }
    if (!payload.proof) {
      throw new Error("missing_proof");
    }
  }
}

function resolveWorldIdAppId(): string {
  return process.env.WORLD_ID_APP_ID?.trim() ?? "";
}

function resolveWorldIdAction(): string {
  return process.env.WORLD_ID_ACTION?.trim() ?? "";
}

function normalizeWorldIdProfile(raw: unknown): WorldIdProfile | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return null;
  }
  const record = raw as Record<string, unknown>;
  const appId = toTrimmedString(record.appId);
  const action = toTrimmedString(record.action);
  if (!appId || !action) {
    return null;
  }
  const id = toTrimmedString(record.id) ?? `${appId}:${action}`;
  const allowedClientSources = Array.isArray(record.clientSources)
    ? Array.from(new Set(record.clientSources.map((item) => normalizeClientSource(item)).filter(Boolean))) as WorldIdClientSource[]
    : [];

  return {
    id,
    appId,
    action,
    allowedClientSources
  };
}

function resolveWorldIdProfilesFromEnv(): WorldIdProfile[] {
  const raw = process.env.WORLD_ID_ALLOWED_PROFILES_JSON?.trim();
  if (!raw) {
    return [];
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("world_id_allowed_profiles_json_invalid_json");
  }

  if (!Array.isArray(parsed)) {
    throw new Error("world_id_allowed_profiles_json_must_be_array");
  }

  const profiles: WorldIdProfile[] = [];
  for (const entry of parsed) {
    const normalized = normalizeWorldIdProfile(entry);
    if (!normalized) {
      continue;
    }
    profiles.push(normalized);
  }
  return profiles;
}

function resolveWorldIdProfiles(): WorldIdProfile[] {
  const configuredProfiles = resolveWorldIdProfilesFromEnv();
  if (configuredProfiles.length > 0) {
    return configuredProfiles;
  }

  const appId = resolveWorldIdAppId();
  const action = resolveWorldIdAction();
  if (!appId || !action) {
    return [];
  }

  return [
    {
      id: "default",
      appId,
      action,
      allowedClientSources: []
    }
  ];
}

function resolveRequestedProfile(input: {
  profiles: WorldIdProfile[];
  requestedAppId?: string;
  requestedAction?: string;
  requestedClientSource?: WorldIdClientSource;
}): WorldIdProfile {
  const appId = input.requestedAppId?.trim() || undefined;
  const action = input.requestedAction?.trim() || undefined;
  const requestedClientSource = input.requestedClientSource;

  let candidates = [...input.profiles];
  if (appId) {
    candidates = candidates.filter((profile) => profile.appId === appId);
  }
  if (action) {
    candidates = candidates.filter((profile) => profile.action === action);
  }

  candidates = candidates.filter((profile) => {
    if (profile.allowedClientSources.length === 0) {
      return true;
    }
    if (!requestedClientSource) {
      return false;
    }
    return profile.allowedClientSources.includes(requestedClientSource);
  });

  if (candidates.length === 0) {
    throw new Error("world_id_profile_not_found");
  }
  if (candidates.length > 1) {
    throw new Error("world_id_profile_ambiguous");
  }
  return candidates[0];
}

function resolveWorldIdVerifyApiV2Base(): string {
  return (process.env.WORLD_ID_VERIFY_API_BASE_URL?.trim() ?? DEFAULT_WORLD_ID_VERIFY_API_V2_BASE).replace(/\/$/, "");
}

function resolveWorldIdVerifyApiV4Base(): string {
  return (process.env.WORLD_ID_VERIFY_API_V4_BASE_URL?.trim() ?? DEFAULT_WORLD_ID_VERIFY_API_V4_BASE).replace(/\/$/, "");
}

function resolveWorldIdVerifyV4RouteId(defaultAppId: string): string {
  return process.env.WORLD_ID_RP_ID?.trim() || defaultAppId;
}

function resolveWorldIdV4FallbackToV2Enabled(): boolean {
  return parseBooleanEnv(process.env.WORLD_ID_V4_FALLBACK_TO_V2, true);
}

function resolveWorldIdRequestTimeoutMs(): number {
  const parsed = Number.parseInt(process.env.WORLD_ID_VERIFY_TIMEOUT_MS?.trim() ?? "", 10);
  if (!Number.isFinite(parsed) || parsed < 1000 || parsed > 30000) {
    return 8000;
  }
  return parsed;
}

function resolveWorldIdSessionTtlSeconds(): number {
  const parsed = Number.parseInt(process.env.WORLD_ID_SESSION_TTL_SECONDS?.trim() ?? "", 10);
  if (!Number.isFinite(parsed) || parsed < 60 || parsed > 86400 * 30) {
    return 60 * 60 * 24;
  }
  return parsed;
}

function parseBooleanEnv(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (["true", "1", "yes", "y", "on"].includes(normalized)) return true;
  if (["false", "0", "no", "n", "off"].includes(normalized)) return false;
  return fallback;
}

export function isWorldIdAssumeEnabled(): boolean {
  return parseBooleanEnv(process.env.ASSUME_WORLD_ID_VERIFIED, false);
}

async function loadDb(): Promise<WorldIdSessionDbSchema> {
  await ensureDir(resolveProjectPath("data"));
  return readJsonFile<WorldIdSessionDbSchema>(WORLD_ID_DB_PATH, {
    sessions: {},
    nullifierWalletMap: {}
  });
}

async function saveDb(db: WorldIdSessionDbSchema): Promise<void> {
  await writeJsonFileAtomic(WORLD_ID_DB_PATH, db);
}

function normalizeStoredSession(session: StoredWorldIdSession): StoredWorldIdSession {
  return {
    token: session.token,
    walletAddress: normalizeAddress(session.walletAddress),
    nullifierHash: normalizeHexStringMaybe(session.nullifierHash) ?? session.nullifierHash,
    appId: session.appId.trim(),
    action: session.action.trim(),
    verificationLevel: session.verificationLevel?.trim(),
    profileId: session.profileId?.trim() || undefined,
    clientSource: normalizeClientSource(session.clientSource),
    issuedAt: session.issuedAt,
    expiresAt: session.expiresAt,
    source: session.source === "assume" ? "assume" : "world_id_cloud"
  };
}

function toPublicSession(session: StoredWorldIdSession): WorldIdSession {
  const normalized = normalizeStoredSession(session);
  return {
    token: normalized.token,
    walletAddress: normalized.walletAddress,
    nullifierHash: normalized.nullifierHash,
    appId: normalized.appId,
    action: normalized.action,
    verificationLevel: normalized.verificationLevel,
    profileId: normalized.profileId,
    clientSource: normalized.clientSource,
    issuedAt: normalized.issuedAt,
    expiresAt: normalized.expiresAt,
    source: normalized.source
  };
}

function isExpired(isoDate: string): boolean {
  const epochMs = Date.parse(isoDate);
  if (!Number.isFinite(epochMs)) {
    return true;
  }
  return epochMs <= Date.now();
}

async function loadDbWithPrune(): Promise<WorldIdSessionDbSchema> {
  const db = await loadDb();
  let mutated = false;

  for (const [token, rawSession] of Object.entries(db.sessions)) {
    const normalized = normalizeStoredSession(rawSession);
    if (isExpired(normalized.expiresAt)) {
      delete db.sessions[token];
      mutated = true;
      continue;
    }
    db.sessions[token] = normalized;
  }

  if (mutated) {
    await saveDb(db);
  }

  return db;
}

async function runWorldVerifyRequest(input: { verifyUrl: string; requestBody: Record<string, unknown> }): Promise<VerifyApiResult> {
  const timeoutMs = resolveWorldIdRequestTimeoutMs();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(input.verifyUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "cre-don-world-id-demo/1.0"
      },
      body: JSON.stringify(input.requestBody),
      signal: controller.signal
    });

    let payload: VerifyApiSuccess | VerifyApiFailure | null = null;
    try {
      payload = (await response.json()) as VerifyApiSuccess | VerifyApiFailure;
    } catch {
      payload = null;
    }

    const ok = response.ok && payload !== null && payload.success === true;
    return {
      ok,
      status: response.status,
      payload
    };
  } finally {
    clearTimeout(timeout);
  }
}

async function verifyWithWorldCloudV2(input: {
  appId: string;
  expectedAction: string;
  proofPayload: ParsedWorldIdLegacyProofPayload;
}): Promise<VerifyApiResult> {
  const requestBody: Record<string, unknown> = {
    merkle_root: input.proofPayload.merkleRoot,
    nullifier_hash: input.proofPayload.nullifierHash,
    proof: input.proofPayload.proof,
    action: input.expectedAction
  };
  if (input.proofPayload.signalHash) {
    requestBody.signal_hash = input.proofPayload.signalHash;
  }
  if (input.proofPayload.verificationLevel) {
    requestBody.verification_level = input.proofPayload.verificationLevel;
  }

  const verifyUrl = `${resolveWorldIdVerifyApiV2Base()}/${input.appId}`;
  return runWorldVerifyRequest({
    verifyUrl,
    requestBody
  });
}

async function verifyWithWorldCloudV4(input: {
  routeId: string;
  proofPayload: ParsedWorldIdV4ProofPayload;
}): Promise<VerifyApiResult> {
  const verifyUrl = `${resolveWorldIdVerifyApiV4Base()}/${input.routeId}`;
  return runWorldVerifyRequest({
    verifyUrl,
    requestBody: input.proofPayload.rawPayload
  });
}

async function verifyWithWorldCloud(input: {
  appId: string;
  expectedAction: string;
  proofPayload: ParsedWorldIdProofPayload;
}): Promise<VerifyApiResult> {
  if (input.proofPayload.kind === "legacy") {
    return verifyWithWorldCloudV2({
      appId: input.appId,
      expectedAction: input.expectedAction,
      proofPayload: input.proofPayload
    });
  }

  const primaryResult = await verifyWithWorldCloudV4({
    routeId: resolveWorldIdVerifyV4RouteId(input.appId),
    proofPayload: input.proofPayload
  });
  if (primaryResult.ok) {
    return primaryResult;
  }

  if (!resolveWorldIdV4FallbackToV2Enabled() || !input.proofPayload.legacyFallback) {
    return primaryResult;
  }

  return verifyWithWorldCloudV2({
    appId: input.appId,
    expectedAction: input.expectedAction,
    proofPayload: input.proofPayload.legacyFallback
  });
}

function buildSession(input: {
  walletAddress: string;
  nullifierHash: string;
  appId: string;
  action: string;
  verificationLevel?: string;
  profileId?: string;
  clientSource?: WorldIdClientSource;
  source: "world_id_cloud" | "assume";
}): StoredWorldIdSession {
  const issuedAt = nowIso();
  const expiresAt = new Date(Date.now() + resolveWorldIdSessionTtlSeconds() * 1000).toISOString();
  return {
    token: `wid_${randomBytes(24).toString("hex")}`,
    walletAddress: normalizeAddress(input.walletAddress),
    nullifierHash: normalizeHexStringMaybe(input.nullifierHash) ?? input.nullifierHash,
    appId: input.appId,
    action: input.action,
    verificationLevel: input.verificationLevel,
    profileId: input.profileId,
    clientSource: input.clientSource,
    issuedAt,
    expiresAt,
    source: input.source
  };
}

function nullifierBoundToDifferentWallet(input: {
  db: WorldIdSessionDbSchema;
  nullifierHash: string;
  walletAddress: string;
}): boolean {
  const key = normalizeHexStringMaybe(input.nullifierHash) ?? input.nullifierHash;
  const boundWallet = input.db.nullifierWalletMap[key];
  if (!boundWallet) {
    return false;
  }
  return boundWallet !== normalizeAddress(input.walletAddress);
}

export async function issueWorldIdSessionFromProof(input: {
  walletAddress: string;
  rawProof: WorldIdProofInput;
  appId?: string;
  action?: string;
  clientSource?: string;
}): Promise<WorldIdSession> {
  const normalizedWalletAddress = normalizeAddress(input.walletAddress);
  const profiles = resolveWorldIdProfiles();
  if (profiles.length === 0) {
    throw new Error("world_id_profile_missing");
  }

  const parsedProof = parseWorldIdProof(input.rawProof);
  assertParsedProofValid(parsedProof);

  const requestedClientSource = normalizeClientSource(input.clientSource);
  if (input.clientSource && !requestedClientSource) {
    throw new Error("world_id_client_source_invalid");
  }
  const selectedProfile = resolveRequestedProfile({
    profiles,
    requestedAppId: input.appId,
    requestedAction: input.action ?? parsedProof.action,
    requestedClientSource
  });

  if (parsedProof.action && parsedProof.action !== selectedProfile.action) {
    throw new Error(`world_id_action_mismatch: expected ${selectedProfile.action}, got ${parsedProof.action}`);
  }

  if (isWorldIdAssumeEnabled()) {
    const db = await loadDbWithPrune();
    if (
      nullifierBoundToDifferentWallet({
        db,
        nullifierHash: parsedProof.nullifierHash,
        walletAddress: normalizedWalletAddress
      })
    ) {
      throw new Error("world_id_nullifier_already_bound_to_different_wallet");
    }

    const session = buildSession({
      walletAddress: normalizedWalletAddress,
      nullifierHash: parsedProof.nullifierHash,
      appId: selectedProfile.appId,
      action: selectedProfile.action,
      verificationLevel: parsedProof.verificationLevel,
      profileId: selectedProfile.id,
      clientSource: requestedClientSource,
      source: "assume"
    });
    db.sessions[session.token] = session;
    db.nullifierWalletMap[session.nullifierHash] = session.walletAddress;
    await saveDb(db);
    return toPublicSession(session);
  }

  const verifyResult = await verifyWithWorldCloud({
    appId: selectedProfile.appId,
    expectedAction: selectedProfile.action,
    proofPayload: parsedProof
  });
  if (!verifyResult.ok) {
    const detail = verifyResult.payload && typeof verifyResult.payload.detail === "string" ? verifyResult.payload.detail : "";
    const code = verifyResult.payload && typeof verifyResult.payload.code === "string" ? verifyResult.payload.code : "";
    const reason = [code, detail].filter(Boolean).join(" ");
    throw new Error(`world_id_verify_failed (${verifyResult.status})${reason ? `: ${reason}` : ""}`);
  }

  const db = await loadDbWithPrune();
  if (
    nullifierBoundToDifferentWallet({
      db,
      nullifierHash: parsedProof.nullifierHash,
      walletAddress: normalizedWalletAddress
    })
  ) {
    throw new Error("world_id_nullifier_already_bound_to_different_wallet");
  }

  const session = buildSession({
    walletAddress: normalizedWalletAddress,
    nullifierHash: parsedProof.nullifierHash,
    appId: selectedProfile.appId,
    action: selectedProfile.action,
    verificationLevel: parsedProof.verificationLevel,
    profileId: selectedProfile.id,
    clientSource: requestedClientSource,
    source: "world_id_cloud"
  });

  db.sessions[session.token] = session;
  db.nullifierWalletMap[session.nullifierHash] = session.walletAddress;
  await saveDb(db);
  return toPublicSession(session);
}

export async function validateWorldIdSessionToken(input: {
  token: string;
  walletAddress: string;
}): Promise<{ ok: true; session: WorldIdSession } | { ok: false; reason: string }> {
  const token = input.token.trim();
  if (!token) {
    return { ok: false, reason: "world_id_token_required" };
  }

  const normalizedWallet = normalizeAddress(input.walletAddress);
  const db = await loadDbWithPrune();
  const session = db.sessions[token];

  if (!session) {
    return { ok: false, reason: "world_id_token_not_found" };
  }
  if (isExpired(session.expiresAt)) {
    return { ok: false, reason: "world_id_token_expired" };
  }
  const normalizedSessionWallet = normalizeAddress(session.walletAddress);
  if (normalizedSessionWallet !== normalizedWallet) {
    return { ok: false, reason: "world_id_token_wallet_mismatch" };
  }

  return {
    ok: true,
    session: toPublicSession(session)
  };
}
