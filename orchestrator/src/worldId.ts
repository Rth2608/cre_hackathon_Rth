import { randomBytes } from "node:crypto";
import { getAddress } from "ethers";
import { ensureDir, nowIso, readJsonFile, resolveProjectPath, writeJsonFileAtomic } from "./utils";

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
  // World ID 4.0 payload
  protocol_version?: unknown;
  nonce?: unknown;
  signal?: unknown;
  max_age?: unknown;
  metadata?: unknown;
  status?: unknown;
  created_at?: unknown;
  updated_at?: unknown;
  responses?: unknown;
  result?: unknown;
  action?: unknown;
  nullifier_hash?: unknown;
  verification_level?: unknown;
  [key: string]: unknown;
}

interface ParsedWorldIdV4ProofPayload {
  rawPayload: Record<string, unknown>;
  nullifierHash: string;
  verificationLevel?: string;
  action?: string;
}

type ParsedWorldIdProofPayload = ParsedWorldIdV4ProofPayload;

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

const WORLD_ID_V3_ALLOWED_IDENTIFIERS = new Set(["orb", "secure_document", "document", "device", "face"]);

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

function normalizeWorldIdV3Identifier(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const normalized = value.trim().toLowerCase();
  if (!WORLD_ID_V3_ALLOWED_IDENTIFIERS.has(normalized)) {
    return undefined;
  }
  return normalized;
}

function toTrimmedString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function normalizeHexStringMaybe(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  if (!trimmed) {
    return undefined;
  }
  const unprefixed = trimmed.startsWith("0x") || trimmed.startsWith("0X") ? trimmed.slice(2) : trimmed;
  if (!unprefixed || !/^[0-9a-fA-F]+$/.test(unprefixed)) {
    return trimmed;
  }
  return `0x${unprefixed.toLowerCase()}`;
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

function looksLikeWorldIdV4Payload(raw: Record<string, unknown>): boolean {
  if (typeof raw.protocol_version === "string") {
    return true;
  }
  if (typeof raw.nonce === "string") {
    return true;
  }
  if (Array.isArray(raw.responses)) {
    return true;
  }
  const result = toRecord(raw.result);
  if (!result) {
    return false;
  }
  return Boolean(
    toTrimmedString(result.proof) || toTrimmedString(result.nullifier_hash) || toTrimmedString(result.merkle_root)
  );
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
  const action =
    toTrimmedString(v4Record.action) ??
    toTrimmedString(result?.action) ??
    toTrimmedString(firstResponse?.action);

  return {
    rawPayload: v4Record,
    nullifierHash: nullifierHash ?? "",
    verificationLevel,
    action
  };
}

function parseWorldIdProof(rawInput: WorldIdProofInput): ParsedWorldIdProofPayload {
  const parsed = parseWorldIdV4Proof(rawInput);
  if (!parsed) {
    throw new Error("invalid_world_id_v4_payload");
  }
  return parsed;
}

function assertParsedProofValid(payload: ParsedWorldIdProofPayload): void {
  if (!payload.nullifierHash) {
    throw new Error("missing_nullifier_hash");
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
    const availableProfiles = input.profiles
      .map((profile) => {
        const sources = profile.allowedClientSources.length > 0 ? profile.allowedClientSources.join("|") : "*";
        return `${profile.appId}:${profile.action}:${sources}`;
      })
      .join(",");
    throw new Error(
      `world_id_profile_not_found: requested_app_id=${appId ?? "-"}, requested_action=${action ?? "-"}, requested_client_source=${requestedClientSource ?? "-"}, available_profiles=${availableProfiles || "-"}`
    );
  }
  if (candidates.length > 1) {
    throw new Error("world_id_profile_ambiguous");
  }
  return candidates[0];
}

function resolveWorldIdVerifyApiV4Base(): string {
  return (process.env.WORLD_ID_VERIFY_API_V4_BASE_URL?.trim() ?? DEFAULT_WORLD_ID_VERIFY_API_V4_BASE).replace(/\/$/, "");
}

function resolveWorldIdVerifyV4RouteId(defaultAppId: string): string {
  const configuredRpId = process.env.WORLD_ID_RP_ID?.trim();
  if (configuredRpId) {
    return configuredRpId;
  }
  const normalizedDefault = defaultAppId.trim();
  return normalizedDefault.startsWith("rp_") ? normalizedDefault : "";
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

function buildWorldVerifyRequestBody(input: { proofPayload: ParsedWorldIdV4ProofPayload }): Record<string, unknown> {
  const raw = input.proofPayload.rawPayload;
  const protocolVersion = toTrimmedString(raw.protocol_version) ?? "";
  if (!protocolVersion.startsWith("3")) {
    return raw;
  }

  const action = toTrimmedString(raw.action) ?? input.proofPayload.action;
  const defaultIdentifier = normalizeWorldIdV3Identifier(input.proofPayload.verificationLevel);
  const responsesRaw = Array.isArray(raw.responses) ? raw.responses : [];
  const normalizedResponses = responsesRaw.map((entry) => {
    const responseRecord = toRecord(entry);
    if (!responseRecord) {
      return entry;
    }
    const normalized = { ...responseRecord };
    const nullifier =
      toTrimmedString(normalized.nullifier) ??
      toTrimmedString(normalized.nullifier_hash) ??
      input.proofPayload.nullifierHash;
    if (nullifier) {
      normalized.nullifier = nullifier;
      if (!toTrimmedString(normalized.nullifier_hash)) {
        normalized.nullifier_hash = nullifier;
      }
    }

    const identifier =
      normalizeWorldIdV3Identifier(normalized.identifier) ??
      normalizeWorldIdV3Identifier(normalized.verification_level) ??
      normalizeWorldIdV3Identifier(normalized.credential_type) ??
      defaultIdentifier;
    if (identifier) {
      normalized.identifier = identifier;
    }
    if (!toTrimmedString(normalized.action) && action) {
      normalized.action = action;
    }
    return normalized;
  });

  const requestBody: Record<string, unknown> = {
    ...raw
  };
  if (normalizedResponses.length > 0) {
    requestBody.responses = normalizedResponses;
  }

  return requestBody;
}

async function verifyWithWorldCloudV4(input: {
  routeId: string;
  proofPayload: ParsedWorldIdV4ProofPayload;
}): Promise<VerifyApiResult> {
  const verifyUrl = `${resolveWorldIdVerifyApiV4Base()}/${input.routeId}`;
  return runWorldVerifyRequest({
    verifyUrl,
    requestBody: buildWorldVerifyRequestBody({ proofPayload: input.proofPayload })
  });
}

async function verifyWithWorldCloud(input: {
  appId: string;
  proofPayload: ParsedWorldIdProofPayload;
}): Promise<VerifyApiResult> {
  const v4RouteId = resolveWorldIdVerifyV4RouteId(input.appId);
  if (!v4RouteId) {
    return {
      ok: false,
      status: 400,
      payload: {
        success: false,
        code: "world_id_rp_id_missing",
        detail: "WORLD_ID_RP_ID must be configured for World ID 4.0 verification."
      }
    };
  }

  const primaryResult = await verifyWithWorldCloudV4({
    routeId: v4RouteId,
    proofPayload: input.proofPayload
  });
  return primaryResult;
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
