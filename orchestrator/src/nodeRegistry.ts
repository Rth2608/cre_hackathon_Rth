import { randomBytes } from "node:crypto";
import { getAddress, verifyMessage } from "ethers";
import type { CanonicalModelFamily, NodeRegistrationChallenge, RegisteredNode } from "./types";
import { ensureDir, hashObject, nowIso, readJsonFile, resolveProjectPath, writeJsonFileAtomic } from "./utils";

const NODE_DB_PATH = resolveProjectPath("data", "nodes.json");
const ALLOWED_MODEL_FAMILIES: CanonicalModelFamily[] = ["gpt", "gemini", "claude", "grok"];

interface NodeDbSchema {
  nodes: Record<string, RegisteredNode>;
  challenges: Record<string, NodeRegistrationChallenge>;
}

interface LegacyRegisteredNode extends Partial<RegisteredNode> {
  modelFamily?: string;
}

interface LegacyNodeDbSchema {
  nodes?: Record<string, LegacyRegisteredNode>;
  challenges?: Record<string, Partial<NodeRegistrationChallenge>>;
}

interface RegisterNodeInput {
  walletAddress: string;
  selectedModelFamilies: string[];
  modelName: string;
  endpointUrl?: string;
  peerId?: string;
  tlsCertFingerprint?: string;
  stakeAmount?: string;
  participationEnabled?: boolean;
  worldIdVerified: boolean;
}

interface CreateNodeChallengeInput {
  walletAddress: string;
  selectedModelFamilies: string[];
  modelName: string;
  endpointUrl: string;
  peerId?: string;
  tlsCertFingerprint?: string;
  stakeAmount?: string;
  participationEnabled?: boolean;
  worldIdVerified: boolean;
}

interface ActivateNodeChallengeInput {
  challengeId: string;
  walletAddress: string;
  signature: string;
}

interface NodeHeartbeatInput {
  walletAddress: string;
  endpointUrl?: string;
}

interface UpdateStakeInput {
  walletAddress: string;
  stakeAmount: string;
}

interface UpdateParticipationInput {
  walletAddress: string;
  participationEnabled: boolean;
  selectedModelFamilies?: string[];
}

interface EndpointProbeResult {
  ok: boolean;
  checkedAt: string;
  latencyMs?: number;
  error?: string;
}

function isAddress(value: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(value);
}

function normalizeAddress(value: string): string {
  return getAddress(value).toLowerCase();
}

function assertModelFamilies(values: string[]): CanonicalModelFamily[] {
  if (!Array.isArray(values) || values.length === 0) {
    throw new Error("selectedModelFamilies must contain at least 1 value");
  }

  const normalized = Array.from(
    new Set(
      values
        .map((value) => value.trim().toLowerCase())
        .filter(Boolean)
        .map((value) => {
          if (!ALLOWED_MODEL_FAMILIES.includes(value as CanonicalModelFamily)) {
            throw new Error(`Unsupported model family: ${value}`);
          }
          return value as CanonicalModelFamily;
        })
    )
  );

  if (normalized.length === 0) {
    throw new Error("selectedModelFamilies must contain at least 1 supported value");
  }

  return normalized;
}

function resolveNodeId(walletAddress: string): string {
  return walletAddress;
}

function assertModelName(value: string): string {
  const normalized = value.trim();
  if (normalized.length < 2 || normalized.length > 128) {
    throw new Error("modelName must be 2~128 chars");
  }
  return normalized;
}

function assertPeerId(value?: string): string | undefined {
  if (!value || value.trim().length === 0) return undefined;
  const normalized = value.trim();
  if (normalized.length < 8 || normalized.length > 128) {
    throw new Error("peerId must be 8~128 chars");
  }
  return normalized;
}

function assertTlsFingerprint(value?: string): string | undefined {
  if (!value || value.trim().length === 0) return undefined;
  const normalized = value.trim().toLowerCase();
  if (!/^[a-f0-9:]{16,191}$/.test(normalized)) {
    throw new Error("tlsCertFingerprint format is invalid");
  }
  return normalized;
}

function assertEndpointUrl(value?: string): string | undefined {
  if (!value || value.trim().length === 0) {
    return undefined;
  }
  const parsed = new URL(value.trim());
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("endpointUrl must be http(s)");
  }
  const normalized = parsed.toString().replace(/\/$/, "");
  return normalized;
}

function assertEndpointUrlRequired(value: string | undefined): string {
  const normalized = assertEndpointUrl(value);
  if (!normalized) {
    throw new Error("endpointUrl is required for self-registration");
  }
  return normalized;
}

function assertStakeAmount(value: string | undefined, fallback = "0"): string {
  const normalized = (value ?? fallback).trim();
  if (!/^[0-9]+$/.test(normalized)) {
    throw new Error("stakeAmount must be integer string");
  }
  return normalized;
}

function resolveChallengeTtlSeconds(): number {
  const parsed = Number.parseInt(process.env.NODE_CHALLENGE_TTL_SECONDS ?? "300", 10);
  if (!Number.isInteger(parsed) || parsed < 30 || parsed > 3600) {
    return 300;
  }
  return parsed;
}

function resolveHealthcheckTimeoutMs(): number {
  const parsed = Number.parseInt(process.env.NODE_ENDPOINT_HEALTHCHECK_TIMEOUT_MS ?? "2500", 10);
  if (!Number.isInteger(parsed) || parsed < 500 || parsed > 15_000) {
    return 2500;
  }
  return parsed;
}

function buildChallengeMessage(challenge: {
  challengeId: string;
  walletAddress: string;
  nodeId: string;
  endpointUrl: string;
  modelName: string;
  selectedModelFamilies: CanonicalModelFamily[];
  stakeAmount: string;
  participationEnabled: boolean;
  nonce: string;
  expiresAt: string;
}): string {
  return [
    "CRE Node Self-Registration Challenge",
    `challengeId: ${challenge.challengeId}`,
    `walletAddress: ${challenge.walletAddress}`,
    `nodeId: ${challenge.nodeId}`,
    `endpointUrl: ${challenge.endpointUrl}`,
    `modelName: ${challenge.modelName}`,
    `modelFamilies: ${challenge.selectedModelFamilies.join(",")}`,
    `stakeAmount: ${challenge.stakeAmount}`,
    `participationEnabled: ${challenge.participationEnabled ? "true" : "false"}`,
    `nonce: ${challenge.nonce}`,
    `expiresAt: ${challenge.expiresAt}`
  ].join("\n");
}

function safeToIso(value: string | undefined, fallback: string): string {
  if (!value) return fallback;
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return fallback;
  return new Date(parsed).toISOString();
}

function normalizeEndpointStatus(value: string | undefined): RegisteredNode["endpointStatus"] {
  if (value === "HEALTHY" || value === "UNHEALTHY") return value;
  return "UNKNOWN";
}

async function probeEndpointHealth(endpointUrl: string): Promise<EndpointProbeResult> {
  const checkedAt = nowIso();
  const timeoutMs = resolveHealthcheckTimeoutMs();

  let healthz: string;
  try {
    healthz = new URL("/healthz", endpointUrl).toString();
  } catch {
    return {
      ok: false,
      checkedAt,
      error: "invalid_endpoint_url"
    };
  }

  const started = Date.now();
  try {
    const response = await fetch(healthz, {
      method: "GET",
      signal: AbortSignal.timeout(timeoutMs)
    });
    const latencyMs = Date.now() - started;
    if (!response.ok) {
      return {
        ok: false,
        checkedAt,
        latencyMs,
        error: `http_${response.status}`
      };
    }

    return {
      ok: true,
      checkedAt,
      latencyMs
    };
  } catch (error) {
    return {
      ok: false,
      checkedAt,
      latencyMs: Date.now() - started,
      error: error instanceof Error ? error.message : String(error)
    };
  }
}

function applyEndpointProbe(node: RegisteredNode, probe: EndpointProbeResult, heartbeatAt?: string): RegisteredNode {
  const failureCount = probe.ok ? 0 : node.endpointFailureCount + 1;
  return {
    ...node,
    endpointStatus: probe.ok ? "HEALTHY" : "UNHEALTHY",
    endpointLastCheckedAt: probe.checkedAt,
    endpointLastHeartbeatAt: heartbeatAt ?? node.endpointLastHeartbeatAt,
    endpointLatencyMs: probe.latencyMs,
    endpointFailureCount: failureCount,
    endpointLastError: probe.ok ? undefined : probe.error
  };
}

async function loadDb(): Promise<NodeDbSchema> {
  await ensureDir(resolveProjectPath("data"));
  const raw = await readJsonFile<LegacyNodeDbSchema>(NODE_DB_PATH, { nodes: {}, challenges: {} });
  const normalized: NodeDbSchema = { nodes: {}, challenges: {} };
  let changed = false;

  for (const [key, item] of Object.entries(raw.nodes ?? {})) {
    const walletRaw = item.walletAddress ?? "";
    const normalizedWalletAddress = isAddress(walletRaw) ? normalizeAddress(walletRaw) : walletRaw.toLowerCase();
    const fallbackFamily = (item.modelFamily?.toLowerCase() ?? "gpt") as CanonicalModelFamily;
    const safeFamily = ALLOWED_MODEL_FAMILIES.includes(fallbackFamily) ? fallbackFamily : "gpt";
    const selectedModelFamilies =
      Array.isArray(item.selectedModelFamilies) && item.selectedModelFamilies.length > 0
        ? item.selectedModelFamilies.filter((value): value is CanonicalModelFamily =>
            ALLOWED_MODEL_FAMILIES.includes(value)
          )
        : [safeFamily];
    const now = nowIso();

    const endpointUrl = assertEndpointUrl(item.endpointUrl);
    const normalizedNode: RegisteredNode = {
      registrationId: item.registrationId ?? key,
      walletAddress: normalizedWalletAddress,
      nodeId:
        normalizedWalletAddress && normalizedWalletAddress.startsWith("0x")
          ? resolveNodeId(normalizedWalletAddress)
          : (item.nodeId ?? `node-${key.slice(0, 6)}`),
      selectedModelFamilies: selectedModelFamilies.length > 0 ? selectedModelFamilies : ["gpt"],
      modelName: item.modelName ?? "mock-node",
      endpointUrl,
      peerId: assertPeerId(item.peerId),
      tlsCertFingerprint: assertTlsFingerprint(item.tlsCertFingerprint),
      endpointStatus: normalizeEndpointStatus(item.endpointStatus),
      endpointLastCheckedAt: safeToIso(item.endpointLastCheckedAt, now),
      endpointLastHeartbeatAt: item.endpointLastHeartbeatAt ? safeToIso(item.endpointLastHeartbeatAt, now) : undefined,
      endpointLatencyMs: typeof item.endpointLatencyMs === "number" ? item.endpointLatencyMs : undefined,
      endpointFailureCount:
        typeof item.endpointFailureCount === "number" && item.endpointFailureCount >= 0 ? item.endpointFailureCount : 0,
      endpointLastError: item.endpointLastError,
      endpointVerifiedAt: item.endpointVerifiedAt ? safeToIso(item.endpointVerifiedAt, now) : undefined,
      stakeAmount: assertStakeAmount(item.stakeAmount, "0"),
      participationEnabled: item.participationEnabled ?? true,
      worldIdVerified: item.worldIdVerified ?? false,
      status: item.status === "INACTIVE" ? "INACTIVE" : "ACTIVE",
      registeredAt: safeToIso(item.registeredAt, now),
      updatedAt: safeToIso(item.updatedAt, now)
    };

    if (
      item.selectedModelFamilies === undefined ||
      item.stakeAmount === undefined ||
      item.participationEnabled === undefined ||
      item.registrationId !== normalizedNode.registrationId ||
      item.walletAddress !== normalizedNode.walletAddress ||
      item.nodeId !== normalizedNode.nodeId ||
      item.endpointStatus === undefined ||
      item.endpointFailureCount === undefined
    ) {
      changed = true;
    }

    normalized.nodes[normalizedNode.registrationId] = normalizedNode;
  }

  for (const [challengeId, value] of Object.entries(raw.challenges ?? {})) {
    const createdAt = safeToIso(value.createdAt, nowIso());
    const expiresAt = safeToIso(value.expiresAt, createdAt);
    const expired = Date.now() > Date.parse(expiresAt);
    const status: NodeRegistrationChallenge["status"] =
      value.status === "USED" ? "USED" : value.status === "EXPIRED" || expired ? "EXPIRED" : "PENDING";

    if (!value.walletAddress || !value.nodeId || !value.challengeMessage || !value.endpointUrl || !value.modelName) {
      changed = true;
      continue;
    }
    if (!Array.isArray(value.selectedModelFamilies) || value.selectedModelFamilies.length === 0) {
      changed = true;
      continue;
    }

    const selectedModelFamilies = value.selectedModelFamilies.filter((item): item is CanonicalModelFamily =>
      ALLOWED_MODEL_FAMILIES.includes(item)
    );
    if (selectedModelFamilies.length === 0) {
      changed = true;
      continue;
    }

    normalized.challenges[challengeId] = {
      challengeId,
      walletAddress: normalizeAddress(value.walletAddress),
      nodeId: value.nodeId,
      selectedModelFamilies,
      modelName: value.modelName,
      endpointUrl: assertEndpointUrlRequired(value.endpointUrl),
      peerId: assertPeerId(value.peerId),
      tlsCertFingerprint: assertTlsFingerprint(value.tlsCertFingerprint),
      stakeAmount: assertStakeAmount(value.stakeAmount, "0"),
      participationEnabled: value.participationEnabled ?? true,
      worldIdVerified: value.worldIdVerified ?? false,
      challengeMessage: value.challengeMessage,
      nonce: value.nonce ?? randomBytes(16).toString("hex"),
      createdAt,
      expiresAt,
      status,
      signature: value.signature,
      usedAt: value.usedAt ? safeToIso(value.usedAt, createdAt) : undefined
    };
  }

  if (changed) {
    await saveDb(normalized);
  }

  return normalized;
}

async function saveDb(db: NodeDbSchema): Promise<void> {
  await writeJsonFileAtomic(NODE_DB_PATH, db);
}

function sortNodes(nodes: RegisteredNode[]): RegisteredNode[] {
  return [...nodes].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
}

export async function listRegisteredNodes(options?: { status?: RegisteredNode["status"] }): Promise<RegisteredNode[]> {
  const db = await loadDb();
  const values = Object.values(db.nodes);
  const filtered = options?.status ? values.filter((node) => node.status === options.status) : values;
  return sortNodes(filtered);
}

export async function getNodeByWallet(walletAddress: string): Promise<RegisteredNode | null> {
  const normalized = normalizeAddress(walletAddress);
  const nodes = await listRegisteredNodes();
  return nodes.find((node) => node.walletAddress === normalized && node.status === "ACTIVE") ?? null;
}

function upsertNodeFromConfig(args: {
  db: NodeDbSchema;
  walletAddress: string;
  selectedModelFamilies: CanonicalModelFamily[];
  modelName: string;
  endpointUrl?: string;
  peerId?: string;
  tlsCertFingerprint?: string;
  stakeAmount: string;
  participationEnabled: boolean;
  worldIdVerified: boolean;
  endpointProbe?: EndpointProbeResult;
  endpointVerifiedAt?: string;
}): RegisteredNode {
  const { db } = args;
  const now = nowIso();
  const walletAddress = normalizeAddress(args.walletAddress);
  const nodeId = resolveNodeId(walletAddress);

  const activeNodeByWallet = Object.values(db.nodes).find(
    (node) => node.walletAddress === walletAddress && node.status === "ACTIVE"
  );
  if (activeNodeByWallet && activeNodeByWallet.nodeId !== nodeId) {
    db.nodes[activeNodeByWallet.registrationId] = {
      ...activeNodeByWallet,
      status: "INACTIVE",
      updatedAt: now
    };
  }

  const conflictingActiveNode = Object.values(db.nodes).find(
    (node) => node.nodeId === nodeId && node.walletAddress !== walletAddress && node.status === "ACTIVE"
  );
  if (conflictingActiveNode) {
    throw new Error(`nodeId already used by ${conflictingActiveNode.walletAddress}`);
  }

  const existing = Object.values(db.nodes).find((node) => node.walletAddress === walletAddress && node.nodeId === nodeId);

  const registrationId =
    existing?.registrationId ??
    hashObject({
      walletAddress,
      nodeId,
      firstRegisteredAt: now
    });

  const endpointProbe = args.endpointProbe;
  const endpointStatus = endpointProbe
    ? endpointProbe.ok
      ? "HEALTHY"
      : "UNHEALTHY"
    : existing?.endpointStatus ?? "UNKNOWN";
  const endpointFailureCount = endpointProbe
    ? endpointProbe.ok
      ? 0
      : (existing?.endpointFailureCount ?? 0) + 1
    : existing?.endpointFailureCount ?? 0;

  const nextNode: RegisteredNode = {
    registrationId,
    walletAddress,
    nodeId,
    selectedModelFamilies: args.selectedModelFamilies,
    modelName: args.modelName,
    endpointUrl: args.endpointUrl,
    peerId: args.peerId,
    tlsCertFingerprint: args.tlsCertFingerprint,
    endpointStatus,
    endpointLastCheckedAt: endpointProbe?.checkedAt ?? existing?.endpointLastCheckedAt,
    endpointLastHeartbeatAt: endpointProbe?.checkedAt ?? existing?.endpointLastHeartbeatAt,
    endpointLatencyMs: endpointProbe?.latencyMs ?? existing?.endpointLatencyMs,
    endpointFailureCount,
    endpointLastError: endpointProbe ? (endpointProbe.ok ? undefined : endpointProbe.error) : existing?.endpointLastError,
    endpointVerifiedAt: args.endpointVerifiedAt ?? existing?.endpointVerifiedAt,
    stakeAmount: args.stakeAmount,
    participationEnabled: args.participationEnabled,
    worldIdVerified: args.worldIdVerified,
    status: "ACTIVE",
    registeredAt: existing?.registeredAt ?? now,
    updatedAt: now
  };

  db.nodes[registrationId] = nextNode;
  return nextNode;
}

export async function registerOrUpdateNode(input: RegisterNodeInput): Promise<RegisteredNode> {
  if (!isAddress(input.walletAddress)) {
    throw new Error(`Invalid walletAddress: ${input.walletAddress}`);
  }
  if (!input.worldIdVerified) {
    throw new Error("worldId verification required");
  }

  const walletAddress = normalizeAddress(input.walletAddress);
  const selectedModelFamilies = assertModelFamilies(input.selectedModelFamilies);
  const modelName = assertModelName(input.modelName);
  const endpointUrl = assertEndpointUrl(input.endpointUrl);
  const peerId = assertPeerId(input.peerId);
  const tlsCertFingerprint = assertTlsFingerprint(input.tlsCertFingerprint);
  const stakeAmount = assertStakeAmount(input.stakeAmount, "0");
  const participationEnabled = input.participationEnabled ?? true;

  const db = await loadDb();
  const node = upsertNodeFromConfig({
    db,
    walletAddress,
    selectedModelFamilies,
    modelName,
    endpointUrl,
    peerId,
    tlsCertFingerprint,
    stakeAmount,
    participationEnabled,
    worldIdVerified: true
  });

  await saveDb(db);
  return node;
}

export async function createNodeRegistrationChallenge(input: CreateNodeChallengeInput): Promise<NodeRegistrationChallenge> {
  if (!isAddress(input.walletAddress)) {
    throw new Error(`Invalid walletAddress: ${input.walletAddress}`);
  }
  if (!input.worldIdVerified) {
    throw new Error("worldId verification required");
  }

  const walletAddress = normalizeAddress(input.walletAddress);
  const selectedModelFamilies = assertModelFamilies(input.selectedModelFamilies);
  const modelName = assertModelName(input.modelName);
  const endpointUrl = assertEndpointUrlRequired(input.endpointUrl);
  const peerId = assertPeerId(input.peerId);
  const tlsCertFingerprint = assertTlsFingerprint(input.tlsCertFingerprint);
  const stakeAmount = assertStakeAmount(input.stakeAmount, "0");
  const participationEnabled = input.participationEnabled ?? true;
  const nodeId = resolveNodeId(walletAddress);

  const createdAt = nowIso();
  const expiresAt = new Date(Date.now() + resolveChallengeTtlSeconds() * 1000).toISOString();
  const nonce = randomBytes(16).toString("hex");
  const challengeId = hashObject({
    walletAddress,
    nodeId,
    endpointUrl,
    modelName,
    selectedModelFamilies,
    nonce,
    createdAt
  });

  const challengeMessage = buildChallengeMessage({
    challengeId,
    walletAddress,
    nodeId,
    endpointUrl,
    modelName,
    selectedModelFamilies,
    stakeAmount,
    participationEnabled,
    nonce,
    expiresAt
  });

  const challenge: NodeRegistrationChallenge = {
    challengeId,
    walletAddress,
    nodeId,
    selectedModelFamilies,
    modelName,
    endpointUrl,
    peerId,
    tlsCertFingerprint,
    stakeAmount,
    participationEnabled,
    worldIdVerified: true,
    challengeMessage,
    nonce,
    createdAt,
    expiresAt,
    status: "PENDING"
  };

  const db = await loadDb();
  db.challenges[challengeId] = challenge;
  await saveDb(db);
  return challenge;
}

function isChallengeExpired(challenge: NodeRegistrationChallenge): boolean {
  return Date.now() > Date.parse(challenge.expiresAt);
}

export async function activateNodeRegistrationChallenge(input: ActivateNodeChallengeInput): Promise<{
  node: RegisteredNode;
  challenge: NodeRegistrationChallenge;
  endpointProbe: EndpointProbeResult;
}> {
  if (!/^0x[0-9a-fA-F]{64}$/.test(input.challengeId)) {
    throw new Error("challengeId must be bytes32 hex");
  }
  if (!isAddress(input.walletAddress)) {
    throw new Error(`Invalid walletAddress: ${input.walletAddress}`);
  }
  const walletAddress = normalizeAddress(input.walletAddress);
  const signature = input.signature.trim();
  if (!/^0x[0-9a-fA-F]+$/.test(signature)) {
    throw new Error("signature must be hex string");
  }

  const db = await loadDb();
  const challenge = db.challenges[input.challengeId];
  if (!challenge) {
    throw new Error("challenge_not_found");
  }
  if (challenge.status !== "PENDING") {
    throw new Error(`challenge_not_pending:${challenge.status}`);
  }
  if (challenge.walletAddress !== walletAddress) {
    throw new Error("challenge_wallet_mismatch");
  }
  if (isChallengeExpired(challenge)) {
    challenge.status = "EXPIRED";
    db.challenges[input.challengeId] = challenge;
    await saveDb(db);
    throw new Error("challenge_expired");
  }

  const recovered = normalizeAddress(verifyMessage(challenge.challengeMessage, signature));
  if (recovered !== walletAddress) {
    throw new Error("challenge_signature_invalid");
  }

  const endpointProbe = await probeEndpointHealth(challenge.endpointUrl);
  const verifiedAt = nowIso();
  const node = upsertNodeFromConfig({
    db,
    walletAddress,
    selectedModelFamilies: challenge.selectedModelFamilies,
    modelName: challenge.modelName,
    endpointUrl: challenge.endpointUrl,
    peerId: challenge.peerId,
    tlsCertFingerprint: challenge.tlsCertFingerprint,
    stakeAmount: challenge.stakeAmount,
    participationEnabled: challenge.participationEnabled,
    worldIdVerified: challenge.worldIdVerified,
    endpointProbe,
    endpointVerifiedAt: verifiedAt
  });

  const usedChallenge: NodeRegistrationChallenge = {
    ...challenge,
    status: "USED",
    signature,
    usedAt: verifiedAt
  };
  db.challenges[input.challengeId] = usedChallenge;
  await saveDb(db);

  return {
    node,
    challenge: usedChallenge,
    endpointProbe
  };
}

function requireNodeByWallet(db: NodeDbSchema, walletAddress: string): { key: string; node: RegisteredNode } {
  const normalized = normalizeAddress(walletAddress);
  const entry = Object.entries(db.nodes).find(([, node]) => node.walletAddress === normalized);
  if (!entry) {
    throw new Error("node_not_found_for_wallet");
  }
  const [key, node] = entry;
  return { key, node };
}

function requireActiveNodeByWallet(db: NodeDbSchema, walletAddress: string): { key: string; node: RegisteredNode } {
  const normalized = normalizeAddress(walletAddress);
  const entry = Object.entries(db.nodes).find(
    ([, node]) => node.walletAddress === normalized && node.status === "ACTIVE"
  );
  if (!entry) {
    throw new Error("active_node_not_found_for_wallet");
  }
  const [key, node] = entry;
  return { key, node };
}

export async function touchNodeHeartbeat(input: NodeHeartbeatInput): Promise<{
  node: RegisteredNode;
  endpointProbe?: EndpointProbeResult;
}> {
  if (!isAddress(input.walletAddress)) {
    throw new Error(`Invalid walletAddress: ${input.walletAddress}`);
  }
  const db = await loadDb();
  const { key, node } = requireNodeByWallet(db, input.walletAddress);
  const now = nowIso();

  const endpointUrl = assertEndpointUrl(input.endpointUrl) ?? node.endpointUrl;
  if (!endpointUrl) {
    throw new Error("endpointUrl_missing_for_heartbeat");
  }
  if (node.endpointUrl && endpointUrl !== node.endpointUrl) {
    throw new Error("endpointUrl_mismatch_with_registered_node");
  }

  const shouldProbe = process.env.NODE_ENDPOINT_HEALTHCHECK_ENABLED === "true";
  let endpointProbe: EndpointProbeResult | undefined;
  let nextNode: RegisteredNode = {
    ...node,
    endpointUrl,
    endpointLastHeartbeatAt: now,
    updatedAt: now
  };

  if (shouldProbe) {
    endpointProbe = await probeEndpointHealth(endpointUrl);
    nextNode = {
      ...applyEndpointProbe(nextNode, endpointProbe, now),
      updatedAt: now
    };
  }

  db.nodes[key] = nextNode;
  await saveDb(db);

  return {
    node: nextNode,
    endpointProbe
  };
}

export async function refreshNodeEndpointHealth(options?: {
  walletAddresses?: string[];
}): Promise<RegisteredNode[]> {
  if (process.env.NODE_ENDPOINT_HEALTHCHECK_ENABLED !== "true") {
    return listRegisteredNodes();
  }

  const db = await loadDb();
  const targetWallets = options?.walletAddresses?.map((address) => normalizeAddress(address));
  const candidates = Object.entries(db.nodes).filter(([, node]) => {
    if (node.status !== "ACTIVE") return false;
    if (!node.endpointUrl) return false;
    if (!targetWallets || targetWallets.length === 0) return true;
    return targetWallets.includes(node.walletAddress);
  });

  if (candidates.length === 0) {
    return sortNodes(Object.values(db.nodes));
  }

  const probes = await Promise.all(
    candidates.map(async ([key, node]) => ({
      key,
      node,
      probe: await probeEndpointHealth(node.endpointUrl!)
    }))
  );

  const now = nowIso();
  for (const item of probes) {
    const updated = {
      ...applyEndpointProbe(item.node, item.probe),
      updatedAt: now
    };
    db.nodes[item.key] = updated;
  }

  await saveDb(db);
  return sortNodes(Object.values(db.nodes));
}

export async function updateNodeStake(input: UpdateStakeInput): Promise<RegisteredNode> {
  if (!isAddress(input.walletAddress)) {
    throw new Error(`Invalid walletAddress: ${input.walletAddress}`);
  }
  const stakeAmount = assertStakeAmount(input.stakeAmount);

  const db = await loadDb();
  const { key, node } = requireActiveNodeByWallet(db, input.walletAddress);
  const updated: RegisteredNode = {
    ...node,
    stakeAmount,
    updatedAt: nowIso()
  };
  db.nodes[key] = updated;
  await saveDb(db);
  return updated;
}

export async function updateNodeParticipation(input: UpdateParticipationInput): Promise<RegisteredNode> {
  if (!isAddress(input.walletAddress)) {
    throw new Error(`Invalid walletAddress: ${input.walletAddress}`);
  }

  const db = await loadDb();
  const { key, node } = requireActiveNodeByWallet(db, input.walletAddress);

  const selectedModelFamilies = input.selectedModelFamilies
    ? assertModelFamilies(input.selectedModelFamilies)
    : node.selectedModelFamilies;

  const updated: RegisteredNode = {
    ...node,
    selectedModelFamilies,
    participationEnabled: input.participationEnabled,
    updatedAt: nowIso()
  };
  db.nodes[key] = updated;
  await saveDb(db);
  return updated;
}
