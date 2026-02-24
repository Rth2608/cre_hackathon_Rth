import { Interface, JsonRpcProvider, getAddress, id } from "ethers";
import { ONCHAIN_READER_ABI } from "./contractAbi";
import type { MarketRequestInput, RegisteredNode, StoredRequest } from "./types";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const VERIFICATION_FINALIZED_TOPIC = id(
  "VerificationFinalized(bytes32,bool,int16,uint8,bytes32,string,address,uint256)"
);
const VERIFICATION_BUNDLE_FINALIZED_TOPIC = id(
  "VerificationBundleFinalized(bytes32,bytes32,bool,int16,uint8,uint32,bytes32,bytes32,bytes32,uint64,address,address,uint256,string)"
);
const NODE_LIFECYCLE_RECORDED_TOPIC = id(
  "NodeLifecycleRecorded(bytes32,address,uint8,bytes32,bytes32,string,string,address,uint256)"
);
const POR_PROOF_RECORDED_TOPIC = id(
  "PorProofRecorded(uint32,uint64,bytes32,uint256,uint256,uint32,bool,string,address,uint256)"
);

interface ReaderContext {
  provider: JsonRpcProvider;
  contractAddress: string;
  chainId: number;
}

interface FinalizationEventRecord {
  requestId: string;
  verdict: boolean;
  aggregateScoreBps: number;
  responders: number;
  finalReportHash: string;
  reportUri: string;
  timestampSeconds: number;
  txHash: string;
  blockNumber: number;
  logIndex: number;
}

interface NodeLifecycleRecord {
  nodeId: string;
  endpointUrl: string;
  action: number;
  timestampSeconds: number;
  blockNumber: number;
  logIndex: number;
}

export interface OnchainPorProofSnapshot {
  marketId: number;
  epoch: number;
  assetsMicroUsdc: string;
  liabilitiesMicroUsdc: string;
  coverageBps: number;
  healthy: boolean;
  proofHash: string;
  proofUri?: string;
  txHash: string;
  updatedAt: string;
  blockNumber: number;
  logIndex: number;
}

function requireEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function resolveFromBlock(): number {
  const raw = process.env.ONCHAIN_LOG_FROM_BLOCK?.trim();
  if (!raw) return 0;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed < 0) return 0;
  return parsed;
}

function resolveRequestLimit(): number {
  const raw = process.env.ONCHAIN_MAX_REQUESTS?.trim();
  if (!raw) return 100;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed <= 0) return 100;
  return parsed;
}

function toIsoFromSeconds(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) {
    return new Date(0).toISOString();
  }
  return new Date(seconds * 1000).toISOString();
}

function toHexRequestId(input: string): string {
  const normalized = input.startsWith("0x") ? input.toLowerCase() : `0x${input.toLowerCase()}`;
  if (!/^0x[0-9a-f]{64}$/.test(normalized)) {
    throw new Error("requestId must be bytes32 hex");
  }
  return normalized;
}

function buildExplorerUrl(txHash: string): string | undefined {
  const base = process.env.TENDERLY_TX_BASE_URL?.trim();
  if (!base) return undefined;
  return `${base.replace(/\/$/, "")}/${txHash}`;
}

function buildPlaceholderInput(): MarketRequestInput {
  return {
    question: "onchain_finalized_request",
    description: "Loaded from on-chain finalization event",
    sourceUrls: [],
    resolutionCriteria: "onchain_consensus_finalized",
    submitterAddress: ZERO_ADDRESS
  };
}

function buildStoredRequestFromEvent(event: FinalizationEventRecord, chainId: number, gasUsed = "0"): StoredRequest {
  const timestamp = toIsoFromSeconds(event.timestampSeconds);
  return {
    requestId: event.requestId,
    input: buildPlaceholderInput(),
    createdAt: timestamp,
    updatedAt: timestamp,
    status: "FINALIZED",
    runAttempts: 1,
    consensus: {
      requestId: event.requestId,
      responders: event.responders,
      aggregateScore: event.aggregateScoreBps / 10_000,
      aggregateScoreBps: event.aggregateScoreBps,
      finalVerdict: event.verdict ? "PASS" : "FAIL",
      includedNodes: [],
      excludedNodes: [],
      finalReportHash: event.finalReportHash,
      status: "OK"
    },
    onchainReceipt: {
      txHash: event.txHash,
      blockNumber: event.blockNumber,
      gasUsed,
      chainId,
      explorerUrl: buildExplorerUrl(event.txHash),
      simulated: false
    }
  };
}

async function createReaderContext(): Promise<ReaderContext> {
  const rpcUrl = requireEnv("RPC_URL");
  const contractAddress = getAddress(requireEnv("CONTRACT_ADDRESS"));
  const chainIdFromEnv = process.env.CHAIN_ID ? Number.parseInt(process.env.CHAIN_ID, 10) : undefined;
  const provider = new JsonRpcProvider(rpcUrl, chainIdFromEnv);
  const chainId = Number((await provider.getNetwork()).chainId);
  return { provider, contractAddress, chainId };
}

function normalizeLogIndex(log: { index?: number; logIndex?: number }): number {
  if (typeof log.index === "number") return log.index;
  if (typeof log.logIndex === "number") return log.logIndex;
  return 0;
}

async function queryFinalizationEvents(context: ReaderContext, requestId?: string): Promise<FinalizationEventRecord[]> {
  const iface = new Interface(ONCHAIN_READER_ABI);
  const topics: Array<string[] | string | null> = [[VERIFICATION_FINALIZED_TOPIC, VERIFICATION_BUNDLE_FINALIZED_TOPIC]];
  if (requestId) {
    topics.push(requestId);
  }

  const logs = await context.provider.getLogs({
    address: context.contractAddress,
    fromBlock: resolveFromBlock(),
    toBlock: "latest",
    topics
  });

  const parsed: FinalizationEventRecord[] = [];

  for (const log of logs) {
    let decoded;
    try {
      decoded = iface.parseLog(log);
    } catch {
      continue;
    }
    if (!decoded) continue;

    if (decoded.name === "VerificationFinalized") {
      parsed.push({
        requestId: String(decoded.args.requestId).toLowerCase(),
        verdict: Boolean(decoded.args.verdict),
        aggregateScoreBps: Number(decoded.args.aggregateScoreBps),
        responders: Number(decoded.args.responders),
        finalReportHash: String(decoded.args.reportHash).toLowerCase(),
        reportUri: String(decoded.args.reportUri),
        timestampSeconds: Number(decoded.args.timestamp),
        txHash: log.transactionHash,
        blockNumber: log.blockNumber,
        logIndex: normalizeLogIndex(log)
      });
      continue;
    }

    if (decoded.name === "VerificationBundleFinalized") {
      parsed.push({
        requestId: String(decoded.args.requestId).toLowerCase(),
        verdict: Boolean(decoded.args.verdict),
        aggregateScoreBps: Number(decoded.args.aggregateScoreBps),
        responders: Number(decoded.args.responders),
        finalReportHash: String(decoded.args.bundleHash).toLowerCase(),
        reportUri: String(decoded.args.reportUri),
        timestampSeconds: Number(decoded.args.timestamp),
        txHash: log.transactionHash,
        blockNumber: log.blockNumber,
        logIndex: normalizeLogIndex(log)
      });
    }
  }

  return parsed;
}

async function getGasUsed(provider: JsonRpcProvider, txHash: string): Promise<string> {
  try {
    const receipt = await provider.getTransactionReceipt(txHash);
    if (!receipt) return "0";
    return receipt.gasUsed.toString();
  } catch {
    return "0";
  }
}

function dedupeLatestRequests(events: FinalizationEventRecord[]): FinalizationEventRecord[] {
  const byRequestId = new Map<string, FinalizationEventRecord>();
  for (const item of events) {
    const current = byRequestId.get(item.requestId);
    if (!current) {
      byRequestId.set(item.requestId, item);
      continue;
    }
    const isNewer =
      item.blockNumber > current.blockNumber ||
      (item.blockNumber === current.blockNumber && item.logIndex > current.logIndex);
    if (isNewer) {
      byRequestId.set(item.requestId, item);
    }
  }

  return [...byRequestId.values()].sort((a, b) => {
    if (a.timestampSeconds !== b.timestampSeconds) return b.timestampSeconds - a.timestampSeconds;
    if (a.blockNumber !== b.blockNumber) return b.blockNumber - a.blockNumber;
    return b.logIndex - a.logIndex;
  });
}

export async function listRequestsFromOnchain(): Promise<StoredRequest[]> {
  const context = await createReaderContext();
  const events = dedupeLatestRequests(await queryFinalizationEvents(context));
  const limited = events.slice(0, resolveRequestLimit());
  return limited.map((event) => buildStoredRequestFromEvent(event, context.chainId));
}

export async function getRequestFromOnchain(requestId: string): Promise<StoredRequest | null> {
  const context = await createReaderContext();
  const normalizedRequestId = toHexRequestId(requestId);
  const events = dedupeLatestRequests(await queryFinalizationEvents(context, normalizedRequestId));
  if (events.length === 0) {
    return null;
  }

  const target = events[0];
  const gasUsed = await getGasUsed(context.provider, target.txHash);
  return buildStoredRequestFromEvent(target, context.chainId, gasUsed);
}

async function queryLifecycleEvents(context: ReaderContext): Promise<NodeLifecycleRecord[]> {
  const iface = new Interface(ONCHAIN_READER_ABI);
  const logs = await context.provider.getLogs({
    address: context.contractAddress,
    fromBlock: resolveFromBlock(),
    toBlock: "latest",
    topics: [[NODE_LIFECYCLE_RECORDED_TOPIC]]
  });

  const records: NodeLifecycleRecord[] = [];
  for (const log of logs) {
    let decoded;
    try {
      decoded = iface.parseLog(log);
    } catch {
      continue;
    }
    if (!decoded || decoded.name !== "NodeLifecycleRecorded") continue;

    records.push({
      nodeId: getAddress(String(decoded.args.nodeId)).toLowerCase(),
      endpointUrl: String(decoded.args.endpointUrl),
      action: Number(decoded.args.action),
      timestampSeconds: Number(decoded.args.timestamp),
      blockNumber: log.blockNumber,
      logIndex: normalizeLogIndex(log)
    });
  }

  return records;
}

function buildRegisteredNodeFromLifecycle(input: {
  nodeId: string;
  endpointUrl: string;
  registeredAtSeconds: number;
  updatedAtSeconds: number;
  heartbeatAtSeconds?: number;
  action: number;
}): RegisteredNode {
  const updatedAt = toIsoFromSeconds(input.updatedAtSeconds);
  return {
    registrationId: `onchain:${input.nodeId}`,
    walletAddress: input.nodeId,
    nodeId: input.nodeId,
    selectedModelFamilies: ["gpt", "gemini", "claude", "grok"],
    modelName: "onchain-operator",
    endpointUrl: input.endpointUrl || undefined,
    endpointStatus: input.action === 2 ? "HEALTHY" : "UNKNOWN",
    endpointLastCheckedAt: updatedAt,
    endpointLastHeartbeatAt: input.heartbeatAtSeconds ? toIsoFromSeconds(input.heartbeatAtSeconds) : undefined,
    endpointFailureCount: 0,
    endpointVerifiedAt: updatedAt,
    stakeAmount: "0",
    participationEnabled: true,
    worldIdVerified: true,
    status: "ACTIVE",
    registeredAt: toIsoFromSeconds(input.registeredAtSeconds),
    updatedAt
  };
}

export async function listNodesFromOnchain(): Promise<RegisteredNode[]> {
  const context = await createReaderContext();
  const events = await queryLifecycleEvents(context);

  const aggregated = new Map<
    string,
    {
      nodeId: string;
      endpointUrl: string;
      action: number;
      registeredAtSeconds: number;
      updatedAtSeconds: number;
      heartbeatAtSeconds?: number;
      blockNumber: number;
      logIndex: number;
    }
  >();

  for (const event of events) {
    const current = aggregated.get(event.nodeId);
    if (!current) {
      aggregated.set(event.nodeId, {
        nodeId: event.nodeId,
        endpointUrl: event.endpointUrl,
        action: event.action,
        registeredAtSeconds: event.timestampSeconds,
        updatedAtSeconds: event.timestampSeconds,
        heartbeatAtSeconds: event.action === 2 ? event.timestampSeconds : undefined,
        blockNumber: event.blockNumber,
        logIndex: event.logIndex
      });
      continue;
    }

    if (event.timestampSeconds < current.registeredAtSeconds) {
      current.registeredAtSeconds = event.timestampSeconds;
    }

    const isNewer =
      event.blockNumber > current.blockNumber ||
      (event.blockNumber === current.blockNumber && event.logIndex > current.logIndex);
    if (!isNewer) {
      continue;
    }

    current.endpointUrl = event.endpointUrl;
    current.action = event.action;
    current.updatedAtSeconds = event.timestampSeconds;
    current.blockNumber = event.blockNumber;
    current.logIndex = event.logIndex;
    if (event.action === 2) {
      current.heartbeatAtSeconds = event.timestampSeconds;
    }
  }

  return [...aggregated.values()]
    .map((item) =>
      buildRegisteredNodeFromLifecycle({
        nodeId: item.nodeId,
        endpointUrl: item.endpointUrl,
        registeredAtSeconds: item.registeredAtSeconds,
        updatedAtSeconds: item.updatedAtSeconds,
        heartbeatAtSeconds: item.heartbeatAtSeconds,
        action: item.action
      })
    )
    .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
}

export async function listPorProofsFromOnchain(options?: {
  marketId?: number;
  limit?: number;
}): Promise<OnchainPorProofSnapshot[]> {
  const context = await createReaderContext();
  const iface = new Interface(ONCHAIN_READER_ABI);
  const topics: Array<string[] | string | null> = [[POR_PROOF_RECORDED_TOPIC]];
  if (typeof options?.marketId === "number" && options.marketId > 0) {
    topics.push(`0x${options.marketId.toString(16).padStart(64, "0")}`);
  }

  const logs = await context.provider.getLogs({
    address: context.contractAddress,
    fromBlock: resolveFromBlock(),
    toBlock: "latest",
    topics
  });

  const records: OnchainPorProofSnapshot[] = [];
  for (const log of logs) {
    let decoded;
    try {
      decoded = iface.parseLog(log);
    } catch {
      continue;
    }
    if (!decoded || decoded.name !== "PorProofRecorded") continue;

    const marketId = Number(decoded.args.marketId);
    const epoch = Number(decoded.args.epoch);
    const assetsMicroUsdc = decoded.args.assetsMicroUsdc.toString();
    const liabilitiesMicroUsdc = decoded.args.liabilitiesMicroUsdc.toString();
    const coverageBps = Number(decoded.args.coverageBps);
    const healthy = Boolean(decoded.args.healthy);
    const proofHash = String(decoded.args.proofHash).toLowerCase();
    const proofUriRaw = String(decoded.args.proofUri);
    const timestampSeconds = Number(decoded.args.timestamp);

    records.push({
      marketId,
      epoch,
      assetsMicroUsdc,
      liabilitiesMicroUsdc,
      coverageBps,
      healthy,
      proofHash,
      proofUri: proofUriRaw.length > 0 ? proofUriRaw : undefined,
      txHash: log.transactionHash,
      updatedAt: toIsoFromSeconds(timestampSeconds),
      blockNumber: log.blockNumber,
      logIndex: normalizeLogIndex(log)
    });
  }

  const sorted = records.sort((a, b) => {
    if (a.marketId !== b.marketId) return a.marketId - b.marketId;
    if (a.epoch !== b.epoch) return b.epoch - a.epoch;
    if (a.blockNumber !== b.blockNumber) return b.blockNumber - a.blockNumber;
    return b.logIndex - a.logIndex;
  });

  const deduped: OnchainPorProofSnapshot[] = [];
  const seen = new Set<string>();
  for (const item of sorted) {
    const key = `${item.marketId}:${item.epoch}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(item);
  }

  const limit = typeof options?.limit === "number" && options.limit > 0 ? options.limit : 20;
  return deduped.slice(0, limit);
}

export async function getLatestPorProofFromOnchain(marketId: number): Promise<OnchainPorProofSnapshot | null> {
  const proofs = await listPorProofsFromOnchain({ marketId, limit: 1 });
  return proofs[0] ?? null;
}
