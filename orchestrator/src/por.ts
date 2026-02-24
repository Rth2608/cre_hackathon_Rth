import { hashObject, nowIso, readJsonFile, resolveProjectPath } from "./utils";
import { getLatestPorProofFromOnchain, listPorProofsFromOnchain } from "./onchainReader";

const POR_HISTORY_PATH = resolveProjectPath("reports", "por-history.json");

export interface PorProofSnapshot {
  marketId: number;
  epoch: number;
  assetsMicroUsdc: string;
  liabilitiesMicroUsdc: string;
  coverageBps: number;
  healthy: boolean;
  proofHash: string;
  proofUri?: string;
  txHash?: string;
  updatedAt: string;
}

export interface PorStatusPayload {
  mode: "MOCK" | "FILE" | "ONCHAIN";
  source: string;
  latest: PorProofSnapshot;
  history: PorProofSnapshot[];
}

interface PorHistoryFileSchema {
  proofs: PorProofSnapshot[];
}

export interface NextPorProofInput {
  marketId: number;
  epoch: number;
  assetsMicroUsdc: string;
  liabilitiesMicroUsdc: string;
  proofHash: string;
  proofUri: string;
}

function parsePositiveInt(name: string, raw: string | undefined, fallback: number): number {
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed < 0) {
    throw new Error(`Invalid ${name}: ${raw}`);
  }
  return parsed;
}

function parseNonNegativeBigInt(name: string, raw: string | undefined, fallback: bigint): bigint {
  if (!raw) return fallback;
  if (!/^[0-9]+$/.test(raw)) {
    throw new Error(`Invalid ${name}: ${raw}`);
  }
  return BigInt(raw);
}

function parseBooleanEnv(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (["true", "1", "yes", "y", "on"].includes(normalized)) return true;
  if (["false", "0", "no", "n", "off"].includes(normalized)) return false;
  return fallback;
}

function toSnapshot(
  marketId: number,
  epoch: number,
  assetsMicroUsdc: bigint,
  liabilitiesMicroUsdc: bigint,
  txHash?: string,
  proofUri?: string
): PorProofSnapshot {
  const coverageBps =
    liabilitiesMicroUsdc === 0n ? 0 : Number((assetsMicroUsdc * 10000n) / liabilitiesMicroUsdc);
  const healthy = liabilitiesMicroUsdc > 0n && coverageBps >= 10000;
  const updatedAt = nowIso();

  const proofHash = hashObject({
    marketId,
    epoch,
    assetsMicroUsdc: assetsMicroUsdc.toString(),
    liabilitiesMicroUsdc: liabilitiesMicroUsdc.toString(),
    coverageBps,
    healthy,
    updatedAt
  });

  return {
    marketId,
    epoch,
    assetsMicroUsdc: assetsMicroUsdc.toString(),
    liabilitiesMicroUsdc: liabilitiesMicroUsdc.toString(),
    coverageBps,
    healthy,
    proofHash,
    proofUri,
    txHash,
    updatedAt
  };
}

function fallbackStatus(): PorStatusPayload {
  const marketId = parsePositiveInt("POR_MARKET_ID", process.env.POR_MARKET_ID, 1);
  const epoch = parsePositiveInt("POR_EPOCH", process.env.POR_EPOCH, 1);
  const assets = parseNonNegativeBigInt("POR_ASSETS_MICROUSDC", process.env.POR_ASSETS_MICROUSDC, 1_000_000_000n);
  const liabilities = parseNonNegativeBigInt(
    "POR_LIABILITIES_MICROUSDC",
    process.env.POR_LIABILITIES_MICROUSDC,
    950_000_000n
  );
  const txHash = process.env.POR_TX_HASH?.trim() || undefined;

  const latest = toSnapshot(marketId, epoch, assets, liabilities, txHash);

  return {
    mode: "MOCK",
    source: "env-fallback",
    latest,
    history: [latest]
  };
}

function resolvePorOnchainReadEnabled(): boolean {
  return parseBooleanEnv(process.env.POR_ONCHAIN_READ_ENABLED, true);
}

function resolvePorOnchainReadStrict(): boolean {
  return parseBooleanEnv(process.env.POR_ONCHAIN_READ_STRICT, false);
}

function isHex32(value: string): boolean {
  return /^0x[0-9a-fA-F]{64}$/.test(value);
}

function isTxHash(value: string): boolean {
  return /^0x[0-9a-fA-F]{64}$/.test(value);
}

function sanitizeProofs(proofs: PorProofSnapshot[]): PorProofSnapshot[] {
  const cleaned = proofs
    .filter((proof) => Number.isFinite(proof.marketId) && proof.marketId >= 0)
    .filter((proof) => Number.isFinite(proof.epoch) && proof.epoch >= 0)
    .filter((proof) => /^[0-9]+$/.test(proof.assetsMicroUsdc))
    .filter((proof) => /^[0-9]+$/.test(proof.liabilitiesMicroUsdc))
    .filter((proof) => Number.isFinite(proof.coverageBps) && proof.coverageBps >= 0)
    .filter((proof) => typeof proof.healthy === "boolean")
    .filter((proof) => typeof proof.updatedAt === "string")
    .filter((proof) => isHex32(proof.proofHash))
    .filter((proof) => proof.txHash === undefined || isTxHash(proof.txHash))
    .sort((a, b) => b.epoch - a.epoch)
    .slice(0, 20);

  return cleaned;
}

export async function getPorStatusSnapshot(): Promise<PorStatusPayload> {
  if (resolvePorOnchainReadEnabled()) {
    try {
      const marketId = parsePositiveInt("POR_MARKET_ID", process.env.POR_MARKET_ID, 1);
      const onchainProofs = await listPorProofsFromOnchain({
        marketId,
        limit: 20
      });
      if (onchainProofs.length > 0) {
        return {
          mode: "ONCHAIN",
          source: "contract:event:PorProofRecorded",
          latest: onchainProofs[0],
          history: onchainProofs
        };
      }
    } catch (error) {
      if (resolvePorOnchainReadStrict()) {
        throw error;
      }
    }
  }

  const fallback = fallbackStatus();
  const file = await readJsonFile<PorHistoryFileSchema>(POR_HISTORY_PATH, {
    proofs: []
  });

  const sanitized = sanitizeProofs(file.proofs);
  if (sanitized.length === 0) {
    return fallback;
  }

  return {
    mode: "FILE",
    source: "reports/por-history.json",
    latest: sanitized[0],
    history: sanitized
  };
}

export async function buildNextPorProofInput(args: {
  requestId: string;
  verificationTxHash?: string;
}): Promise<NextPorProofInput> {
  const marketId = parsePositiveInt("POR_MARKET_ID", process.env.POR_MARKET_ID, 1);
  const baseEpoch = parsePositiveInt("POR_EPOCH", process.env.POR_EPOCH, 1);
  const baseAssets = parseNonNegativeBigInt("POR_ASSETS_MICROUSDC", process.env.POR_ASSETS_MICROUSDC, 1_000_000_000n);
  const baseLiabilities = parseNonNegativeBigInt(
    "POR_LIABILITIES_MICROUSDC",
    process.env.POR_LIABILITIES_MICROUSDC,
    950_000_000n
  );
  const deltaAssets = parseNonNegativeBigInt(
    "POR_AUTO_DELTA_ASSETS_MICROUSDC",
    process.env.POR_AUTO_DELTA_ASSETS_MICROUSDC,
    10_000_000n
  );
  const deltaLiabilities = parseNonNegativeBigInt(
    "POR_AUTO_DELTA_LIABILITIES_MICROUSDC",
    process.env.POR_AUTO_DELTA_LIABILITIES_MICROUSDC,
    9_000_000n
  );

  const latest = await getLatestPorProofFromOnchain(marketId);
  let epoch = baseEpoch;
  let assetsMicroUsdc = baseAssets;
  let liabilitiesMicroUsdc = baseLiabilities;

  if (latest) {
    epoch = latest.epoch + 1;
    assetsMicroUsdc = BigInt(latest.assetsMicroUsdc) + deltaAssets;
    liabilitiesMicroUsdc = BigInt(latest.liabilitiesMicroUsdc) + deltaLiabilities;
  }

  if (liabilitiesMicroUsdc == 0n) {
    throw new Error("POR liabilities cannot be zero");
  }

  const proofHash = hashObject({
    marketId,
    epoch,
    assetsMicroUsdc: assetsMicroUsdc.toString(),
    liabilitiesMicroUsdc: liabilitiesMicroUsdc.toString(),
    requestId: args.requestId,
    verificationTxHash: args.verificationTxHash ?? null
  });

  return {
    marketId,
    epoch,
    assetsMicroUsdc: assetsMicroUsdc.toString(),
    liabilitiesMicroUsdc: liabilitiesMicroUsdc.toString(),
    proofHash,
    proofUri: `por://verification/${args.requestId}`
  };
}
