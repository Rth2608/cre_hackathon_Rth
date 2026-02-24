import { Wallet, getAddress } from "ethers";

export const DEFAULT_DON_OPERATOR_PRIVATE_KEYS_BY_NODE_ID: Record<string, string> = {
  gpt: "0x1000000000000000000000000000000000000000000000000000000000000001",
  gemini: "0x2000000000000000000000000000000000000000000000000000000000000002",
  claude: "0x3000000000000000000000000000000000000000000000000000000000000003",
  grok: "0x4000000000000000000000000000000000000000000000000000000000000004"
};

export const DEFAULT_DON_OPERATOR_ADDRESS_BY_NODE_ID: Record<string, string> = Object.fromEntries(
  Object.entries(DEFAULT_DON_OPERATOR_PRIVATE_KEYS_BY_NODE_ID).map(([nodeId, privateKey]) => [
    nodeId,
    new Wallet(privateKey).address
  ])
);

function normalizePrivateKey(value: string, fieldName: string): string {
  const normalized = value.trim();
  if (!/^0x[0-9a-fA-F]{64}$/.test(normalized)) {
    throw new Error(`Invalid private key format for ${fieldName}`);
  }
  return normalized.toLowerCase();
}

function tryNormalizeAddress(value: string): string | null {
  try {
    return getAddress(value).toLowerCase();
  } catch {
    return null;
  }
}

export function parseDonOperatorPrivateKeyMap(raw: string | undefined): Record<string, string> {
  if (!raw || raw.trim().length === 0) {
    return {};
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`Failed to parse DON_OPERATOR_PRIVATE_KEYS_JSON: ${error instanceof Error ? error.message : String(error)}`);
  }

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("DON_OPERATOR_PRIVATE_KEYS_JSON must be a JSON object");
  }

  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
    if (typeof value !== "string") {
      throw new Error(`DON_OPERATOR_PRIVATE_KEYS_JSON value for key '${key}' must be a string private key`);
    }
    const normalizedKey = key.trim().toLowerCase();
    if (!normalizedKey) {
      throw new Error("DON_OPERATOR_PRIVATE_KEYS_JSON includes an empty key");
    }
    result[normalizedKey] = normalizePrivateKey(value, key);
  }
  return result;
}

export function getSignerAddressFromPrivateKey(privateKey: string): string {
  return new Wallet(normalizePrivateKey(privateKey, "privateKey")).address;
}

export function resolveDonSignerPrivateKey(args: {
  nodeId: string;
  operatorAddress: string;
  customMap?: Record<string, string>;
}): string | null {
  const nodeId = args.nodeId.trim().toLowerCase();
  const normalizedOperatorAddress = tryNormalizeAddress(args.operatorAddress);
  const customMap = args.customMap ?? {};

  if (normalizedOperatorAddress && customMap[normalizedOperatorAddress]) {
    return customMap[normalizedOperatorAddress]!;
  }
  if (customMap[nodeId]) {
    return customMap[nodeId]!;
  }

  const defaultByNodeId = DEFAULT_DON_OPERATOR_PRIVATE_KEYS_BY_NODE_ID[nodeId];
  if (defaultByNodeId) {
    const defaultAddress = DEFAULT_DON_OPERATOR_ADDRESS_BY_NODE_ID[nodeId]?.toLowerCase();
    if (!normalizedOperatorAddress || normalizedOperatorAddress === defaultAddress) {
      return defaultByNodeId;
    }
  }

  if (normalizedOperatorAddress) {
    for (const [candidateNodeId, address] of Object.entries(DEFAULT_DON_OPERATOR_ADDRESS_BY_NODE_ID)) {
      if (address.toLowerCase() === normalizedOperatorAddress) {
        return DEFAULT_DON_OPERATOR_PRIVATE_KEYS_BY_NODE_ID[candidateNodeId] ?? null;
      }
    }
  }

  return null;
}
