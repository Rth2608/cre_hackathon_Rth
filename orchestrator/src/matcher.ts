import type { CanonicalModelFamily, RegisteredNode } from "./types";
import { DEFAULT_RUNTIME_NODES, type RuntimeNode } from "./mockNodes";

const FAMILY_ORDER: CanonicalModelFamily[] = ["gpt", "gemini", "claude", "grok"];

interface MatchOptions {
  desiredNodes?: number;
  minStakeAmount?: string;
  allowDefaultNodes?: boolean;
  requireEndpointUrl?: boolean;
  requireHealthyEndpoint?: boolean;
  heartbeatTtlSeconds?: number;
}

export interface MatchResult {
  runtimeNodes: RuntimeNode[];
  selectedNodes: RegisteredNode[];
  usedDefaultNodes: boolean;
}

function parseStake(value: string | undefined): bigint {
  if (!value || !/^[0-9]+$/.test(value)) return 0n;
  return BigInt(value);
}

function sortCandidates(nodes: RegisteredNode[]): RegisteredNode[] {
  return [...nodes].sort((a, b) => {
    const stakeDiff = parseStake(b.stakeAmount) - parseStake(a.stakeAmount);
    if (stakeDiff > 0n) return 1;
    if (stakeDiff < 0n) return -1;
    return b.updatedAt.localeCompare(a.updatedAt);
  });
}

function toRuntime(node: RegisteredNode, family: CanonicalModelFamily): RuntimeNode {
  return {
    nodeId: node.nodeId,
    modelFamily: family,
    modelName: node.modelName,
    operatorAddress: node.walletAddress
  };
}

function isHeartbeatRecent(node: RegisteredNode, heartbeatTtlSeconds: number | undefined): boolean {
  if (!heartbeatTtlSeconds || heartbeatTtlSeconds <= 0) {
    return true;
  }
  if (!node.endpointLastHeartbeatAt) {
    return false;
  }

  const heartbeatAt = Date.parse(node.endpointLastHeartbeatAt);
  if (Number.isNaN(heartbeatAt)) {
    return false;
  }

  const ageMs = Date.now() - heartbeatAt;
  return ageMs <= heartbeatTtlSeconds * 1000;
}

export function selectRuntimeNodesForRequest(registeredNodes: RegisteredNode[], options?: MatchOptions): MatchResult {
  const desiredNodes = options?.desiredNodes ?? 4;
  const minStake = parseStake(options?.minStakeAmount ?? "0");
  const allowDefaultNodes = options?.allowDefaultNodes ?? true;
  const requireEndpointUrl = options?.requireEndpointUrl ?? false;
  const requireHealthyEndpoint = options?.requireHealthyEndpoint ?? false;
  const heartbeatTtlSeconds = options?.heartbeatTtlSeconds;

  const candidates = sortCandidates(
    registeredNodes.filter((node) => {
      if (node.status !== "ACTIVE") return false;
      if (!node.participationEnabled) return false;
      if (!Array.isArray(node.selectedModelFamilies) || node.selectedModelFamilies.length === 0) return false;
      if (requireEndpointUrl && !node.endpointUrl) return false;
      if (requireHealthyEndpoint && node.endpointStatus !== "HEALTHY") return false;
      if (!isHeartbeatRecent(node, heartbeatTtlSeconds)) return false;
      return parseStake(node.stakeAmount) >= minStake;
    })
  );

  const selectedNodes: RegisteredNode[] = [];
  const selectedRuntimeNodes: RuntimeNode[] = [];
  const selectedNodeIds = new Set<string>();
  const usedFamilies = new Set<CanonicalModelFamily>();

  for (const family of FAMILY_ORDER) {
    if (selectedNodes.length >= desiredNodes) break;
    const node = candidates.find(
      (candidate) => !selectedNodeIds.has(candidate.registrationId) && candidate.selectedModelFamilies.includes(family)
    );
    if (!node) continue;
    selectedNodes.push(node);
    selectedRuntimeNodes.push(toRuntime(node, family));
    selectedNodeIds.add(node.registrationId);
    usedFamilies.add(family);
  }

  for (const node of candidates) {
    if (selectedNodes.length >= desiredNodes) break;
    if (selectedNodeIds.has(node.registrationId)) continue;
    const family = node.selectedModelFamilies.find((item) => !usedFamilies.has(item)) ?? node.selectedModelFamilies[0];
    if (!family) continue;
    selectedNodes.push(node);
    selectedRuntimeNodes.push(toRuntime(node, family));
    selectedNodeIds.add(node.registrationId);
    usedFamilies.add(family);
  }

  if (selectedRuntimeNodes.length === 0 && allowDefaultNodes) {
    return {
      runtimeNodes: DEFAULT_RUNTIME_NODES,
      selectedNodes: [],
      usedDefaultNodes: true
    };
  }

  return {
    runtimeNodes: selectedRuntimeNodes,
    selectedNodes,
    usedDefaultNodes: false
  };
}
