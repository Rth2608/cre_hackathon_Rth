import { describe, expect, test } from "bun:test";
import { selectRuntimeNodesForRequest } from "./matcher";
import type { RegisteredNode } from "./types";

function node(input: Partial<RegisteredNode> & { walletAddress: string; modelName: string }): RegisteredNode {
  const now = new Date().toISOString();
  const wallet = input.walletAddress.toLowerCase();
  return {
    registrationId: input.registrationId ?? wallet,
    walletAddress: wallet,
    nodeId: input.nodeId ?? wallet,
    selectedModelFamilies: input.selectedModelFamilies ?? ["gpt"],
    modelName: input.modelName,
    endpointUrl: input.endpointUrl,
    peerId: input.peerId,
    tlsCertFingerprint: input.tlsCertFingerprint,
    endpointStatus: input.endpointStatus ?? "UNKNOWN",
    endpointLastCheckedAt: input.endpointLastCheckedAt ?? now,
    endpointLastHeartbeatAt: input.endpointLastHeartbeatAt,
    endpointLatencyMs: input.endpointLatencyMs,
    endpointFailureCount: input.endpointFailureCount ?? 0,
    endpointLastError: input.endpointLastError,
    endpointVerifiedAt: input.endpointVerifiedAt,
    stakeAmount: input.stakeAmount ?? "1000",
    participationEnabled: input.participationEnabled ?? true,
    worldIdVerified: input.worldIdVerified ?? true,
    status: input.status ?? "ACTIVE",
    registeredAt: input.registeredAt ?? now,
    updatedAt: input.updatedAt ?? now
  };
}

describe("matcher endpoint filters", () => {
  test("requires endpoint URL when enabled", () => {
    const withEndpoint = node({
      walletAddress: "0x1111111111111111111111111111111111111111",
      modelName: "node-a",
      selectedModelFamilies: ["gpt"],
      endpointUrl: "https://a.example.com",
      endpointStatus: "HEALTHY"
    });
    const withoutEndpoint = node({
      walletAddress: "0x2222222222222222222222222222222222222222",
      modelName: "node-b",
      selectedModelFamilies: ["gemini"],
      endpointStatus: "HEALTHY"
    });

    const result = selectRuntimeNodesForRequest([withEndpoint, withoutEndpoint], {
      desiredNodes: 2,
      allowDefaultNodes: false,
      requireEndpointUrl: true
    });

    expect(result.selectedNodes.length).toBe(1);
    expect(result.selectedNodes[0].walletAddress).toBe(withEndpoint.walletAddress);
  });

  test("requires HEALTHY endpoint when enabled", () => {
    const healthy = node({
      walletAddress: "0x3333333333333333333333333333333333333333",
      modelName: "node-c",
      selectedModelFamilies: ["gpt"],
      endpointUrl: "https://c.example.com",
      endpointStatus: "HEALTHY"
    });
    const unhealthy = node({
      walletAddress: "0x4444444444444444444444444444444444444444",
      modelName: "node-d",
      selectedModelFamilies: ["gemini"],
      endpointUrl: "https://d.example.com",
      endpointStatus: "UNHEALTHY",
      endpointFailureCount: 3
    });

    const result = selectRuntimeNodesForRequest([healthy, unhealthy], {
      desiredNodes: 2,
      allowDefaultNodes: false,
      requireHealthyEndpoint: true
    });

    expect(result.selectedNodes.length).toBe(1);
    expect(result.selectedNodes[0].walletAddress).toBe(healthy.walletAddress);
  });

  test("filters stale heartbeat when ttl is set", () => {
    const freshHeartbeat = new Date(Date.now() - 30_000).toISOString();
    const staleHeartbeat = new Date(Date.now() - 10 * 60_000).toISOString();

    const fresh = node({
      walletAddress: "0x5555555555555555555555555555555555555555",
      modelName: "node-e",
      selectedModelFamilies: ["gpt"],
      endpointUrl: "https://e.example.com",
      endpointStatus: "HEALTHY",
      endpointLastHeartbeatAt: freshHeartbeat
    });
    const stale = node({
      walletAddress: "0x6666666666666666666666666666666666666666",
      modelName: "node-f",
      selectedModelFamilies: ["gemini"],
      endpointUrl: "https://f.example.com",
      endpointStatus: "HEALTHY",
      endpointLastHeartbeatAt: staleHeartbeat
    });

    const result = selectRuntimeNodesForRequest([fresh, stale], {
      desiredNodes: 2,
      allowDefaultNodes: false,
      heartbeatTtlSeconds: 120
    });

    expect(result.selectedNodes.length).toBe(1);
    expect(result.selectedNodes[0].walletAddress).toBe(fresh.walletAddress);
  });
});
