import { FormEvent, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  IDKitWidget,
  type IErrorState,
  type ISuccessResult,
  VerificationLevel as IDKitVerificationLevel
} from "@worldcoin/idkit";
import {
  MiniKit,
  type MiniKitInstallReturnType,
  type MiniAppVerifyActionPayload,
  VerificationLevel as MiniKitVerificationLevel
} from "@worldcoin/minikit-js";
import { ConnectButton, useActiveAccount } from "thirdweb/react";
import { signMessage } from "thirdweb/utils";
import AppNav from "../components/AppNav";
import {
  activateNodeChallenge,
  listNodes,
  listRequests,
  requestNodeChallenge,
  sendNodeHeartbeat,
  verifyWorldIdForWallet,
  type RegisteredNode,
  type RequestRecord,
  type WorldIdSession
} from "../lib/api";
import { clearWorldIdSession, getWorldIdConfig, isWorldIdConfigured, loadWorldIdSession, saveWorldIdSession } from "../lib/worldId";
import { isThirdwebClientConfigured, thirdwebClient } from "../lib/thirdweb";

const MODEL_FAMILIES = ["gpt", "gemini", "claude", "grok"] as const;
type ModelFamily = (typeof MODEL_FAMILIES)[number];

function buildNodeHeartbeatMessage(input: { walletAddress: string; endpointUrl: string; timestamp: number }): string {
  return [
    "CRE Node Heartbeat",
    `walletAddress: ${input.walletAddress}`,
    `endpointUrl: ${input.endpointUrl}`,
    `timestamp: ${input.timestamp}`
  ].join("\n");
}

function toLowerAddress(value: string): string {
  return value.trim().toLowerCase();
}

function formatEndpointHealth(node: RegisteredNode): string {
  const latency = typeof node.endpointLatencyMs === "number" ? `${node.endpointLatencyMs}ms` : "-";
  const error = node.endpointLastError ? ` / ${node.endpointLastError}` : "";
  return `${node.endpointStatus} (${latency})${error}`;
}

function buildWorldProofFromIdKit(result: ISuccessResult): Record<string, unknown> {
  return {
    merkle_root: result.merkle_root,
    nullifier_hash: result.nullifier_hash,
    proof: result.proof,
    verification_level: result.verification_level
  };
}

function buildWorldProofFromMiniKit(payload: MiniAppVerifyActionPayload): Record<string, unknown> | null {
  if (payload.status !== "success") {
    return null;
  }

  if ("proof" in payload && typeof payload.proof === "string") {
    return {
      merkle_root: payload.merkle_root,
      nullifier_hash: payload.nullifier_hash,
      proof: payload.proof,
      verification_level: payload.verification_level
    };
  }

  if ("verifications" in payload && Array.isArray(payload.verifications) && payload.verifications.length > 0) {
    const first = payload.verifications[0];
    return {
      merkle_root: first.merkle_root,
      nullifier_hash: first.nullifier_hash,
      proof: first.proof,
      verification_level: first.verification_level
    };
  }

  return null;
}

function getWorldIdErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isMiniKitInstallUsable(installResult: MiniKitInstallReturnType): boolean {
  if (installResult.success) {
    return true;
  }
  return installResult.errorCode === "already_installed";
}

export default function VerifyPage() {
  const activeAccount = useActiveAccount();
  const walletAddress = activeAccount?.address ?? "";
  const walletConnected = walletAddress.length > 0;
  const thirdwebConfigured = isThirdwebClientConfigured();
  const worldIdConfigured = isWorldIdConfigured();
  const worldIdConfig = getWorldIdConfig();

  const [requests, setRequests] = useState<RequestRecord[]>([]);
  const [nodes, setNodes] = useState<RegisteredNode[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [registeringNode, setRegisteringNode] = useState(false);
  const [sendingHeartbeat, setSendingHeartbeat] = useState(false);
  const [registrationMessage, setRegistrationMessage] = useState<string | null>(null);
  const [verifyingWorldId, setVerifyingWorldId] = useState(false);
  const [worldProofJson, setWorldProofJson] = useState("");
  const [miniKitAvailable, setMiniKitAvailable] = useState(false);
  const [worldIdSession, setWorldIdSession] = useState<WorldIdSession | null>(null);
  const [nodeForm, setNodeForm] = useState<{
    selectedModelFamilies: ModelFamily[];
    stakeAmount: string;
    participationEnabled: boolean;
  }>({
    selectedModelFamilies: ["gpt"],
    stakeAmount: "1000",
    participationEnabled: true
  });

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [requestItems, nodeItems] = await Promise.all([listRequests(), listNodes()]);
      setRequests(requestItems);
      setNodes(nodeItems);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  useEffect(() => {
    if (!walletConnected) {
      setWorldIdSession(null);
      return;
    }
    setWorldIdSession(loadWorldIdSession(walletAddress));
  }, [walletAddress, walletConnected]);

  useEffect(() => {
    if (!worldIdConfigured || !walletConnected) {
      setMiniKitAvailable(false);
      return;
    }

    try {
      const installResult = MiniKit.install(worldIdConfig.appId);
      setMiniKitAvailable(isMiniKitInstallUsable(installResult));
    } catch {
      setMiniKitAvailable(false);
    }
  }, [walletConnected, worldIdConfig.appId, worldIdConfigured]);

  const verifyWorldIdWithProof = async (proof: Record<string, unknown>, sourceLabel: string) => {
    const result = await verifyWorldIdForWallet({
      walletAddress,
      proof
    });
    saveWorldIdSession(walletAddress, result.session);
    setWorldIdSession(result.session);
    setRegistrationMessage(
      `${sourceLabel} verification succeeded. Session valid until ${new Date(result.session.expiresAt).toLocaleString()}.`
    );
  };

  const onVerifyWorldIdManual = async () => {
    setRegistrationMessage(null);
    setError(null);

    if (!walletConnected) {
      setError("Connect wallet before World ID verification.");
      return;
    }
    if (!worldIdConfigured) {
      setError("Missing VITE_WORLD_ID_APP_ID / VITE_WORLD_ID_ACTION.");
      return;
    }

    let parsedProof: Record<string, unknown>;
    try {
      parsedProof = JSON.parse(worldProofJson) as Record<string, unknown>;
    } catch {
      setError("World ID proof JSON is invalid.");
      return;
    }

    setVerifyingWorldId(true);
    try {
      await verifyWorldIdWithProof(parsedProof, "Manual");
    } catch (err) {
      setError(getWorldIdErrorMessage(err));
    } finally {
      setVerifyingWorldId(false);
    }
  };

  const onVerifyWorldIdMiniApp = async () => {
    setRegistrationMessage(null);
    setError(null);

    if (!walletConnected) {
      setError("Connect wallet before World ID verification.");
      return;
    }
    if (!worldIdConfigured) {
      setError("Missing VITE_WORLD_ID_APP_ID / VITE_WORLD_ID_ACTION.");
      return;
    }

    setVerifyingWorldId(true);
    try {
      const installResult = MiniKit.install(worldIdConfig.appId);
      if (!isMiniKitInstallUsable(installResult)) {
        const errorCode = installResult.success ? "unknown" : installResult.errorCode;
        throw new Error(`minikit_unavailable: ${errorCode}`);
      }
      setMiniKitAvailable(true);

      const { finalPayload } = await MiniKit.commandsAsync.verify({
        action: worldIdConfig.action,
        signal: walletAddress,
        verification_level: MiniKitVerificationLevel.Device
      });

      const proof = buildWorldProofFromMiniKit(finalPayload);
      if (!proof) {
        if (finalPayload.status === "error") {
          throw new Error(`world_id_verify_failed: ${finalPayload.error_code}`);
        }
        throw new Error("world_id_verify_failed: invalid_miniapp_payload");
      }

      await verifyWorldIdWithProof(proof, "Mini App");
    } catch (err) {
      setError(getWorldIdErrorMessage(err));
    } finally {
      setVerifyingWorldId(false);
    }
  };

  const onVerifyWorldIdExternal = async (result: ISuccessResult) => {
    if (!walletConnected) {
      setError("Connect wallet before World ID verification.");
      return;
    }
    setRegistrationMessage(null);
    setError(null);
    setVerifyingWorldId(true);
    try {
      await verifyWorldIdWithProof(buildWorldProofFromIdKit(result), "External Widget");
    } catch (err) {
      setError(getWorldIdErrorMessage(err));
      throw err;
    } finally {
      setVerifyingWorldId(false);
    }
  };

  const onWorldIdExternalError = (errorState: IErrorState) => {
    setError(`world_id_widget_error: ${errorState.code}`);
  };

  const onClearWorldId = () => {
    if (!walletConnected) {
      return;
    }
    clearWorldIdSession(walletAddress);
    setWorldIdSession(null);
    setRegistrationMessage("World ID session was cleared for this wallet.");
  };

  const onRegisterNode = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setRegistrationMessage(null);

    if (!thirdwebConfigured) {
      setError("Missing VITE_THIRDWEB_CLIENT_ID. Configure dapp/.env and restart.");
      return;
    }
    if (!walletConnected || !activeAccount) {
      setError("Connect wallet before registering a node.");
      return;
    }
    if (nodeForm.selectedModelFamilies.length === 0) {
      setError("Select at least one model family.");
      return;
    }
    if (!worldIdSession?.token) {
      setError("Verify World ID first and obtain a session token.");
      return;
    }

    setRegisteringNode(true);
    setError(null);
    try {
      const challengeResult = await requestNodeChallenge({
        walletAddress,
        selectedModelFamilies: nodeForm.selectedModelFamilies,
        stakeAmount: nodeForm.stakeAmount,
        participationEnabled: nodeForm.participationEnabled,
        worldIdToken: worldIdSession.token
      });
      const challenge = challengeResult.challenge;
      const signature = await signMessage({
        account: activeAccount,
        message: challenge.challengeMessage
      });

      const activated = await activateNodeChallenge({
        challengeId: challenge.challengeId,
        walletAddress,
        signature
      });

      const health = activated.endpointProbe.ok ? "HEALTHY" : `UNHEALTHY (${activated.endpointProbe.error ?? "unknown"})`;
      const lifecycleTx = activated.lifecycleOnchainReceipt?.txHash
        ? `, tx=${activated.lifecycleOnchainReceipt.txHash}`
        : "";
      setRegistrationMessage(
        `Node ${activated.node.nodeId} activated. endpoint=${health}, x402=${challengeResult.paymentReceipt.paymentRef.slice(0, 14)}...${lifecycleTx}`
      );
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setRegisteringNode(false);
    }
  };

  const myActiveNode = useMemo(
    () => nodes.find((node) => node.walletAddress.toLowerCase() === walletAddress.toLowerCase() && node.status === "ACTIVE"),
    [nodes, walletAddress]
  );

  const onSendHeartbeat = async () => {
    setRegistrationMessage(null);

    if (!walletConnected || !activeAccount || !myActiveNode) {
      setError("Connect wallet and activate node first.");
      return;
    }
    if (!myActiveNode.endpointUrl) {
      setError("Current node has no endpoint URL.");
      return;
    }

    setSendingHeartbeat(true);
    setError(null);
    try {
      const timestamp = Date.now();
      const heartbeatMessage = buildNodeHeartbeatMessage({
        walletAddress: toLowerAddress(walletAddress),
        endpointUrl: myActiveNode.endpointUrl,
        timestamp
      });
      const signature = await signMessage({
        account: activeAccount,
        message: heartbeatMessage
      });

      const result = await sendNodeHeartbeat({
        walletAddress,
        endpointUrl: myActiveNode.endpointUrl,
        timestamp,
        signature
      });

      const lifecycleTx = result.lifecycleOnchainReceipt?.txHash ? `, tx=${result.lifecycleOnchainReceipt.txHash}` : "";
      setRegistrationMessage(
        `Heartbeat accepted. endpoint=${result.node.endpointStatus}, checkedAt=${result.node.endpointLastCheckedAt ?? "-"}${lifecycleTx}`
      );
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSendingHeartbeat(false);
    }
  };

  const toggleModelFamily = (family: ModelFamily) => {
    setNodeForm((prev) => {
      const exists = prev.selectedModelFamilies.includes(family);
      const selectedModelFamilies = exists
        ? prev.selectedModelFamilies.filter((item) => item !== family)
        : [...prev.selectedModelFamilies, family];

      return {
        ...prev,
        selectedModelFamilies
      };
    });
  };

  return (
    <div className="page-shell">
      <main className="panel">
        <AppNav current="verify" />
        <header className="hero compact">
          <p className="eyebrow">Verifier Participation</p>
          <h1>Operator Verify Settings</h1>
          <p>
            DON-like flow: create registration challenge, sign with wallet, then activate node. Node ID is fixed to your
            wallet address.
          </p>
          <div className="wallet-row">
            {thirdwebConfigured ? (
              <ConnectButton
                client={thirdwebClient}
                connectButton={{ className: "wallet-connect-btn", label: "Connect Wallet" }}
              />
            ) : (
              <p className="config-warning">
                Missing <code>VITE_THIRDWEB_CLIENT_ID</code>. Wallet login is disabled.
              </p>
            )}
            {walletConnected && <p className="wallet-info mono">Connected: {walletAddress}</p>}
          </div>
          <div className="inline-row">
            <Link to="/" className="text-link">
              Back to Request
            </Link>
            <button type="button" className="secondary" onClick={load}>
              Refresh List
            </button>
          </div>
        </header>

        <section className="status-card">
          <h2>World ID Verification</h2>
          <p>
            Verify with Mini App (World App) or External Widget. A wallet-bound World ID session token is required before node
            activation.
          </p>
          <p className="config-warning">
            App ID: {worldIdConfig.appId || "-"} / Action: {worldIdConfig.action || "-"}
          </p>
          <div className="action-row">
            <button
              type="button"
              onClick={onVerifyWorldIdMiniApp}
              disabled={!walletConnected || verifyingWorldId || !worldIdConfigured}
            >
              {verifyingWorldId ? "Verifying..." : "Verify in World Mini App"}
            </button>
            {worldIdConfigured ? (
              <IDKitWidget
                app_id={worldIdConfig.appId}
                action={worldIdConfig.action}
                signal={walletAddress}
                verification_level={IDKitVerificationLevel.Device}
                handleVerify={onVerifyWorldIdExternal}
                onSuccess={() => undefined}
                onError={onWorldIdExternalError}
              >
                {({ open }: { open: () => void }) => (
                  <button type="button" className="secondary" onClick={open} disabled={!walletConnected || verifyingWorldId}>
                    Verify with External Widget
                  </button>
                )}
              </IDKitWidget>
            ) : (
              <button type="button" className="secondary" disabled>
                Verify with External Widget
              </button>
            )}
            <button type="button" className="secondary" onClick={onClearWorldId} disabled={!walletConnected}>
              Clear Session
            </button>
          </div>
          {!miniKitAvailable && (
            <p className="config-warning">
              Mini App verification is available only inside World App. For desktop browser testing, use External Widget.
            </p>
          )}
          <details className="manual-world-proof">
            <summary>Manual proof JSON (simulator fallback)</summary>
            <label>
              World ID Proof JSON
              <textarea
                value={worldProofJson}
                onChange={(event) => setWorldProofJson(event.target.value)}
                rows={7}
                placeholder='{"merkle_root":"0x...","nullifier_hash":"0x...","proof":"0x...","verification_level":"device"}'
              />
            </label>
            <div className="action-row">
              <button
                type="button"
                className="secondary"
                onClick={onVerifyWorldIdManual}
                disabled={!walletConnected || verifyingWorldId || !worldIdConfigured}
              >
                {verifyingWorldId ? "Verifying..." : "Verify Manual Proof"}
              </button>
            </div>
          </details>
          {worldIdSession ? (
            <p>
              Session token active until {new Date(worldIdSession.expiresAt).toLocaleString()} ({worldIdSession.source}).
            </p>
          ) : (
            <p>No active World ID session for this wallet.</p>
          )}
        </section>

        <section className="status-card">
          <h2>Register / Update Node</h2>
          <form onSubmit={onRegisterNode} className="form-grid compact-form">
            <p className="config-warning">Node ID is auto-assigned as your wallet address.</p>
            <label>
              Stake Amount (token unit)
              <input
                value={nodeForm.stakeAmount}
                onChange={(event) => setNodeForm((prev) => ({ ...prev, stakeAmount: event.target.value }))}
                inputMode="numeric"
                pattern="[0-9]+"
                required
              />
            </label>
            <fieldset className="family-picker">
              <legend>LLM Family Participation (select 1~4)</legend>
              <div className="family-grid">
                {MODEL_FAMILIES.map((family) => (
                  <label key={family} className="family-option">
                    <input
                      type="checkbox"
                      checked={nodeForm.selectedModelFamilies.includes(family)}
                      onChange={() => toggleModelFamily(family)}
                    />
                    <span>{family}</span>
                  </label>
                ))}
              </div>
            </fieldset>
            <label className="inline-check">
              <input
                type="checkbox"
                checked={nodeForm.participationEnabled}
                onChange={(event) => setNodeForm((prev) => ({ ...prev, participationEnabled: event.target.checked }))}
              />
              <span>Participate in auto-matching for new requests</span>
            </label>
            <p className="config-warning">
              Model Name / Endpoint URL are auto-assigned by server mapping for this wallet.
            </p>
            <div className="action-row">
              <button type="submit" disabled={!walletConnected || registeringNode || !thirdwebConfigured}>
                {registeringNode ? "Signing / Activating..." : "Sign And Activate Node"}
              </button>
            </div>
          </form>
          {myActiveNode ? (
            <div>
              <p>
                <strong>My Active Node:</strong> {myActiveNode.nodeId} ({myActiveNode.selectedModelFamilies.join(", ")}
                {" / "}
                {myActiveNode.modelName}) | stake={myActiveNode.stakeAmount} |{" "}
                {myActiveNode.participationEnabled ? "participating" : "paused"}
              </p>
              <p>
                endpoint={myActiveNode.endpointUrl ?? "-"} | health={formatEndpointHealth(myActiveNode)}
              </p>
              <div className="action-row">
                <button
                  type="button"
                  className="secondary"
                  onClick={onSendHeartbeat}
                  disabled={sendingHeartbeat || !walletConnected || !myActiveNode.endpointUrl}
                >
                  {sendingHeartbeat ? "Sending Heartbeat..." : "Send Signed Heartbeat"}
                </button>
              </div>
            </div>
          ) : (
            <p>No active node for this wallet yet.</p>
          )}
          {registrationMessage && <p>{registrationMessage}</p>}
        </section>

        <section className="status-card">
          <h2>Auto Verification Flow</h2>
          <p>Manual verification is disabled in this page. Verification runs automatically on request submission.</p>
          <p>
            Flow: <code>request submit - x402 check - node match - consensus - on-chain finalize</code>
          </p>
        </section>

        <section className="status-card">
          <h2>Recent Requests</h2>
          <p className="config-warning">This list is loaded from on-chain finalization events for the active registry.</p>
          {loading ? (
            <p>Loading requests...</p>
          ) : requests.length === 0 ? (
            <p>No requests yet. Create one in the Request page.</p>
          ) : (
            <div className="request-table">
              <div className="request-head">
                <span>Request</span>
                <span>Status</span>
                <span>Attempts</span>
                <span>Updated</span>
                <span>Action</span>
              </div>
              {requests.map((record) => {
                return (
                  <div key={record.requestId} className="request-row">
                    <span className="mono small">{record.requestId}</span>
                    <span className={`status-badge ${record.status === "FINALIZED" ? "ok" : "warn"}`}>
                      {record.status}
                    </span>
                    <span>{record.runAttempts}/2</span>
                    <span>{new Date(record.updatedAt).toLocaleString()}</span>
                    <span className="inline-row">
                      <Link className="text-link" to={`/result/${encodeURIComponent(record.requestId)}`}>
                        Result
                      </Link>
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </section>

        <section className="status-card">
          <h2>Active Nodes</h2>
          <p className="config-warning">
            This list is reconstructed from on-chain node lifecycle events (activation/heartbeat).
          </p>
          {nodes.length === 0 ? (
            <p>No registered nodes. Default mock 4 nodes will be used unless server requires registered nodes.</p>
          ) : (
            <div className="request-table">
              <div className="request-head">
                <span>Node ID</span>
                <span>Models / Stake</span>
                <span>Endpoint</span>
                <span>Health</span>
                <span>Wallet</span>
                <span>Updated</span>
              </div>
              {nodes.map((node) => (
                <div key={node.registrationId} className="request-row">
                  <span className="mono small">{node.nodeId}</span>
                  <span>
                    {node.selectedModelFamilies.join(", ")} / stake={node.stakeAmount}
                  </span>
                  <span className="mono small">{node.endpointUrl ?? "-"}</span>
                  <span className={`status-badge ${node.endpointStatus === "HEALTHY" ? "ok" : "warn"}`}>
                    {node.endpointStatus}
                  </span>
                  <span className="mono small">{node.walletAddress}</span>
                  <span>{new Date(node.updatedAt).toLocaleString()}</span>
                </div>
              ))}
            </div>
          )}
        </section>

        {error && <p className="error-text">{error}</p>}
      </main>
    </div>
  );
}
