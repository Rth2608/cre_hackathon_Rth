import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ConnectButton, useActiveAccount } from "thirdweb/react";
import AppNav from "../components/AppNav";
import { ApiRequestError, getRequest, runVerificationForWallet, type RequestRecord, type WorldIdSession } from "../lib/api";
import { isThirdwebClientConfigured, thirdwebClient } from "../lib/thirdweb";
import { clearWorldIdSession, loadWorldIdSession } from "../lib/worldId";
import { worldChainSepoliaChain } from "../lib/worldChain";

function scoreLabel(score?: number): string {
  if (typeof score !== "number") return "-";
  return `${(score * 100).toFixed(2)}%`;
}

function formatRequestId(value: string | undefined): string {
  if (!value) {
    return "-";
  }
  return value;
}

export default function ResultPage() {
  const { requestId } = useParams();
  const activeAccount = useActiveAccount();
  const walletAddress = activeAccount?.address ?? "";
  const walletConnected = walletAddress.length > 0;
  const thirdwebConfigured = isThirdwebClientConfigured();

  const [request, setRequest] = useState<RequestRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const [runningVerification, setRunningVerification] = useState(false);
  const [worldIdSession, setWorldIdSession] = useState<WorldIdSession | null>(null);
  const [lastRunTraceId, setLastRunTraceId] = useState<string | null>(null);
  const [traceCopied, setTraceCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    if (!requestId) {
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const reqData = await getRequest(requestId);
      setRequest(reqData);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, [requestId]);

  useEffect(() => {
    if (!walletConnected) {
      setWorldIdSession(null);
      return;
    }
    setWorldIdSession(loadWorldIdSession(walletAddress));
  }, [walletAddress, walletConnected]);

  const resultPath = requestId ? `/result/${encodeURIComponent(requestId)}` : "/result";
  const verifyLink = `${"/verify"}?returnTo=${encodeURIComponent(resultPath)}`;

  const worldIdSessionActive =
    worldIdSession && Number.isFinite(Date.parse(worldIdSession.expiresAt))
      ? Date.parse(worldIdSession.expiresAt) > Date.now()
      : Boolean(worldIdSession?.token);

  const ownedByConnectedWallet =
    request && walletConnected
      ? request.input.submitterAddress.trim().toLowerCase() === walletAddress.trim().toLowerCase()
      : false;

  const runVerificationReason = useMemo(() => {
    if (!requestId || !request) return "Request not loaded";
    if (!thirdwebConfigured) return "Set VITE_THIRDWEB_CLIENT_ID";
    if (!walletConnected || !activeAccount) return "Connect wallet";
    if (!ownedByConnectedWallet) return "Connected wallet does not match request submitter";
    if (request.status === "RUNNING") return "Already running";
    if (request.status === "FINALIZED") return "Already finalized";
    if (request.status === "REJECTED_DUPLICATE" || request.status === "REJECTED_CONFLICT") return "Rejected in queue screening";
    if (request.runAttempts >= 2) return "Max attempts reached";
    if (!worldIdSession?.token || !worldIdSessionActive) return "Verify World ID again";
    return "Ready";
  }, [requestId, request, thirdwebConfigured, walletConnected, activeAccount, ownedByConnectedWallet, worldIdSession, worldIdSessionActive]);

  const canRunVerification = runVerificationReason === "Ready";
  const derivedTraceId = requestId && request && request.runAttempts > 0 ? `${requestId}:run:${request.runAttempts}` : null;
  const effectiveTraceId = lastRunTraceId || derivedTraceId;

  const onCopyTraceId = async () => {
    if (!effectiveTraceId) {
      return;
    }
    try {
      await navigator.clipboard.writeText(effectiveTraceId);
      setTraceCopied(true);
      window.setTimeout(() => setTraceCopied(false), 1200);
    } catch {
      setTraceCopied(false);
    }
  };

  const onRunVerification = async () => {
    if (!requestId || !request) {
      return;
    }
    if (!activeAccount || !walletConnected) {
      setError("Connect wallet before running verification.");
      return;
    }
    if (!ownedByConnectedWallet) {
      setError("Connected wallet must match the request submitter to run verification.");
      return;
    }
    if (!worldIdSession?.token || !worldIdSessionActive) {
      setError("World ID session is missing or expired. Re-verify in Verify page.");
      return;
    }

    setRunningVerification(true);
    setError(null);
    try {
      const updated = await runVerificationForWallet(requestId, walletAddress, worldIdSession.token, activeAccount);
      const traceId = updated.traceId || updated.workflow?.traceId;
      if (traceId) {
        setLastRunTraceId(traceId);
      }

      clearWorldIdSession(walletAddress);
      setWorldIdSession(null);
      setRequest(updated);
      await load();
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (err instanceof ApiRequestError && err.traceId) {
        setLastRunTraceId(err.traceId);
      }
      if (message.includes("world_id_token_")) {
        clearWorldIdSession(walletAddress);
        setWorldIdSession(null);
      }
      setError(err instanceof ApiRequestError && err.traceId ? `${message} (traceId: ${err.traceId})` : message);
    } finally {
      setRunningVerification(false);
    }
  };

  if (loading) {
    return (
      <div className="page-shell">
        <main className="panel">
          <p>Loading request...</p>
        </main>
      </div>
    );
  }

  return (
    <div className="page-shell">
      <main className="panel">
        <AppNav current="result" />
        <header className="hero compact">
          <p className="eyebrow">Verification Result</p>
          <h1>Request</h1>
          <p className="wallet-info mono request-id-hero">{formatRequestId(requestId)}</p>
          <div className="wallet-row">
            {thirdwebConfigured ? (
              <ConnectButton
                client={thirdwebClient}
                chains={[worldChainSepoliaChain]}
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
            <Link to={verifyLink} className="text-link">
              Verify World ID
            </Link>
            <button type="button" className="secondary" onClick={load}>
              Refresh
            </button>
          </div>
        </header>

        {error && <p className="error-text">{error}</p>}

        {request && (
          <section className="grid-2">
            <article className="status-card">
              <h2>Request Status</h2>
              <p>
                <strong>Status:</strong>{" "}
                <span
                  className={`status-badge ${
                    request.status === "FINALIZED"
                      ? "ok"
                      : request.status === "REJECTED_DUPLICATE" ||
                          request.status === "REJECTED_CONFLICT" ||
                          request.status.startsWith("FAILED_")
                        ? "bad"
                        : "warn"
                  }`}
                >
                  {request.status}
                </span>
              </p>
              <p>
                <strong>Queue Priority:</strong> {request.queuePriority ?? "-"}
              </p>
              {request.queueDecision && (
                <>
                  <p>
                    <strong>Queue Decision:</strong> {request.queueDecision.decision}
                  </p>
                  <p>
                    <strong>Queue Source:</strong> {request.queueDecision.source}
                  </p>
                  <p>
                    <strong>Queue Reason:</strong> {request.queueDecision.reason ?? "-"}
                  </p>
                </>
              )}
              {request.vectorSync && (
                <>
                  <p>
                    <strong>Vector Sync:</strong> {request.vectorSync.state} / {request.vectorSync.vectorStatus}
                  </p>
                  <p>
                    <strong>Vector Attempts:</strong> {request.vectorSync.attempts}
                  </p>
                  <p>
                    <strong>Vector Updated:</strong> {new Date(request.vectorSync.updatedAt).toLocaleString()}
                  </p>
                  {request.vectorSync.lastError && (
                    <p>
                      <strong>Vector Error:</strong> {request.vectorSync.lastError}
                    </p>
                  )}
                </>
              )}
              <p>
                <strong>Attempts:</strong> {request.runAttempts}/2
              </p>
              <p>
                <strong>Updated:</strong> {new Date(request.updatedAt).toLocaleString()}
              </p>
              {request.lastError && (
                <p>
                  <strong>Error:</strong> {request.lastError}
                </p>
              )}
              <p>
                <strong>Manual Re-run:</strong> {canRunVerification ? "READY" : "BLOCKED"} ({runVerificationReason})
              </p>
              {effectiveTraceId && (
                <p>
                  <strong>Trace ID:</strong> <span className="mono">{effectiveTraceId}</span>
                </p>
              )}
              <div className="action-row">
                <button type="button" onClick={onRunVerification} disabled={runningVerification || !canRunVerification}>
                  {runningVerification ? "Running..." : "Run Verification Again"}
                </button>
                {effectiveTraceId && (
                  <button type="button" className="secondary" onClick={onCopyTraceId}>
                    {traceCopied ? "Copied" : "Copy Trace ID"}
                  </button>
                )}
                {!worldIdSessionActive && (
                  <Link to={verifyLink} className="text-link">
                    Verify World ID First
                  </Link>
                )}
              </div>
            </article>

            <article className="status-card">
              <h2>Consensus</h2>
              <p>
                <strong>Verdict:</strong>{" "}
                <span className={`status-badge ${request.consensus?.finalVerdict === "PASS" ? "ok" : "bad"}`}>
                  {request.consensus?.finalVerdict ?? "-"}
                </span>
              </p>
              <p>
                <strong>Aggregate Score:</strong> {scoreLabel(request.consensus?.aggregateScore)}
              </p>
              <p>
                <strong>Responders:</strong> {request.consensus?.responders ?? "-"}
              </p>
              <p className="mono">{request.consensus?.finalReportHash || "No report hash yet"}</p>
            </article>
          </section>
        )}
      </main>
    </div>
  );
}
