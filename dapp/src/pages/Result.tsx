import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ConnectButton, useActiveAccount } from "thirdweb/react";
import AppNav from "../components/AppNav";
import {
  ApiRequestError,
  getReport,
  getRequest,
  runVerificationForWallet,
  type RequestRecord,
  type WorkflowStepLog,
  type WorldIdSession
} from "../lib/api";
import { isThirdwebClientConfigured, thirdwebClient } from "../lib/thirdweb";
import { clearWorldIdSession, loadWorldIdSession } from "../lib/worldId";
import { worldChainSepoliaChain } from "../lib/worldChain";

interface ReportPayload {
  requestId: string;
  nodeReports: Array<{
    nodeId: string;
    verdict: "PASS" | "FAIL";
    confidence: number;
    rationale: string;
    evidenceSummary: string;
    reportHash: string;
    generatedAt: string;
  }>;
  nodeFailures?: Array<{ nodeId: string; reason: string }>;
  consensus?: RequestRecord["consensus"];
  onchainReceipt?: RequestRecord["onchainReceipt"];
  generatedAt: string;
}

function scoreLabel(score?: number): string {
  if (typeof score !== "number") return "-";
  return `${(score * 100).toFixed(2)}%`;
}

function workflowStepLabel(step: WorkflowStepLog["step"]): string {
  switch (step) {
    case "validate_input":
      return "Validate Input";
    case "dispatch_nodes":
      return "Dispatch Nodes";
    case "collect_reports":
      return "Collect Reports";
    case "compute_consensus":
      return "Compute Consensus";
    case "persist_offchain_report":
      return "Persist Off-chain Report";
    case "submit_onchain":
      return "Submit On-chain";
    case "emit_run_summary":
      return "Emit Run Summary";
    default:
      return step;
  }
}

function workflowStepDuration(log: WorkflowStepLog): string {
  const startedAtMs = Date.parse(log.startedAt);
  const endedAtMs = Date.parse(log.endedAt);
  if (!Number.isFinite(startedAtMs) || !Number.isFinite(endedAtMs)) {
    return "-";
  }
  const deltaMs = Math.max(endedAtMs - startedAtMs, 0);
  if (deltaMs < 1000) {
    return `${deltaMs}ms`;
  }
  return `${(deltaMs / 1000).toFixed(2)}s`;
}

export default function ResultPage() {
  const { requestId } = useParams();
  const activeAccount = useActiveAccount();
  const walletAddress = activeAccount?.address ?? "";
  const walletConnected = walletAddress.length > 0;
  const thirdwebConfigured = isThirdwebClientConfigured();
  const [request, setRequest] = useState<RequestRecord | null>(null);
  const [report, setReport] = useState<ReportPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [runningVerification, setRunningVerification] = useState(false);
  const [worldIdSession, setWorldIdSession] = useState<WorldIdSession | null>(null);
  const [lastRunTraceId, setLastRunTraceId] = useState<string | null>(null);
  const [lastRunStepLogs, setLastRunStepLogs] = useState<WorkflowStepLog[] | null>(null);
  const [traceCopied, setTraceCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    if (!requestId) return;

    setLoading(true);
    setError(null);

    try {
      const [reqData, reportData] = await Promise.allSettled([getRequest(requestId), getReport(requestId)]);

      if (reqData.status === "fulfilled") {
        setRequest(reqData.value);
      }

      if (reportData.status === "fulfilled") {
        setReport(reportData.value as ReportPayload);
      } else {
        setReport(null);
      }
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
  const workflowStepLogs =
    request?.workflowStepLogs && request.workflowStepLogs.length > 0
      ? request.workflowStepLogs
      : lastRunStepLogs && lastRunStepLogs.length > 0
        ? lastRunStepLogs
        : null;

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
      if (updated.workflow?.stepLogs && updated.workflow.stepLogs.length > 0) {
        setLastRunStepLogs(updated.workflow.stepLogs);
      }
      // Server consumes session token per run-verification request.
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
          <h1>Request {requestId}</h1>
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
                      : request.status === "REJECTED_DUPLICATE" || request.status === "REJECTED_CONFLICT" || request.status.startsWith("FAILED_")
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

        {request?.onchainReceipt && (
          <section className="status-card">
            <h2>On-chain Receipt</h2>
            <p>
              <strong>txHash:</strong> <span className="mono">{request.onchainReceipt.txHash}</span>
            </p>
            <p>
              <strong>Block:</strong> {request.onchainReceipt.blockNumber} | <strong>Gas:</strong>{" "}
              {request.onchainReceipt.gasUsed}
            </p>
            <p>
              <strong>Execution:</strong>{" "}
              <span className={`status-badge ${request.onchainReceipt.simulated ? "warn" : "ok"}`}>
                {request.onchainReceipt.simulated ? "Simulated" : "Live"}
              </span>
            </p>
            {request.onchainReceipt.explorerUrl && (
              <p>
                <a href={request.onchainReceipt.explorerUrl} target="_blank" rel="noreferrer" className="text-link">
                  Open Tenderly tx
                </a>
              </p>
            )}
          </section>
        )}

        {request?.paymentReceipt && (
          <section className="status-card">
            <h2>x402 Payment</h2>
            <p>
              <strong>Required:</strong> {request.paymentReceipt.required ? "Yes" : "No"}
            </p>
            <p>
              <strong>Paid:</strong> {request.paymentReceipt.paid ? "Yes" : "No"}
            </p>
            <p>
              <strong>Payer:</strong> <span className="mono">{request.paymentReceipt.payerAddress}</span>
            </p>
            <p>
              <strong>Resource:</strong> {request.paymentReceipt.resource} | <strong>Price:</strong>{" "}
              {request.paymentReceipt.price}
            </p>
            <p>
              <strong>Payment Ref:</strong> <span className="mono">{request.paymentReceipt.paymentRef}</span>
            </p>
          </section>
        )}

        {request?.activeNodes && request.activeNodes.length > 0 && (
          <section className="status-card">
            <h2>Active Nodes Used</h2>
            <div className="request-table">
              <div className="request-head">
                <span>Node ID</span>
                <span>Models / Stake</span>
                <span>Participation</span>
                <span>Wallet</span>
                <span>Updated</span>
              </div>
              {request.activeNodes.map((node) => (
                <div key={node.registrationId} className="request-row">
                  <span className="mono small">{node.nodeId}</span>
                  <span>
                    {node.selectedModelFamilies.join(", ")} / stake={node.stakeAmount}
                  </span>
                  <span className={`status-badge ${node.participationEnabled ? "ok" : "warn"}`}>
                    {node.participationEnabled ? "ENABLED" : "PAUSED"}
                  </span>
                  <span className="mono small">{node.walletAddress}</span>
                  <span>{new Date(node.updatedAt).toLocaleString()}</span>
                </div>
              ))}
            </div>
          </section>
        )}

        {workflowStepLogs && (
          <section className="status-card">
            <h2>Workflow Steps</h2>
            <div className="workflow-step-list">
              {workflowStepLogs.map((stepLog, index) => (
                <article key={`${stepLog.step}:${stepLog.startedAt}:${index}`} className="workflow-step-item">
                  <div className="inline-row between">
                    <h3>{workflowStepLabel(stepLog.step)}</h3>
                    <span
                      className={`status-badge ${
                        stepLog.status === "ok" ? "ok" : stepLog.status === "failed" ? "bad" : "warn"
                      }`}
                    >
                      {stepLog.status}
                    </span>
                  </div>
                  <p className="mono small">
                    {new Date(stepLog.startedAt).toLocaleString()} - {new Date(stepLog.endedAt).toLocaleString()} (
                    {workflowStepDuration(stepLog)})
                  </p>
                  {stepLog.detail && <p>{stepLog.detail}</p>}
                </article>
              ))}
            </div>
          </section>
        )}

        {report && (
          <section className="status-card">
            <h2>Node Reports</h2>
            <div className="report-list">
              {report.nodeReports.map((node) => (
                <article key={node.nodeId} className="report-item">
                  <div className="inline-row between">
                    <h3>{node.nodeId.toUpperCase()}</h3>
                    <span className={node.verdict === "PASS" ? "pill pass" : "pill fail"}>{node.verdict}</span>
                  </div>
                  <p>
                    <strong>Confidence:</strong> {(node.confidence * 100).toFixed(0)}%
                  </p>
                  <p>{node.rationale}</p>
                  <p>{node.evidenceSummary}</p>
                  <p className="mono small">{node.reportHash}</p>
                </article>
              ))}
            </div>

            {report.nodeFailures && report.nodeFailures.length > 0 && (
              <article className="status-card muted">
                <h3>Node Failures</h3>
                {report.nodeFailures.map((failed) => (
                  <p key={failed.nodeId}>
                    {failed.nodeId}: {failed.reason}
                  </p>
                ))}
              </article>
            )}
          </section>
        )}
      </main>
    </div>
  );
}
