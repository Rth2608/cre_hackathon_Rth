import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import AppNav from "../components/AppNav";
import { getReport, getRequest, type RequestRecord } from "../lib/api";

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

export default function ResultPage() {
  const { requestId } = useParams();
  const [request, setRequest] = useState<RequestRecord | null>(null);
  const [report, setReport] = useState<ReportPayload | null>(null);
  const [loading, setLoading] = useState(true);
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
          <div className="inline-row">
            <Link to="/" className="text-link">
              Back to Request
            </Link>
            <Link to="/verify" className="text-link">
              Verify Operators
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
                <span className={`status-badge ${request.status === "FINALIZED" ? "ok" : "warn"}`}>
                  {request.status}
                </span>
              </p>
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
              <strong>Mode:</strong>{" "}
              <span className={`status-badge ${request.onchainReceipt.simulated ? "warn" : "ok"}`}>
                {request.onchainReceipt.simulated ? "Mock" : "Live"}
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
