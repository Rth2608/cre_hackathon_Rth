import { useEffect, useState } from "react";
import AppNav from "../components/AppNav";
import { getPorStatus, type PorProofSnapshot, type PorStatus } from "../lib/api";

function formatUsdcFromMicro(raw: string): string {
  const value = BigInt(raw);
  const whole = value / 1_000_000n;
  const fraction = value % 1_000_000n;
  const fractionText = fraction.toString().padStart(6, "0").replace(/0+$/, "");
  if (!fractionText) {
    return `${whole.toString()} USDC`;
  }
  return `${whole.toString()}.${fractionText} USDC`;
}

function coverageLabel(snapshot: PorProofSnapshot): string {
  return `${(snapshot.coverageBps / 100).toFixed(2)}%`;
}

export default function PorDashboardPage() {
  const [payload, setPayload] = useState<PorStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const next = await getPorStatus();
      setPayload(next);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  return (
    <div className="page-shell">
      <main className="panel">
        <AppNav current="por" />
        <header className="hero compact">
          <p className="eyebrow">Proof Of Reserve</p>
          <h1>PoR Dashboard</h1>
          <p>Track asset-liability coverage records produced by the verification workflow.</p>
          <div className="inline-row">
            <button type="button" className="secondary" onClick={load}>
              Refresh
            </button>
          </div>
        </header>

        {loading ? (
          <section className="status-card">
            <p>Loading PoR data...</p>
          </section>
        ) : null}

        {error && <p className="error-text">{error}</p>}

        {payload && (
          <>
            <section className="kpi-grid">
              <article className="status-card">
                <h2>Coverage</h2>
                <p className="kpi-value">{coverageLabel(payload.latest)}</p>
                <p>
                  <span className={`status-badge ${payload.latest.healthy ? "ok" : "bad"}`}>
                    {payload.latest.healthy ? "HEALTHY" : "UNDERCOLLATERALIZED"}
                  </span>
                </p>
              </article>
              <article className="status-card">
                <h2>Assets</h2>
                <p className="kpi-value">{formatUsdcFromMicro(payload.latest.assetsMicroUsdc)}</p>
                <p>Market #{payload.latest.marketId}</p>
              </article>
              <article className="status-card">
                <h2>Liabilities</h2>
                <p className="kpi-value">{formatUsdcFromMicro(payload.latest.liabilitiesMicroUsdc)}</p>
                <p>Epoch {payload.latest.epoch}</p>
              </article>
            </section>

            <section className="status-card">
              <h2>Latest Proof</h2>
              <p>
                <strong>Source:</strong> {payload.source} ({payload.mode})
              </p>
              <p>
                <strong>Proof Hash:</strong> <span className="mono">{payload.latest.proofHash}</span>
              </p>
              {payload.latest.proofUri && (
                <p>
                  <strong>Proof URI:</strong> <span className="mono">{payload.latest.proofUri}</span>
                </p>
              )}
              {payload.latest.txHash && (
                <p>
                  <strong>Tx Hash:</strong> <span className="mono">{payload.latest.txHash}</span>
                </p>
              )}
              <p>
                <strong>Updated:</strong> {new Date(payload.latest.updatedAt).toLocaleString()}
              </p>
            </section>

            <section className="status-card">
              <h2>Proof History</h2>
              <div className="request-table">
                <div className="request-head por-head">
                  <span>Epoch</span>
                  <span>Coverage</span>
                  <span>Assets</span>
                  <span>Liabilities</span>
                  <span>Proof Hash</span>
                </div>
                {payload.history.map((proof) => (
                  <div key={`${proof.marketId}-${proof.epoch}-${proof.proofHash}`} className="request-row por-row">
                    <span>#{proof.epoch}</span>
                    <span className={`status-badge ${proof.healthy ? "ok" : "bad"}`}>{coverageLabel(proof)}</span>
                    <span>{formatUsdcFromMicro(proof.assetsMicroUsdc)}</span>
                    <span>{formatUsdcFromMicro(proof.liabilitiesMicroUsdc)}</span>
                    <span className="mono small">{proof.proofHash}</span>
                  </div>
                ))}
              </div>
            </section>
          </>
        )}
      </main>
    </div>
  );
}
