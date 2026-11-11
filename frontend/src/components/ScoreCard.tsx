import { SEVERITY_LABEL, SEVERITY_ORDER, gradeColor } from "../meta";
import type { ScanResult } from "../types";

const RADIUS = 52;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

export function ScoreCard({ result, durationMs }: { result: ScanResult; durationMs: number }) {
  const findings = result.checks.flatMap((c) => c.findings);
  const failed = findings.filter((f) => !f.passed && f.severity !== "info");
  const passed = findings.filter((f) => f.passed).length;
  const color = gradeColor(result.grade);
  const redirected = result.final_url.replace(/\/$/, "") !== result.url.replace(/\/$/, "");

  return (
    <section className="card score-card">
      <div className="gauge" style={{ color }}>
        <svg viewBox="0 0 120 120" aria-hidden="true">
          <circle className="gauge-track" cx="60" cy="60" r={RADIUS} />
          <circle
            className="gauge-value"
            cx="60"
            cy="60"
            r={RADIUS}
            strokeDasharray={CIRCUMFERENCE}
            strokeDashoffset={CIRCUMFERENCE * (1 - result.score / 100)}
          />
        </svg>
        <div className="gauge-label">
          <span className="grade">{result.grade}</span>
          <span className="score">{result.score}/100</span>
        </div>
      </div>

      <div className="score-info">
        <h2 className="target">{new URL(result.final_url).host}</h2>
        <dl className="facts">
          <div>
            <dt>URL analysée</dt>
            <dd>{result.url}</dd>
          </div>
          {redirected && (
            <div>
              <dt>Redirigé vers</dt>
              <dd>{result.final_url}</dd>
            </div>
          )}
          <div>
            <dt>Statut HTTP</dt>
            <dd>{result.status_code}</dd>
          </div>
          <div>
            <dt>Durée</dt>
            <dd>{(durationMs / 1000).toFixed(1)} s</dd>
          </div>
        </dl>
        <div className="tally">
          {SEVERITY_ORDER.filter((s) => s !== "info").map((s) => {
            const n = failed.filter((f) => f.severity === s).length;
            return (
              <span key={s} className={`tally-item sev-${s} ${n === 0 ? "is-zero" : ""}`}>
                <b>{n}</b> {SEVERITY_LABEL[s].toLowerCase()}
              </span>
            );
          })}
          <span className="tally-item sev-ok">
            <b>{passed}</b> réussis
          </span>
        </div>
      </div>
    </section>
  );
}
