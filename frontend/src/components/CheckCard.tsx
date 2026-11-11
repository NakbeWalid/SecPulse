import { bySeverity } from "../meta";
import type { CheckResult, Finding } from "../types";
import { SeverityBadge } from "./SeverityBadge";

interface Props {
  meta: { label: string; description: string };
  check: CheckResult;
}

export function CheckCard({ meta, check }: Props) {
  const failed = check.findings.filter((f) => !f.passed).sort(bySeverity);
  const passed = check.findings.filter((f) => f.passed);
  const issues = failed.filter((f) => f.severity !== "info").length;

  let status: { text: string; cls: string };
  if (check.error) status = { text: "Erreur", cls: "status-error" };
  else if (issues > 0) status = { text: `${issues} problème${issues > 1 ? "s" : ""}`, cls: `status-${failed[0].severity}` };
  else status = { text: "OK", cls: "status-ok" };

  return (
    <section className="card check-card">
      <header className="check-head">
        <div>
          <h3>{meta.label}</h3>
          <p>{meta.description}</p>
        </div>
        <span className={`status ${status.cls}`}>{status.text}</span>
      </header>

      {check.error && <p className="check-error">Ce contrôle n'a pas pu aboutir : {check.error}</p>}

      {failed.length > 0 && (
        <ul className="findings">
          {failed.map((f) => (
            <FindingRow key={f.id} f={f} />
          ))}
        </ul>
      )}

      {passed.length > 0 && (
        <details className="passed">
          <summary>
            {passed.length} contrôle{passed.length > 1 ? "s" : ""} réussi{passed.length > 1 ? "s" : ""}
          </summary>
          <ul className="findings">
            {passed.map((f) => (
              <li key={f.id} className="finding finding-ok">
                <span className="ok-mark" aria-label="réussi">✓</span>
                <div>
                  <div className="finding-title">{f.title}</div>
                  {f.detail && <div className="finding-detail mono" title={f.detail}>{f.detail}</div>}
                </div>
              </li>
            ))}
          </ul>
        </details>
      )}
    </section>
  );
}

function FindingRow({ f }: { f: Finding }) {
  return (
    <li className="finding">
      <SeverityBadge severity={f.severity} />
      <div>
        <div className="finding-title">{f.title}</div>
        {f.detail && <div className="finding-detail">{f.detail}</div>}
        {f.recommendation && (
          <div className="finding-reco">
            <span>Correctif</span> {f.recommendation}
          </div>
        )}
      </div>
    </li>
  );
}
