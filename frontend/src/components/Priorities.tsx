import { CHECKS, bySeverity } from "../meta";
import type { CheckResult } from "../types";
import { SeverityBadge } from "./SeverityBadge";

const MAX = 3;

/** Les problèmes les plus graves, tous checks confondus : par où commencer. */
export function Priorities({ checks }: { checks: CheckResult[] }) {
  const top = checks
    .flatMap((c) => c.findings.filter((f) => !f.passed && f.severity !== "info").map((f) => ({ f, check: c.name })))
    .sort((a, b) => bySeverity(a.f, b.f))
    .slice(0, MAX);

  if (top.length === 0) {
    return (
      <section className="card priorities priorities-clean">
        <h2>Aucun problème notable</h2>
        <p>Toutes les vérifications importantes sont passées. Beau travail.</p>
      </section>
    );
  }

  return (
    <section className="card priorities">
      <h2>À corriger en priorité</h2>
      <ol>
        {top.map(({ f, check }) => (
          <li key={check + f.id}>
            <SeverityBadge severity={f.severity} />
            <div>
              <div className="finding-title">{f.title}</div>
              {f.recommendation && <div className="finding-reco">{f.recommendation}</div>}
            </div>
            <span className="priority-check">{CHECKS.find((m) => m.name === check)?.label}</span>
          </li>
        ))}
      </ol>
    </section>
  );
}
