import { useEffect, useState } from "react";
import { CHECKS } from "../meta";

export function Loading({ target }: { target: string }) {
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    const started = Date.now();
    const id = setInterval(() => setElapsed((Date.now() - started) / 1000), 100);
    return () => clearInterval(id);
  }, []);

  return (
    <section className="card loading" aria-live="polite">
      <div className="loading-head">
        <span className="pulse-dot" />
        Analyse de <b>{target}</b>
        <span className="elapsed">{elapsed.toFixed(1)} s</span>
      </div>
      <ul className="loading-list">
        {CHECKS.map((c, i) => (
          <li key={c.name} style={{ animationDelay: `${i * 0.15}s` }}>
            {c.label}
          </li>
        ))}
      </ul>
    </section>
  );
}
