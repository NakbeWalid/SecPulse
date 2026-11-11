import { useCallback, useEffect, useRef, useState } from "react";
import { scan } from "./api";
import { CheckCard } from "./components/CheckCard";
import { Loading } from "./components/Loading";
import { Priorities } from "./components/Priorities";
import { ScoreCard } from "./components/ScoreCard";
import { CHECKS } from "./meta";
import type { ScanResult } from "./types";

type State =
  | { status: "idle" }
  | { status: "loading"; target: string }
  | { status: "done"; result: ScanResult; durationMs: number }
  | { status: "error"; message: string };

const EXAMPLES = ["github.com", "http://http.badssl.com", "expired.badssl.com"];

export default function App() {
  const [url, setUrl] = useState(() => new URLSearchParams(location.search).get("site") ?? "");
  const [state, setState] = useState<State>({ status: "idle" });
  const controller = useRef<AbortController | null>(null);

  const run = useCallback(async (target: string, updateHistory = true) => {
    target = target.trim();
    if (!target) return;
    controller.current?.abort();
    const ctrl = (controller.current = new AbortController());
    setUrl(target);
    setState({ status: "loading", target });
    if (updateHistory) history.pushState(null, "", `?site=${encodeURIComponent(target)}`);

    const started = performance.now();
    try {
      const result = await scan(target, ctrl.signal);
      setState({ status: "done", result, durationMs: performance.now() - started });
    } catch (e) {
      if (ctrl.signal.aborted) return;
      setState({ status: "error", message: e instanceof Error ? e.message : String(e) });
    }
  }, []);

  // Un lien ?site=... lance le scan directement (partage d'un rapport).
  useEffect(() => {
    const fromQuery = () => {
      const q = new URLSearchParams(location.search).get("site");
      if (q) run(q, false);
      else setState({ status: "idle" });
    };
    fromQuery();
    addEventListener("popstate", fromQuery);
    return () => removeEventListener("popstate", fromQuery);
  }, [run]);

  return (
    <div className="page">
      <header className="topbar">
        <a className="brand" href="/">
          <svg viewBox="0 0 32 32" aria-hidden="true">
            <path d="M3 17h6l3-8 5 15 3-7h9" />
          </svg>
          SecPulse
        </a>
        <span className="topbar-note">Audit de sécurité web passif</span>
      </header>

      <main>
        <section className={`hero ${state.status === "idle" ? "hero-large" : ""}`}>
          {state.status === "idle" && (
            <>
              <h1>Votre site est-il bien protégé ?</h1>
              <p className="lead">
                SecPulse analyse un site en quelques secondes : HTTPS, en-têtes de sécurité, cookies, CORS,
                contenu mixte et fichiers sensibles exposés. Vous obtenez une note et des correctifs concrets.
              </p>
            </>
          )}
          <form
            className="scan-form"
            onSubmit={(e) => {
              e.preventDefault();
              run(url);
            }}
          >
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="exemple.com"
              aria-label="URL du site à analyser"
              spellCheck={false}
              autoFocus
            />
            <button type="submit" disabled={state.status === "loading" || !url.trim()}>
              {state.status === "loading" ? "Analyse…" : "Analyser"}
            </button>
          </form>
          {state.status === "idle" && (
            <div className="examples">
              Essayer :
              {EXAMPLES.map((ex) => (
                <button key={ex} type="button" className="chip" onClick={() => run(ex)}>
                  {ex}
                </button>
              ))}
            </div>
          )}
        </section>

        {state.status === "loading" && <Loading target={state.target} />}

        {state.status === "error" && (
          <div className="error-box" role="alert">
            <strong>Analyse impossible.</strong> {state.message}
          </div>
        )}

        {state.status === "done" && (
          <div className="report">
            <ScoreCard result={state.result} durationMs={state.durationMs} />
            <Priorities checks={state.result.checks} />
            <h2 className="section-title">Détail par catégorie</h2>
            <div className="check-grid">
              {CHECKS.map((meta) => {
                const check = state.result.checks.find((c) => c.name === meta.name);
                return check && <CheckCard key={meta.name} meta={meta} check={check} />;
              })}
            </div>
          </div>
        )}
      </main>

      <footer className="footer">
        N'analysez que des sites dont vous êtes propriétaire ou pour lesquels vous avez une autorisation.
      </footer>
    </div>
  );
}
