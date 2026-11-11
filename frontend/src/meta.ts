import type { Finding, Severity } from "./types";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critique",
  high: "Élevée",
  medium: "Moyenne",
  low: "Faible",
  info: "Info",
};

/** Ordre d'affichage et description de chaque check du backend. */
export const CHECKS: { name: string; label: string; description: string }[] = [
  { name: "tls", label: "HTTPS & certificat", description: "Chiffrement, validité et expiration du certificat, version du protocole TLS." },
  { name: "headers", label: "En-têtes de sécurité", description: "HSTS, CSP, anti-clickjacking, nosniff, Referrer-Policy, fuite de version." },
  { name: "cookies", label: "Cookies", description: "Attributs Secure, HttpOnly et SameSite de chaque cookie posé." },
  { name: "cors", label: "CORS", description: "Le serveur laisse-t-il un site tiers lire ses réponses ?" },
  { name: "mixed_content", label: "Contenu mixte", description: "Ressources chargées en HTTP depuis une page HTTPS." },
  { name: "exposed_files", label: "Fichiers exposés", description: ".git, .env, sauvegardes, phpinfo… accessibles publiquement." },
];

export const bySeverity = (a: Finding, b: Finding) =>
  SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);

export function gradeColor(grade: string): string {
  return { A: "var(--ok)", B: "#84cc16", C: "var(--medium)", D: "var(--high)" }[grade] ?? "var(--critical)";
}
