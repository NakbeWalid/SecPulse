import type { ScanResult } from "./types";

export async function scan(url: string, signal?: AbortSignal): Promise<ScanResult> {
  const res = await fetch(`/api/scan?url=${encodeURIComponent(url)}`, { signal });
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    const detail = body?.detail;
    throw new Error(typeof detail === "string" ? detail : `Le serveur a répondu ${res.status}.`);
  }
  return body as ScanResult;
}
