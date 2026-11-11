// Miroir des modèles Pydantic de backend/app/models.py
export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Finding {
  id: string;
  title: string;
  passed: boolean;
  severity: Severity;
  detail: string;
  recommendation: string | null;
}

export interface CheckResult {
  name: string;
  findings: Finding[];
  error: string | null;
}

export interface ScanResult {
  url: string;
  final_url: string;
  status_code: number;
  score: number;
  grade: string;
  checks: CheckResult[];
}
