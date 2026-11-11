import { SEVERITY_LABEL } from "../meta";
import type { Severity } from "../types";

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge sev-${severity}`}>{SEVERITY_LABEL[severity]}</span>;
}
