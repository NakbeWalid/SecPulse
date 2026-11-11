import re

import httpx

from app.models import Finding, Severity

HSTS_MIN_MAX_AGE = 15_552_000  # 180 jours


def analyse_headers(response: httpx.Response) -> list[Finding]:
    h = response.headers
    is_https = response.url.scheme == "https"
    csp = h.get("content-security-policy", "")
    findings: list[Finding] = []

    # HSTS (ne s'applique qu'en HTTPS : les navigateurs l'ignorent en HTTP)
    if is_https:
        hsts = h.get("strict-transport-security")
        if not hsts:
            findings.append(Finding(
                id="hsts", title="Strict-Transport-Security absent", passed=False,
                severity=Severity.high,
                detail="Le navigateur peut être rétrogradé en HTTP (attaque SSL stripping).",
                recommendation="Ajouter 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
            ))
        else:
            m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
            max_age = int(m.group(1)) if m else 0
            if max_age < HSTS_MIN_MAX_AGE:
                findings.append(Finding(
                    id="hsts", title="max-age HSTS trop court", passed=False,
                    severity=Severity.low,
                    detail=f"max-age={max_age}s (minimum conseillé : 180 jours).",
                    recommendation="Passer max-age à au moins 15552000 (idéalement 31536000).",
                ))
            else:
                findings.append(Finding(id="hsts", title="HSTS configuré", passed=True,
                                        severity=Severity.high, detail=hsts))

    # Content-Security-Policy
    if not csp:
        findings.append(Finding(
            id="csp", title="Content-Security-Policy absent", passed=False,
            severity=Severity.medium,
            detail="Aucune politique ne limite les scripts exécutables : un XSS est plus facile à exploiter.",
            recommendation="Définir une CSP, par ex. \"default-src 'self'; object-src 'none'\".",
        ))
    else:
        script_src = _directive(csp, "script-src")
        if script_src is None:
            script_src = _directive(csp, "default-src") or ""
        weak = [k for k in ("'unsafe-inline'", "'unsafe-eval'") if k in script_src.lower()]
        if weak:
            findings.append(Finding(
                id="csp", title="CSP permissive", passed=False, severity=Severity.low,
                detail=f"Les scripts autorisent {', '.join(weak)}.",
                recommendation="Retirer 'unsafe-inline'/'unsafe-eval' au profit de nonces ou de hashes.",
            ))
        else:
            findings.append(Finding(id="csp", title="CSP présente", passed=True,
                                    severity=Severity.medium, detail=csp))

    # X-Content-Type-Options
    nosniff = h.get("x-content-type-options", "").strip().lower() == "nosniff"
    findings.append(Finding(
        id="x-content-type-options",
        title="X-Content-Type-Options: nosniff" + ("" if nosniff else " absent"),
        passed=nosniff, severity=Severity.low,
        recommendation=None if nosniff else "Ajouter 'X-Content-Type-Options: nosniff'.",
    ))

    # Protection anti-clickjacking (X-Frame-Options ou CSP frame-ancestors)
    xfo = h.get("x-frame-options", "").strip().upper()
    protected = xfo in ("DENY", "SAMEORIGIN") or _directive(csp, "frame-ancestors") is not None
    findings.append(Finding(
        id="clickjacking",
        title="Protection anti-clickjacking" + (" présente" if protected else " absente"),
        passed=protected, severity=Severity.medium,
        recommendation=None if protected else
        "Ajouter 'X-Frame-Options: DENY' ou la directive CSP \"frame-ancestors 'self'\".",
    ))

    # Referrer-Policy
    rp = h.get("referrer-policy")
    rp_ok = bool(rp) and rp.strip().lower() not in ("unsafe-url", "no-referrer-when-downgrade")
    findings.append(Finding(
        id="referrer-policy",
        title="Referrer-Policy" + (" correcte" if rp_ok else " absente ou faible"),
        passed=rp_ok, severity=Severity.low, detail=rp or "",
        recommendation=None if rp_ok else "Ajouter 'Referrer-Policy: strict-origin-when-cross-origin'.",
    ))

    # Permissions-Policy
    pp = "permissions-policy" in h
    findings.append(Finding(
        id="permissions-policy", title="Permissions-Policy" + (" présente" if pp else " absente"),
        passed=pp, severity=Severity.info,
        recommendation=None if pp else
        "Restreindre les API sensibles, ex. 'Permissions-Policy: camera=(), geolocation=()'.",
    ))

    # Fuite d'informations sur la stack technique
    leaks = []
    server = h.get("server", "")
    if re.search(r"\d", server):
        leaks.append(f"Server: {server}")
    if "x-powered-by" in h:
        leaks.append(f"X-Powered-By: {h['x-powered-by']}")
    findings.append(Finding(
        id="info-disclosure",
        title="Version du serveur exposée" if leaks else "Pas de version serveur exposée",
        passed=not leaks, severity=Severity.low, detail="; ".join(leaks),
        recommendation="Masquer les versions dans les en-têtes Server / X-Powered-By." if leaks else None,
    ))

    return findings


def _directive(csp: str, name: str) -> str | None:
    """Renvoie la valeur d'une directive CSP, ou None si elle est absente."""
    for part in csp.split(";"):
        tokens = part.strip().split(None, 1)
        if tokens and tokens[0].lower() == name:
            return tokens[1] if len(tokens) > 1 else ""
    return None
