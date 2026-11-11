import httpx

from app.models import Finding, Severity

_ORDER = list(Severity)


def analyse_cookies(response: httpx.Response) -> list[Finding]:
    cookies_raw = response.headers.get_list("set-cookie")
    is_https = response.url.scheme == "https"

    if not cookies_raw:
        return [Finding(id="cookies", title="Aucun cookie défini", passed=True, severity=Severity.info)]

    results: list[Finding] = []
    for cookie in cookies_raw:
        parts = [p.strip() for p in cookie.split(";")]
        name = parts[0].split("=", 1)[0].strip()
        attrs: dict[str, str] = {}
        for p in parts[1:]:
            key, _, value = p.partition("=")
            attrs[key.strip().lower()] = value.strip().lower()

        problems: list[tuple[Severity, str]] = []
        # Sans HTTPS, Secure est inutilisable ; l'absence de HTTPS est signalée par le check TLS.
        if "secure" not in attrs and is_https:
            problems.append((Severity.medium, "flag Secure absent (le cookie peut transiter en clair)"))
        if "httponly" not in attrs:
            problems.append((Severity.low, "flag HttpOnly absent (lisible par JavaScript en cas de XSS)"))
        samesite = attrs.get("samesite")
        if samesite is None:
            problems.append((Severity.low, "attribut SameSite absent (exposition au CSRF)"))
        elif samesite == "none" and "secure" not in attrs:
            problems.append((Severity.medium, "SameSite=None sans Secure (rejeté par les navigateurs)"))

        if problems:
            severity = max((s for s, _ in problems), key=_ORDER.index)
            results.append(Finding(
                id=f"cookie:{name}", title=f"Cookie « {name} » mal protégé", passed=False,
                severity=severity, detail="; ".join(msg for _, msg in problems),
                recommendation="Définir le cookie avec 'Secure; HttpOnly; SameSite=Lax' (ou Strict).",
            ))
        else:
            results.append(Finding(id=f"cookie:{name}", title=f"Cookie « {name} » correctement protégé",
                                   passed=True, severity=Severity.medium))
    return results
