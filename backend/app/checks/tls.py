import asyncio
import socket
import ssl
import time

import httpx

from app.models import Finding, Severity

TIMEOUT = 10
WEAK_PROTOCOLS = {"SSLv3", "TLSv1", "TLSv1.1"}


def _inspect(host: str, port: int) -> tuple[dict, str]:
    """Handshake TLS avec vérification du certificat. Lève ssl.SSLError si invalide."""
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert(), tls.version() or "inconnu"


async def analyse_tls(original_url: str, final_url: str) -> list[Finding]:
    original = httpx.URL(original_url)
    final = httpx.URL(final_url)

    if final.scheme != "https":
        return [Finding(
            id="https", title="Le site n'utilise pas HTTPS", passed=False, severity=Severity.critical,
            detail="Tout le trafic (mots de passe, cookies) circule en clair.",
            recommendation="Installer un certificat (ex. Let's Encrypt) et rediriger HTTP vers HTTPS.",
        )]

    findings: list[Finding] = []
    if original.scheme == "http":
        findings.append(Finding(id="https-redirect", title="HTTP redirige vers HTTPS",
                                passed=True, severity=Severity.high))

    host, port = final.host, final.port or 443
    try:
        cert, protocol = await asyncio.to_thread(_inspect, host, port)
    except ssl.SSLCertVerificationError as e:
        return findings + [Finding(
            id="certificate", title="Certificat TLS invalide", passed=False, severity=Severity.critical,
            detail=e.verify_message or str(e),
            recommendation="Utiliser un certificat valide, non expiré, émis pour ce domaine.",
        )]
    except ssl.SSLError as e:
        # Le contexte par défaut refuse TLS < 1.2 : un échec ici signale souvent un protocole obsolète.
        return findings + [Finding(
            id="tls-handshake", title="Échec de la négociation TLS", passed=False, severity=Severity.high,
            detail=str(e),
            recommendation="Activer TLS 1.2 et TLS 1.3 avec des suites de chiffrement modernes.",
        )]

    findings.append(Finding(id="certificate", title="Certificat TLS valide", passed=True,
                            severity=Severity.critical))

    days_left = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) // 86400)
    if days_left < 14:
        sev, ok = Severity.high, False
    elif days_left < 30:
        sev, ok = Severity.medium, False
    else:
        sev, ok = Severity.medium, True
    findings.append(Finding(
        id="certificate-expiry",
        title=f"Certificat valide encore {days_left} jour(s)" if ok else f"Certificat expire dans {days_left} jour(s)",
        passed=ok, severity=sev, detail=f"Expiration : {cert['notAfter']}",
        recommendation=None if ok else "Renouveler le certificat (et automatiser le renouvellement).",
    ))

    weak = protocol in WEAK_PROTOCOLS
    findings.append(Finding(
        id="tls-protocol", title=f"Protocole négocié : {protocol}", passed=not weak,
        severity=Severity.high,
        recommendation="Désactiver SSLv3, TLS 1.0 et 1.1." if weak else None,
    ))
    return findings
