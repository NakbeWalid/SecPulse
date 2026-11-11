import asyncio
import re
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from app.models import Finding, Severity

MAX_BYTES = 8192


@dataclass(frozen=True)
class Probe:
    path: str
    severity: Severity
    description: str
    # Un 200 ne suffit pas (beaucoup de sites renvoient leur page d'accueil pour toute URL) :
    # on vérifie que le contenu ressemble vraiment au fichier attendu.
    matches: Callable[[bytes], bool]


def _text(body: bytes) -> str:
    return body.decode("utf-8", errors="ignore")


def _not_html(body: bytes) -> bool:
    return b"<html" not in body.lower() and b"<!doctype" not in body.lower()


PROBES = [
    Probe("/.git/HEAD", Severity.critical, "Dépôt Git exposé (code source téléchargeable)",
          lambda b: _text(b).startswith("ref: ") or bool(re.fullmatch(rb"[0-9a-f]{40}\s*", b))),
    Probe("/.git/config", Severity.critical, "Configuration Git exposée",
          lambda b: b"[core]" in b and _not_html(b)),
    Probe("/.env", Severity.critical, "Fichier .env exposé (secrets, mots de passe)",
          lambda b: _not_html(b) and bool(re.search(rb"^[A-Z][A-Z0-9_]*=", b, re.M))),
    Probe("/wp-config.php.bak", Severity.critical, "Sauvegarde de configuration WordPress exposée",
          lambda b: b"DB_PASSWORD" in b),
    Probe("/backup.zip", Severity.high, "Archive de sauvegarde exposée",
          lambda b: b.startswith(b"PK\x03\x04")),
    Probe("/backup.sql", Severity.high, "Dump SQL exposé",
          lambda b: _not_html(b) and bool(re.search(rb"(CREATE TABLE|INSERT INTO)", b, re.I))),
    Probe("/server-status", Severity.medium, "Page server-status d'Apache exposée",
          lambda b: b"Apache Server Status" in b),
    Probe("/phpinfo.php", Severity.medium, "phpinfo() exposé (configuration du serveur)",
          lambda b: b"phpinfo()" in b and b"PHP Version" in b),
    Probe("/.DS_Store", Severity.low, "Fichier .DS_Store exposé (liste des fichiers)",
          lambda b: b[4:8] == b"Bud1"),
]


async def _fetch_head(client: httpx.AsyncClient, url: str) -> tuple[int, bytes]:
    """Récupère au plus MAX_BYTES du corps, pour ne pas télécharger une archive entière."""
    async with client.stream("GET", url, follow_redirects=False) as response:
        body = b""
        if response.status_code == 200:
            async for chunk in response.aiter_bytes():
                body += chunk
                if len(body) >= MAX_BYTES:
                    break
        return response.status_code, body[:MAX_BYTES]


async def _probe(client: httpx.AsyncClient, base: str, probe: Probe) -> Finding | None:
    try:
        status, body = await _fetch_head(client, base + probe.path)
    except httpx.HTTPError:
        return None
    if status == 200 and probe.matches(body):
        return Finding(
            id=f"exposed:{probe.path}", title=probe.description, passed=False, severity=probe.severity,
            detail=f"{base}{probe.path} est accessible publiquement.",
            recommendation="Bloquer l'accès à ce fichier sur le serveur et le retirer du répertoire web.",
        )
    return None


async def analyse_exposed_files(client: httpx.AsyncClient, url: str) -> list[Finding]:
    parsed = httpx.URL(url)
    base = f"{parsed.scheme}://{parsed.netloc.decode()}"
    results = await asyncio.gather(*(_probe(client, base, p) for p in PROBES))
    findings = [f for f in results if f is not None]
    if not findings:
        findings.append(Finding(id="exposed-files", title=f"Aucun fichier sensible exposé "
                                f"({len(PROBES)} chemins testés)", passed=True, severity=Severity.critical))
    return findings
