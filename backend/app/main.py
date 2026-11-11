import asyncio
import ipaddress
import os
from collections.abc import Awaitable, Callable

import httpx
from fastapi import FastAPI, HTTPException, Query

from app.checks.cookies import analyse_cookies
from app.checks.cors import analyse_cors
from app.checks.exposed_files import analyse_exposed_files
from app.checks.headers import analyse_headers
from app.checks.mixed_content import analyse_mixed_content
from app.checks.tls import analyse_tls
from app.models import CheckResult, Finding, ScanResult
from app.scoring import compute_score, grade_for

TIMEOUT = 10
USER_AGENT = "SecPulse/0.1 (+security scanner)"
# Mettre SECPULSE_ALLOW_PRIVATE=1 pour scanner localhost / un réseau local en développement.
ALLOW_PRIVATE = os.getenv("SECPULSE_ALLOW_PRIVATE") == "1"

app = FastAPI(title="SecPulse", version="0.1.0")


class BlockedTarget(Exception):
    pass


def _is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


async def _assert_public_host(host: str) -> None:
    """Protection SSRF : refuse les cibles qui résolvent vers une adresse interne."""
    if ALLOW_PRIVATE:
        return
    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(host, None)
        except OSError:
            raise BlockedTarget(f"Impossible de résoudre le nom d'hôte « {host} ».")
        addresses = [ipaddress.ip_address(info[4][0].split("%")[0]) for info in infos]
    if not all(_is_public(ip) for ip in addresses):
        raise BlockedTarget(f"« {host} » pointe vers une adresse privée ou réservée.")


async def _guard_request(request: httpx.Request) -> None:
    # Appelé pour chaque requête, redirections comprises.
    await _assert_public_host(request.url.host)


def _validate_url(url: str) -> str:
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    try:
        parsed = httpx.URL(url)
    except httpx.InvalidURL:
        raise HTTPException(400, "URL invalide.")
    if parsed.scheme not in ("http", "https") or not parsed.host:
        raise HTTPException(400, "Seules les URL http:// et https:// sont acceptées.")
    return str(parsed)


async def _run(name: str, check: Callable[[], Awaitable[list[Finding]] | list[Finding]]) -> CheckResult:
    """Exécute un check en isolant ses erreurs : un check qui plante n'arrête pas le scan."""
    try:
        result = check()
        findings = await result if asyncio.iscoroutine(result) else result
        return CheckResult(name=name, findings=findings)
    except Exception as e:  # noqa: BLE001
        return CheckResult(name=name, error=f"{type(e).__name__}: {e}")


@app.get("/scan", response_model=ScanResult)
async def run_scan(url: str = Query(..., description="URL du site à analyser")) -> ScanResult:
    target = _validate_url(url)

    # verify=False : on veut analyser le site même si son certificat est invalide ;
    # la validité du certificat est vérifiée séparément par le check TLS.
    async with httpx.AsyncClient(
        timeout=TIMEOUT, verify=False, headers={"User-Agent": USER_AGENT},
        event_hooks={"request": [_guard_request]},
    ) as client:
        try:
            response = await client.get(target, follow_redirects=True)
        except BlockedTarget as e:
            raise HTTPException(400, str(e))
        except httpx.TimeoutException:
            raise HTTPException(504, "Le site n'a pas répondu à temps.")
        except httpx.HTTPError as e:
            raise HTTPException(502, f"Impossible de joindre le site : {e}")

        final_url = str(response.url)
        checks = [
            await _run("headers", lambda: analyse_headers(response)),
            await _run("cookies", lambda: analyse_cookies(response)),
            await _run("mixed_content", lambda: analyse_mixed_content(response)),
            *await asyncio.gather(
                _run("tls", lambda: analyse_tls(target, final_url)),
                _run("cors", lambda: analyse_cors(client, final_url)),
                _run("exposed_files", lambda: analyse_exposed_files(client, final_url)),
            ),
        ]

    score = compute_score(checks)
    return ScanResult(
        url=target, final_url=final_url, status_code=response.status_code,
        score=score, grade=grade_for(score), checks=checks,
    )
