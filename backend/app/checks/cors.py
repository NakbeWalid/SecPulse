import httpx

from app.models import Finding, Severity

PROBE_ORIGIN = "https://evil.secpulse.invalid"


async def analyse_cors(client: httpx.AsyncClient, url: str) -> list[Finding]:
    """Envoie une requête avec une Origin étrangère et regarde ce que le serveur autorise."""
    response = await client.get(url, headers={"Origin": PROBE_ORIGIN}, follow_redirects=False)
    acao = response.headers.get("access-control-allow-origin", "").strip()
    credentials = response.headers.get("access-control-allow-credentials", "").strip().lower() == "true"

    if not acao:
        return [Finding(id="cors", title="CORS non ouvert aux origines étrangères",
                        passed=True, severity=Severity.high)]

    if acao == PROBE_ORIGIN:
        if credentials:
            return [Finding(
                id="cors", title="CORS reflète n'importe quelle origine avec credentials", passed=False,
                severity=Severity.critical,
                detail="Tout site peut lire les réponses authentifiées de l'utilisateur.",
                recommendation="N'autoriser qu'une liste blanche d'origines explicites.",
            )]
        return [Finding(
            id="cors", title="CORS reflète n'importe quelle origine", passed=False, severity=Severity.medium,
            detail=f"Access-Control-Allow-Origin renvoie l'Origin reçue ({PROBE_ORIGIN}).",
            recommendation="N'autoriser qu'une liste blanche d'origines explicites.",
        )]

    if acao == "null":
        return [Finding(
            id="cors", title="CORS autorise l'origine « null »", passed=False,
            severity=Severity.high if credentials else Severity.medium,
            detail="Une iframe sandboxée ou un fichier local peut se faire passer pour l'origine null.",
            recommendation="Ne jamais autoriser 'null' comme origine.",
        )]

    if acao == "*":
        # Les navigateurs refusent '*' avec credentials : sans danger pour les données authentifiées.
        return [Finding(
            id="cors", title="CORS ouvert à toutes les origines (*)", passed=True, severity=Severity.info,
            detail="Acceptable pour une ressource publique ; à éviter pour une API privée.",
        )]

    return [Finding(id="cors", title="CORS restreint à une origine précise", passed=True,
                    severity=Severity.high, detail=f"Access-Control-Allow-Origin: {acao}")]
