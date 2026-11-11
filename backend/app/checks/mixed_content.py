from html.parser import HTMLParser

import httpx

from app.models import Finding, Severity

# Contenu actif : bloqué par les navigateurs et dangereux (peut contrôler la page).
_ACTIVE = {"script": "src", "iframe": "src", "object": "data", "embed": "src", "form": "action"}
# Contenu passif : affiché avec un avertissement, mais peut être altéré en transit.
_PASSIVE = {"img": "src", "audio": "src", "video": "src", "source": "src"}

MAX_REPORTED = 5


class _Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.active: list[str] = []
        self.passive: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: (v or "") for k, v in attrs}
        if tag == "link":
            # Une feuille de style ou un script préchargé est actif ; une icône est passive.
            rel = a.get("rel", "").lower()
            target = self.active if ("stylesheet" in rel or "preload" in rel) else self.passive
            self._add(target, a.get("href", ""))
        elif tag in _ACTIVE:
            self._add(self.active, a.get(_ACTIVE[tag], ""))
        elif tag in _PASSIVE:
            self._add(self.passive, a.get(_PASSIVE[tag], ""))

    @staticmethod
    def _add(target: list[str], url: str) -> None:
        if url.strip().lower().startswith("http://"):
            target.append(url.strip())


def analyse_mixed_content(response: httpx.Response) -> list[Finding]:
    if response.url.scheme != "https":
        return [Finding(id="mixed-content", title="Contenu mixte non applicable (page en HTTP)",
                        passed=True, severity=Severity.info)]
    if "html" not in response.headers.get("content-type", "").lower():
        return [Finding(id="mixed-content", title="Contenu mixte non applicable (réponse non HTML)",
                        passed=True, severity=Severity.info)]

    collector = _Collector()
    collector.feed(response.text)
    findings: list[Finding] = []

    if collector.active:
        findings.append(Finding(
            id="mixed-content-active", title="Contenu mixte actif", passed=False, severity=Severity.high,
            detail=f"{len(collector.active)} ressource(s) active(s) en HTTP : "
                   + ", ".join(collector.active[:MAX_REPORTED]),
            recommendation="Charger scripts, styles et iframes en HTTPS.",
        ))
    if collector.passive:
        findings.append(Finding(
            id="mixed-content-passive", title="Contenu mixte passif", passed=False, severity=Severity.low,
            detail=f"{len(collector.passive)} ressource(s) passive(s) en HTTP : "
                   + ", ".join(collector.passive[:MAX_REPORTED]),
            recommendation="Charger images et médias en HTTPS.",
        ))
    if not findings:
        findings.append(Finding(id="mixed-content", title="Aucun contenu mixte détecté",
                                passed=True, severity=Severity.high))
    return findings
