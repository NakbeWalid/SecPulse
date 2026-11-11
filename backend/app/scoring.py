from app.models import CheckResult, Severity

PENALTIES = {
    Severity.info: 0,
    Severity.low: 3,
    Severity.medium: 10,
    Severity.high: 20,
    Severity.critical: 40,
}

# Une faille critique plafonne le score : le site ne peut pas obtenir mieux que F.
CRITICAL_CAP = 40


def compute_score(checks: list[CheckResult]) -> int:
    failed = [f for c in checks for f in c.findings if not f.passed]
    score = 100 - sum(PENALTIES[f.severity] for f in failed)
    if any(f.severity == Severity.critical for f in failed):
        score = min(score, CRITICAL_CAP)
    return max(0, score)


def grade_for(score: int) -> str:
    for threshold, grade in ((90, "A"), (80, "B"), (65, "C"), (50, "D")):
        if score >= threshold:
            return grade
    return "F"
