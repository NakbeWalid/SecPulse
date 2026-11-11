import asyncio

import httpx
import pytest
from fastapi.testclient import TestClient

from app.checks.cookies import analyse_cookies
from app.checks.cors import PROBE_ORIGIN, analyse_cors
from app.checks.exposed_files import analyse_exposed_files
from app.checks.headers import analyse_headers
from app.checks.mixed_content import analyse_mixed_content
from app.main import app
from app.models import CheckResult, Finding, Severity
from app.scoring import compute_score, grade_for


def make_response(url="https://example.com/", headers=None, text="", status=200):
    return httpx.Response(status, headers=headers or [], text=text, request=httpx.Request("GET", url))


def by_id(findings):
    return {f.id: f for f in findings}


# --- headers ---------------------------------------------------------------

def test_headers_missing_everything():
    f = by_id(analyse_headers(make_response()))
    assert not f["hsts"].passed and f["hsts"].severity == Severity.high
    assert not f["csp"].passed
    assert not f["clickjacking"].passed
    assert not f["x-content-type-options"].passed


def test_headers_well_configured():
    resp = make_response(headers={
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=()",
        "Server": "nginx",
    })
    assert all(f.passed for f in analyse_headers(resp))


def test_headers_weak_values():
    resp = make_response(headers={
        "Strict-Transport-Security": "max-age=300",
        "Content-Security-Policy": "script-src 'self' 'unsafe-inline'",
        "Server": "Apache/2.4.41",
        "X-Powered-By": "PHP/7.4",
    })
    f = by_id(analyse_headers(resp))
    assert not f["hsts"].passed and f["hsts"].severity == Severity.low
    assert not f["csp"].passed and "unsafe-inline" in f["csp"].detail
    assert not f["info-disclosure"].passed


def test_hsts_not_checked_over_http():
    assert "hsts" not in by_id(analyse_headers(make_response("http://example.com/")))


# --- cookies ---------------------------------------------------------------

def test_cookies_none():
    assert analyse_cookies(make_response())[0].passed


def test_cookies_flags():
    resp = make_response(headers=[
        ("Set-Cookie", "session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"),
        ("Set-Cookie", "tracker=1; Path=/"),
        ("Set-Cookie", "x=1; SameSite=None; HttpOnly"),
    ])
    f = by_id(analyse_cookies(resp))
    assert f["cookie:session"].passed
    assert not f["cookie:tracker"].passed and f["cookie:tracker"].severity == Severity.medium
    assert "SameSite=None" in f["cookie:x"].detail


# --- mixed content ---------------------------------------------------------

def test_mixed_content():
    html = """<html><script src="http://cdn.example/a.js"></script>
              <img src="http://img.example/b.png"><img src="https://ok/c.png"></html>"""
    resp = make_response(headers={"Content-Type": "text/html"}, text=html)
    f = by_id(analyse_mixed_content(resp))
    assert not f["mixed-content-active"].passed and f["mixed-content-active"].severity == Severity.high
    assert not f["mixed-content-passive"].passed


def test_mixed_content_clean():
    resp = make_response(headers={"Content-Type": "text/html"}, text='<script src="/a.js"></script>')
    assert analyse_mixed_content(resp)[0].passed


# --- CORS / fichiers exposés (serveur simulé) ------------------------------

def run_with(handler, check, url="https://example.com/"):
    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await check(client, url)
    return asyncio.run(go())


@pytest.mark.parametrize("headers, passed, severity", [
    ({}, True, Severity.high),
    ({"Access-Control-Allow-Origin": PROBE_ORIGIN, "Access-Control-Allow-Credentials": "true"},
     False, Severity.critical),
    ({"Access-Control-Allow-Origin": PROBE_ORIGIN}, False, Severity.medium),
    ({"Access-Control-Allow-Origin": "*"}, True, Severity.info),
])
def test_cors(headers, passed, severity):
    f = run_with(lambda req: httpx.Response(200, headers=headers), analyse_cors)[0]
    assert (f.passed, f.severity) == (passed, severity)


def test_exposed_files_detects_git_and_ignores_catch_all():
    def handler(request):
        if request.url.path == "/.git/HEAD":
            return httpx.Response(200, text="ref: refs/heads/main\n")
        # Site « catch-all » qui renvoie sa page d'accueil en 200 pour tout chemin.
        return httpx.Response(200, text="<!doctype html><html>Accueil</html>")

    findings = run_with(handler, analyse_exposed_files)
    assert [f.id for f in findings] == ["exposed:/.git/HEAD"]


def test_exposed_files_none():
    findings = run_with(lambda req: httpx.Response(404), analyse_exposed_files)
    assert len(findings) == 1 and findings[0].passed


# --- scoring ---------------------------------------------------------------

def finding(sev, passed=False):
    return Finding(id="x", title="x", passed=passed, severity=sev)


def test_scoring():
    assert compute_score([CheckResult(name="a", findings=[finding(Severity.high, passed=True)])]) == 100
    assert compute_score([CheckResult(name="a", findings=[finding(Severity.medium), finding(Severity.low)])]) == 87
    assert compute_score([CheckResult(name="a", findings=[finding(Severity.critical)])]) == 40
    assert [grade_for(s) for s in (95, 85, 70, 55, 10)] == ["A", "B", "C", "D", "F"]


# --- endpoint --------------------------------------------------------------

client = TestClient(app)


@pytest.mark.parametrize("url", ["ftp://example.com", "http://127.0.0.1", "http://localhost:8000",
                                 "http://10.0.0.5", "http://169.254.169.254/latest/meta-data"])
def test_scan_rejects_bad_or_internal_targets(url):
    assert client.get("/scan", params={"url": url}).status_code == 400
