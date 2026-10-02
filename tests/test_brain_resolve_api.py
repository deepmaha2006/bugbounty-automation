"""Stage 4: POST /api/brain/resolve — authenticated, permissioned, rate-limited."""
import socket

import pytest

from conftest import auth_headers, register_user
from webapp.services import remediation_service

URL = "/api/brain/resolve"


@pytest.fixture(autouse=True)
def _clean_unresolved():
    remediation_service.clear_unresolved()
    yield
    remediation_service.clear_unresolved()


def test_known_type_resolves_with_priority_and_score(client, admin_headers):
    r = client.post(URL, headers=admin_headers, json={
        "type": "Stored XSS", "confidence": "confirmed",
        "context": {"exposure": "internet_facing", "asset": "shop-web-01"}})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["key"] == "xss.stored" and body["resolved_by"] == "alias"
    assert body["priority"] == "P1" and body["risk_score"] == 100
    assert "exposure internet_facing (+5)" in body["rationale"]
    assert body["unresolved"] is False
    assert body["remediation"]["immediate"] and body["verification"]


def test_category_only_resolves_by_category(client, admin_headers):
    body = client.post(URL, headers=admin_headers, json={"category": "SSRF"}).json()
    assert body["resolved_by"] == "category" and body["key"].startswith("ssrf.")


def test_cwe_only_resolves_by_cwe(client, admin_headers):
    body = client.post(URL, headers=admin_headers, json={"cwe": "cwe-1336"}).json()
    assert (body["resolved_by"], body["key"]) == ("cwe", "rce.ssti")


def test_free_text_signal_resolves_by_keyword(client, admin_headers):
    body = client.post(URL, headers=admin_headers,
                       json={"signal": "WAF log: repeated SQL injection probes on /login"}).json()
    assert body["key"] == "sqli.injection" and body["resolved_by"] == "keyword"


def test_unknown_input_falls_back_and_is_logged(client, admin_headers):
    r = client.post(URL, headers=admin_headers,
                    json={"type": "Flux Capacitor Anomaly", "category": "physics"})
    assert r.status_code == 200
    body = r.json()
    assert body["unresolved"] is True and body["resolved_by"] == "generic"
    assert body["priority"] in ("P1", "P2", "P3", "P4")
    [item] = remediation_service.get_unresolved()
    assert item["signature"] == "physics|flux capacitor anomaly"


def test_requires_authentication(client):
    assert client.post(URL, json={"type": "Stored XSS"}).status_code == 401


def test_viewer_role_is_forbidden(client, fake, admin_headers):
    data = register_user(client, "readonly", signup_email=True)
    fake.set_user_role(data["user"]["id"], "viewer")
    r = client.post(URL, headers=auth_headers(data["access_token"]), json={"type": "Stored XSS"})
    assert r.status_code == 403


def test_analyst_role_is_allowed(client, user_headers):
    assert client.post(URL, headers=user_headers, json={"type": "Stored XSS"}).status_code == 200


def test_rate_limit_is_enforced_per_user(client, admin_headers, user_headers):
    codes = [client.post(URL, headers=admin_headers, json={"type": "Stored XSS"}).status_code
             for _ in range(61)]
    assert codes.count(200) == 60 and codes[-1] == 429
    # another user is unaffected
    assert client.post(URL, headers=user_headers, json={"type": "Stored XSS"}).status_code == 200


@pytest.mark.parametrize("body", [
    {},
    {"type": "   "},
    {"cwe": "79"},
    {"type": "x", "confidence": "maybe"},
    {"type": "x", "context": {"exposure": "the-moon"}},
    {"type": 12345},
    {"type": "x" * 201},
])
def test_malformed_body_is_422(client, admin_headers, body):
    assert client.post(URL, headers=admin_headers, json=body).status_code == 422


def test_non_json_body_is_422(client, admin_headers):
    r = client.post(URL, headers={**admin_headers, "Content-Type": "application/json"},
                    content=b"not json")
    assert r.status_code == 422


def test_makes_no_outbound_connections(client, admin_headers, monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("brain/resolve attempted a network connection")
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    r = client.post(URL, headers=admin_headers, json={"signal": "unknown thing happened"})
    assert r.status_code == 200
