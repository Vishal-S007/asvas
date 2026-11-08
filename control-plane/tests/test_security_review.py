"""Security review 2026-11-08 (docs/security-review.md): regression tests for the fixed findings."""

from __future__ import annotations

import pytest

from asvas.config import Settings, get_settings


def test_sr1_security_headers_on_every_api_response(client):
    for r in (client.get("/api/v1/health"), client.get("/api/v1/me"),
              client.get("/api/v1/assessments", headers=client.as_user("viewer@acme.test"))):
        h = r.headers
        assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY"
        assert h["cache-control"] == "no-store" and h["referrer-policy"] == "no-referrer"
        assert "default-src 'none'" in h["content-security-policy"]


def test_sr2_cors_only_configured_origins(client):
    ok = client.options("/api/v1/health", headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"})
    bad = client.options("/api/v1/health", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert "access-control-allow-origin" not in bad.headers


def test_sr2_production_refuses_localhost_cors():
    base = dict(env="production", jwt_secret="j" * 40, signing_key="s" * 40, allow_loopback_targets=False,
                oidc_issuer="https://idp.example/realms/asvas")
    with pytest.raises(ValueError, match="CORS"):
        Settings(**base)
    Settings(**base, cors_origins=["https://asvas.example"])


def test_sr3_token_for_other_client_rejected(client, monkeypatch, clean):
    from tests import test_oidc
    s = get_settings()
    monkeypatch.setattr(s, "oidc_issuer", test_oidc.ISS)
    monkeypatch.setattr(s, "oidc_require_mfa", True)
    from types import SimpleNamespace

    from asvas import auth
    monkeypatch.setattr(auth, "_jwks_client", lambda *_: SimpleNamespace(
        get_signing_key_from_jwt=lambda t: SimpleNamespace(key=test_oidc.KEY.public_key())))
    for azp in (None, "some-other-client"):
        r = client.get("/api/v1/me", headers={"Authorization": f"Bearer {test_oidc.tok(azp=azp)}"})
        assert r.status_code == 401 and "different client" in r.json()["title"]


def test_sr4_api_docs_disabled_outside_development(monkeypatch):
    from fastapi.testclient import TestClient

    from asvas.api.app import create_app
    monkeypatch.setattr(get_settings(), "env", "test")
    c = TestClient(create_app())
    assert c.get("/docs").status_code == 404 and c.get("/openapi.json").status_code == 404
