"""CP-07: OIDC access-token validation (JWKS signature, issuer, audience, client, verified e-mail, MFA, role
agreement). Uses a locally generated RSA key standing in for the IdP's JWKS; the live Keycloak flow is covered by
dashboard/e2e/oidc-sso.e2e.cjs."""

from __future__ import annotations

import time
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from asvas import auth
from asvas.config import get_settings

ISS = "https://idp.test/realms/asvas"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER = rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture()
def oidc(monkeypatch, clean):
    s = get_settings()
    monkeypatch.setattr(s, "oidc_issuer", ISS)
    monkeypatch.setattr(s, "oidc_require_mfa", True)
    monkeypatch.setattr(auth, "_jwks_client",
                        lambda *_: SimpleNamespace(get_signing_key_from_jwt=lambda t: SimpleNamespace(key=KEY.public_key())))


def tok(key=KEY, **over):
    now = int(time.time())
    c = {"iss": ISS, "aud": ["asvas-api", "account"], "azp": "asvas-dashboard", "sub": "kc-1", "iat": now,
         "exp": now + 300, "email": "operator@acme.test", "email_verified": True, "amr": ["pwd", "otp"],
         "realm_access": {"roles": ["asvas-operator", "default-roles-asvas"]}}
    c.update(over)
    c = {k: v for k, v in c.items() if v is not None}
    return jwt.encode(c, key, algorithm="RS256", headers={"kid": "k1"})


def me(client, t):
    return client.get("/api/v1/me", headers={"Authorization": f"Bearer {t}"})


def test_valid_token_maps_to_asvas_user(client, oidc):
    r = me(client, tok())
    assert r.status_code == 200 and r.json()["email"] == "operator@acme.test" and r.json()["role"] == "operator"


@pytest.mark.parametrize("over,code,msg", [
    ({"iss": "https://evil.test/realms/asvas"}, 401, "issuer"),
    ({"aud": "account"}, 401, "Audience"),
    ({"exp": int(time.time()) - 10}, 401, "expired"),
    ({"azp": "other-client"}, 401, "different client"),
    ({"email_verified": False}, 401, "verified e-mail"),
    ({"amr": ["pwd"]}, 401, "multi-factor"),
    ({"amr": None}, 401, "multi-factor"),
    ({"email": "nobody@acme.test"}, 403, "no active ASVAS account"),
    ({"realm_access": {"roles": ["asvas-viewer"]}}, 403, "does not grant role"),
    ({"realm_access": {"roles": ["asvas-admin"]}}, 403, "does not grant role"),  # IdP role must match exactly
])
def test_rejections(client, oidc, over, code, msg):
    r = me(client, tok(**over))
    assert r.status_code == code and msg in r.json()["title"], r.text


def test_wrong_signing_key_rejected(client, oidc):
    r = me(client, tok(key=OTHER))
    assert r.status_code == 401 and "Signature" in r.json()["title"]


def test_alg_none_rejected(client, oidc):
    t = jwt.encode({"iss": ISS, "sub": "x"}, None, algorithm="none")
    assert me(client, t).status_code == 401


def test_oidc_token_refused_when_oidc_not_configured(client, clean, monkeypatch):
    monkeypatch.setattr(get_settings(), "oidc_issuer", "")
    assert me(client, tok()).status_code == 401


def test_dev_tokens_refused_in_production(client, monkeypatch):
    from asvas.auth import issue_token, lookup_user
    u = lookup_user(email="operator@acme.test")
    t = issue_token(u["id"], u["tenant_id"], u["role"])
    monkeypatch.setattr(get_settings(), "env", "production")
    r = me(client, t)
    assert r.status_code == 401 and "production" in r.json()["title"]


def test_production_requires_oidc_and_mfa():
    from asvas.config import Settings
    base = dict(env="production", jwt_secret="j" * 40, signing_key="s" * 40, allow_loopback_targets=False)
    with pytest.raises(ValueError, match="OIDC_ISSUER"):
        Settings(**base)
    with pytest.raises(ValueError, match="MFA"):
        Settings(**base, oidc_issuer=ISS, oidc_require_mfa=False)


def test_auth_config_endpoint(client, oidc):
    c = client.get("/api/v1/auth/config").json()
    assert c["oidc"]["issuer"] == ISS and c["oidc"]["pkce"] == "S256" and c["mfa_required"] is True
