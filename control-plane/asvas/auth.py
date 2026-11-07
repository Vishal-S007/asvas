"""Authentication (JWT) and role-based authorization (spec pp. 40-42, 86).

Two token types:
* OIDC access tokens (CP-07) from the configured issuer (Keycloak in development and tests): signature checked
  against the issuer's JWKS, plus issuer, audience, expiry, verified e-mail and - unless disabled in development -
  an "amr" claim containing "otp" (MFA). The person must also exist as an active ASVAS user, and the IdP must grant
  the realm role "asvas-<role>" matching the user's ASVAS role: both sources have to agree.
* HS256 tokens from /api/v1/auth/dev-login, which only exists when ASVAS_ENV=development and are refused when
  ASVAS_ENV=production.
"""

from __future__ import annotations

import datetime as dt
import functools
import ssl
import uuid
from dataclasses import dataclass

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import text

from asvas.config import get_settings
from asvas.db import get_engine

# "auditor" is read-only like "viewer" (rank 0: no mutating endpoint accepts it) and additionally may open the
# compliance controls view (UI-04).
ROLE_RANK = {"viewer": 0, "auditor": 0, "operator": 1, "approver": 2, "admin": 3}
_bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class Principal:
    user_id: uuid.UUID
    tenant_id: uuid.UUID
    email: str
    display_name: str
    role: str

    @property
    def actor(self) -> str:
        return f"user:{self.user_id}"

    def has(self, role: str) -> bool:
        return ROLE_RANK[self.role] >= ROLE_RANK[role]


def issue_token(user_id: uuid.UUID, tenant_id: uuid.UUID, role: str) -> str:
    s = get_settings()
    now = dt.datetime.now(dt.UTC)
    claims = {"sub": str(user_id), "tid": str(tenant_id), "role": role, "iat": now,
              "exp": now + dt.timedelta(minutes=s.jwt_ttl_minutes), "iss": "asvas", "aud": "asvas-api"}
    return jwt.encode(claims, s.jwt_secret.get_secret_value(), algorithm="HS256")


def lookup_user(user_id: uuid.UUID | None = None, email: str | None = None) -> dict | None:
    with get_engine().begin() as conn:
        r = conn.execute(text("SELECT * FROM asvas_lookup_user(:u, :e)"),
                         {"u": str(user_id) if user_id else None, "e": email}).first()
        return dict(r._mapping) if r else None


def _unauth(msg: str) -> HTTPException:
    return HTTPException(status.HTTP_401_UNAUTHORIZED, msg, headers={"WWW-Authenticate": "Bearer"})


@functools.lru_cache(maxsize=4)
def _jwks_client(issuer: str, ca_file: str) -> jwt.PyJWKClient:
    ctx = ssl.create_default_context(cafile=ca_file or None)
    return jwt.PyJWKClient(f"{issuer}/protocol/openid-connect/certs", cache_keys=True, lifespan=300, ssl_context=ctx,
                           timeout=5)


def oidc_principal(token: str) -> Principal:
    s = get_settings()
    try:
        key = _jwks_client(s.oidc_issuer, s.oidc_ca_file).get_signing_key_from_jwt(token)
        claims = jwt.decode(token, key.key, algorithms=["RS256", "ES256", "PS256"], audience=s.oidc_audience,
                            issuer=s.oidc_issuer, options={"require": ["sub", "exp", "iat", "iss", "aud"]})
    except jwt.PyJWTError as e:
        raise _unauth(f"invalid OIDC token: {e}") from e
    if claims.get("azp") not in (None, s.oidc_client_id):
        raise _unauth("token was issued to a different client")
    if not claims.get("email") or claims.get("email_verified") is not True:
        raise _unauth("OIDC token has no verified e-mail")
    if s.oidc_require_mfa and "otp" not in (claims.get("amr") or []):
        raise _unauth("multi-factor authentication required (amr lacks otp)")
    user = lookup_user(email=claims["email"])
    if not user or not user["active"]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "no active ASVAS account for this identity")
    granted = {r.removeprefix("asvas-") for r in (claims.get("realm_access") or {}).get("roles", [])
               if r.startswith("asvas-")}
    if user["role"] not in granted:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            f"identity provider does not grant role 'asvas-{user['role']}' for this user")
    return Principal(user["id"], user["tenant_id"], user["email"], user["display_name"], user["role"])


def current_principal(creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> Principal:
    if creds is None or creds.scheme.lower() != "bearer":
        raise _unauth("missing bearer token")
    s = get_settings()
    try:
        alg = jwt.get_unverified_header(creds.credentials).get("alg")
    except jwt.PyJWTError as e:
        raise _unauth(f"invalid token: {e}") from e
    if alg != "HS256":
        if not s.oidc_issuer:
            raise _unauth("OIDC is not configured on this server")
        return oidc_principal(creds.credentials)
    if s.env == "production":
        raise _unauth("development tokens are not accepted in production")
    try:
        claims = jwt.decode(creds.credentials, s.jwt_secret.get_secret_value(), algorithms=["HS256"],
                            audience="asvas-api", issuer="asvas",
                            options={"require": ["sub", "tid", "role", "exp"]})
    except jwt.PyJWTError as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"invalid token: {e}",
                            headers={"WWW-Authenticate": "Bearer"}) from e
    user = lookup_user(user_id=uuid.UUID(claims["sub"]))
    # Role & tenant are re-read from the database: a stale token cannot keep a revoked role.
    if not user or not user["active"] or str(user["tenant_id"]) != claims["tid"]:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user inactive or unknown")
    return Principal(user["id"], user["tenant_id"], user["email"], user["display_name"], user["role"])


def require(role: str):
    def dep(p: Principal = Depends(current_principal)) -> Principal:
        if not p.has(role):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"requires role '{role}' (you are '{p.role}')")
        return p
    return dep
