"""Authentication (JWT) and role-based authorization (spec pp. 40-42, 86).

M1 issues HS256 tokens for seeded development users via /api/v1/auth/dev-login, which only exists when
ASVAS_ENV=development. Enterprise OIDC/MFA is planned (requirements CP-07).
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import text

from asvas.config import get_settings
from asvas.db import get_engine

ROLE_RANK = {"viewer": 0, "operator": 1, "approver": 2, "admin": 3}
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


def current_principal(creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> Principal:
    if creds is None or creds.scheme.lower() != "bearer":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token",
                            headers={"WWW-Authenticate": "Bearer"})
    s = get_settings()
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
