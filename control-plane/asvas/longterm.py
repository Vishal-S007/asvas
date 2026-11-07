"""Long-term memory in Qdrant (requirement DA-04; spec pp. 9-10, 16, 73).

After an assessment completes, an anonymised summary (tools used, rules hit with severity and verification status,
counts) is stored as a vector so later planning in the *same tenant* can see what similar past assessments found.

Guarantees, stated precisely:
* Tenant isolation: every point carries tenant_id; every search sends a mandatory tenant_id filter AND the
  results are re-checked here (a point from another tenant is dropped and logged).
* Anonymisation before storage: no hostnames, IPs, ports, URLs, assessment names, evidence or banners — only
  catalogue identifiers (tool ids, rule ids, CWE, severity) and counts. The text is also passed through redact().
* The embedding is a deterministic hashed bag-of-words (256 dims). It is lexical, not semantic; no external
  embedding model is called.
* Disabled cleanly when ASVAS_QDRANT_URL is unset; failures never affect an assessment (best effort, audited).
"""

from __future__ import annotations

import datetime as dt
import functools
import hashlib
import logging
import math
import re
import uuid
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy import Connection

from asvas.config import get_settings
from asvas.db import rows
from asvas.redaction import redact

log = logging.getLogger("asvas.longterm")
COLLECTION = "asvas_memory"
DIM = 256
_FORBIDDEN = re.compile(r"(\b\d{1,3}(\.\d{1,3}){3}\b|https?://|\b[a-z0-9-]+\.(test|local|com|net|org|io)\b|:\d{2,5}\b)",
                        re.I)


def embed(text: str, dim: int = DIM) -> list[float]:
    toks = re.findall(r"[a-z0-9_.-]+", text.lower())
    feats = toks + [f"{a} {b}" for a, b in zip(toks, toks[1:], strict=False)]
    v = [0.0] * dim
    for f in feats:
        h = int.from_bytes(hashlib.sha256(f.encode()).digest()[:8], "big")
        v[h % dim] += 1.0 if (h >> 63) & 1 else -1.0
    n = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / n for x in v]


def summarise(conn: Connection, assessment_id) -> dict[str, Any]:
    """Anonymised, catalogue-only description of a finished assessment."""
    tools = sorted({r["tool_id"] for r in rows(conn, "SELECT DISTINCT tool_id FROM jobs WHERE assessment_id = :a",
                                                a=str(assessment_id))})
    f = rows(conn, "SELECT rule_id, cwe, severity, verification_status, count(*) AS n FROM findings "
                   "WHERE assessment_id = :a GROUP BY 1,2,3,4 ORDER BY 1", a=str(assessment_id))
    services = rows(conn, "SELECT count(*) AS n FROM assets WHERE assessment_id = :a AND kind = 'service'",
                    a=str(assessment_id))[0]["n"]
    rules = [{"rule_id": x["rule_id"], "cwe": x["cwe"], "severity": x["severity"],
              "verification": x["verification_status"], "count": x["n"]} for x in f]
    text = redact(f"tools {' '.join(tools)} services {services} findings " + " ".join(
        f"{r['rule_id']} {r['cwe'] or ''} {r['severity']} {r['verification']}" for r in rules))
    if _FORBIDDEN.search(text):  # defence in depth: never store anything that looks like a target identifier
        raise ValueError("anonymisation check failed: summary contains a host/IP/URL/port-like token")
    return {"text": text, "tools": tools, "rules": rules, "services": services}


class LongTermMemory:
    def __init__(self, url: str, api_key: str | None, ca_file: str | None,
                 transport: httpx.BaseTransport | None = None):
        self.url = url.rstrip("/")
        self._c = httpx.Client(base_url=self.url, timeout=3.0, transport=transport, trust_env=False,
                               verify=ca_file or True, headers={"api-key": api_key} if api_key else {})
        self._ready = False

    name = "qdrant"

    def _ensure(self) -> None:
        if self._ready:
            return
        r = self._c.get(f"/collections/{COLLECTION}")
        if r.status_code == 404:
            self._c.put(f"/collections/{COLLECTION}",
                        json={"vectors": {"size": DIM, "distance": "Cosine"}}).raise_for_status()
            self._c.put(f"/collections/{COLLECTION}/index",
                        json={"field_name": "tenant_id", "field_schema": "keyword"}).raise_for_status()
        else:
            r.raise_for_status()
        self._ready = True

    def remember(self, tenant_id, assessment_id, summary: dict) -> None:
        self._ensure()
        payload = {"tenant_id": str(tenant_id), "assessment_ref": hashlib.sha256(str(assessment_id).encode()).hexdigest(),
                   "text": summary["text"], "tools": summary["tools"], "rules": summary["rules"],
                   "stored_at": dt.datetime.now(dt.UTC).isoformat()}
        pid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"asvas:{tenant_id}:{assessment_id}"))
        self._c.put(f"/collections/{COLLECTION}/points?wait=true",
                    json={"points": [{"id": pid, "vector": embed(summary["text"]), "payload": payload}]}
                    ).raise_for_status()

    def recall(self, tenant_id, query: str, limit: int = 3) -> list[dict]:
        self._ensure()
        r = self._c.post(f"/collections/{COLLECTION}/points/search", json={
            "vector": embed(query), "limit": limit, "with_payload": True,
            "filter": {"must": [{"key": "tenant_id", "match": {"value": str(tenant_id)}}]}})
        r.raise_for_status()
        out = []
        for p in r.json()["result"]:
            if p["payload"].get("tenant_id") != str(tenant_id):
                log.error("long-term memory returned a point of another tenant; dropped")
                continue
            out.append({"score": round(p["score"], 4), "tools": p["payload"]["tools"], "rules": p["payload"]["rules"]})
        return out

    def forget_tenant(self, tenant_id) -> None:
        self._ensure()
        self._c.post(f"/collections/{COLLECTION}/points/delete?wait=true", json={
            "filter": {"must": [{"key": "tenant_id", "match": {"value": str(tenant_id)}}]}}).raise_for_status()

    def health(self) -> dict:
        try:
            return {"enabled": True, "reachable": self._c.get("/readyz").status_code == 200, "url": self.url}
        except Exception as e:  # noqa: BLE001
            return {"enabled": True, "reachable": False, "url": self.url, "error": type(e).__name__}


class DisabledMemory:
    name = "disabled"

    def remember(self, *a, **k) -> None:
        return None

    def recall(self, *a, **k) -> list[dict]:
        return []

    def forget_tenant(self, *a, **k) -> None:
        return None

    def health(self) -> dict:
        return {"enabled": False}


@functools.lru_cache
def get_memory():
    s = get_settings()
    if not s.qdrant_url:
        return DisabledMemory()
    key = Path(s.qdrant_api_key_file).read_text().strip() if s.qdrant_api_key_file else None
    return LongTermMemory(s.qdrant_url, key, s.qdrant_ca_file or None)
