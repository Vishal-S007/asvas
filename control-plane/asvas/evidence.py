"""Evidence persistence, asset correlation and deterministic finding rules (spec pp. 11-15, 84-85).

Findings are derived only from stored evidence by fixed rules. A model never creates or grades a finding.
`confirmed` = the misconfiguration is directly observed in the response; `suspected` = indicated only
(e.g., by a banner or an advertised method) and not verified.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Connection, text

from asvas import audit
from asvas.canonical import canonical_json, sha256_hex

MAX_EVIDENCE_BYTES = 256 * 1024
VERSION_RE = re.compile(r"[A-Za-z][\w.\-]*/\d+(?:\.\d+)+")


@dataclass
class RuleHit:
    rule_id: str
    title: str
    observed: str
    severity: str
    rationale: str
    confidence: str
    verification: str
    cwe: str | None
    remediation: str
    key: str = ""  # distinguishes multiple hits of one rule (e.g. cookie name)
    evidence_seq: int = 0


def store_exchanges(conn: Connection, tenant_id, assessment_id, job_id, attempt: int,
                    exchanges: list[dict[str, Any]]) -> dict[int, uuid.UUID]:
    """Persist each request/response exchange as an append-only, SHA-256-addressed evidence record."""
    ids: dict[int, uuid.UUID] = {}
    for ex in exchanges:
        body = canonical_json(_strip_floats(ex)).encode()
        if len(body) > MAX_EVIDENCE_BYTES:
            body = body[:MAX_EVIDENCE_BYTES]
        digest = sha256_hex(body)
        r = conn.execute(text(
            "INSERT INTO evidence (tenant_id, assessment_id, job_id, attempt, seq, kind, content_type, content, sha256, size_bytes) "
            "VALUES (:t,:a,:j,:att,:seq,'http_exchange','application/json',:c,:h,:n) "
            "ON CONFLICT (job_id, attempt, seq) DO NOTHING RETURNING id"),
            {"t": str(tenant_id), "a": str(assessment_id), "j": str(job_id), "att": attempt, "seq": int(ex["seq"]),
             "c": body, "h": digest, "n": len(body)}).scalar()
        if r is None:
            r = conn.execute(text("SELECT id FROM evidence WHERE job_id=:j AND attempt=:a AND seq=:s"),
                             {"j": str(job_id), "a": attempt, "s": int(ex["seq"])}).scalar()
        ids[int(ex["seq"])] = r
    return ids


def _strip_floats(o: Any) -> Any:
    if isinstance(o, float):
        return int(o)
    if isinstance(o, dict):
        return {k: _strip_floats(v) for k, v in o.items()}
    if isinstance(o, list):
        return [_strip_floats(v) for v in o]
    return o


def load_evidence(conn: Connection, evidence_id) -> dict[str, Any] | None:
    r = conn.execute(text("SELECT * FROM evidence WHERE id = :id"), {"id": str(evidence_id)}).first()
    if not r:
        return None
    m = dict(r._mapping)
    content = bytes(m.pop("content"))
    m["integrity_ok"] = sha256_hex(content) == m["sha256"]
    m["content"] = json.loads(content.decode())
    return m


def upsert_asset(conn: Connection, tenant_id, assessment_id, kind: str, identifier: str, attrs: dict) -> uuid.UUID:
    return conn.execute(text(
        "INSERT INTO assets (tenant_id, assessment_id, kind, identifier, attributes) VALUES (:t,:a,:k,:i,CAST(:at AS jsonb)) "
        "ON CONFLICT (assessment_id, kind, identifier) DO UPDATE SET last_seen = now(), "
        "attributes = assets.attributes || EXCLUDED.attributes RETURNING id"),
        {"t": str(tenant_id), "a": str(assessment_id), "k": kind, "i": identifier, "at": json.dumps(attrs)}).scalar()


def correlate_assets(conn: Connection, tenant_id, assessment_id, target: dict, exchanges: list[dict]) -> uuid.UUID:
    ips = sorted({e["request"]["resolved_ip"] for e in exchanges if e.get("request", {}).get("resolved_ip")})
    host_id = upsert_asset(conn, tenant_id, assessment_id, "host", target["host"], {"resolved_ips": ips})
    svc = f"{target['scheme']}://{target['host']}:{target['port']}"
    attrs: dict[str, Any] = {"scheme": target["scheme"], "port": target["port"]}
    finals = [e for e in exchanges if e.get("response")]
    if finals:
        hdrs = _headers(finals[-1])
        if "server" in hdrs:
            attrs["server_banner_untrusted"] = hdrs["server"][:200]
    svc_id = upsert_asset(conn, tenant_id, assessment_id, "service", svc, attrs)
    conn.execute(text(
        "INSERT INTO asset_relations (tenant_id, assessment_id, src_asset, dst_asset, relation) "
        "VALUES (:t,:a,:s,:d,'exposes') ON CONFLICT DO NOTHING"),
        {"t": str(tenant_id), "a": str(assessment_id), "s": str(host_id), "d": str(svc_id)})
    return svc_id


def _headers(ex: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in (ex.get("response") or {}).get("headers", []):
        lk = k.lower()
        out[lk] = f"{out[lk]}, {v}" if lk in out and lk != "set-cookie" else v
    return out


def _set_cookies(ex: dict) -> list[str]:
    return [v for k, v in (ex.get("response") or {}).get("headers", []) if k.lower() == "set-cookie"]


def evaluate_tls(exchanges: list[dict]) -> list[RuleHit]:
    hits: list[RuleHit] = []
    by_probe = {e["tls"]["probe"]: e for e in exchanges if e.get("tls")}
    d = by_probe.get("default")
    if d and d["tls"]["handshake"]:
        t, seq = d["tls"], int(d["seq"])
        if t.get("verify_error"):
            hits.append(RuleHit("TLS-UNTRUSTED", "Certificate does not validate against trusted roots",
                                f"Chain validation failed: {t['verify_error'][:200]} (self-signed: {t['self_signed']}; "
                                f"issuer {t.get('leaf_issuer', '')[:120]!r}).", "medium",
                                "Clients cannot authenticate the server; users may be trained to accept warnings. "
                                "Validated against the executor host's root store.", "high", "confirmed", "CWE-295",
                                "Serve a certificate issued by a trusted CA, including the full intermediate chain.",
                                evidence_seq=seq))
        if t.get("hostname_error"):
            hits.append(RuleHit("TLS-HOSTNAME", "Certificate does not match the target name",
                                f"Hostname check failed: {t['hostname_error'][:200]}; SANs {t.get('leaf_sans')}.",
                                "medium", "Name mismatch defeats server authentication.", "high", "confirmed", "CWE-297",
                                "Issue a certificate whose SAN covers every name/IP clients use.", evidence_seq=seq))
        days = t.get("days_until_expiry", 0)
        if days < 0:
            hits.append(RuleHit("TLS-EXPIRED", "Certificate has expired", f"notAfter {t.get('leaf_not_after')}.",
                                "high", "Expired certificates break authentication for all clients.", "high", "confirmed",
                                "CWE-298", "Renew the certificate and automate renewal.", evidence_seq=seq))
        elif days < t.get("expiry_warning_days", 30):
            hits.append(RuleHit("TLS-EXPIRING", f"Certificate expires in {days} days",
                                f"notAfter {t.get('leaf_not_after')} is within the {t.get('expiry_warning_days')}-day "
                                "warning window.", "low", "Operational risk of an outage at expiry; no current weakness.",
                                "high", "confirmed", None, "Renew the certificate; automate renewal.", evidence_seq=seq))
    legacy = by_probe.get("legacy-only")
    if legacy and legacy["tls"]["handshake"]:
        hits.append(RuleHit("TLS-LEGACY", f"Legacy protocol accepted: {legacy['tls']['version']}",
                            f"Server completed a handshake restricted to TLS 1.0/1.1 (negotiated "
                            f"{legacy['tls']['version']}, {legacy['tls'].get('cipher_suite')}).", "medium",
                            "TLS 1.0/1.1 are deprecated (RFC 8996); downgrade exposure depends on client support.",
                            "high", "confirmed", "CWE-327", "Disable TLS 1.0 and 1.1; require TLS 1.2 or later.",
                            evidence_seq=int(legacy["seq"])))
    return hits


def evaluate_rules(tool_id: str, target: dict, exchanges: list[dict]) -> list[RuleHit]:
    if tool_id == "tls.configuration":
        return evaluate_tls(exchanges)
    finals = [e for e in exchanges if e.get("response")]
    if not finals:
        return []
    ex = finals[-1]
    seq = int(ex["seq"])
    h = _headers(ex)
    hits: list[RuleHit] = []
    is_html = "text/html" in h.get("content-type", "")
    if tool_id == "http.security_headers":
        if h.get("x-content-type-options", "").strip().lower() != "nosniff":
            hits.append(RuleHit("HDR-XCTO", "X-Content-Type-Options not set to nosniff",
                                f"Response (HTTP {ex['response']['status']}) has X-Content-Type-Options="
                                f"{h.get('x-content-type-options', '<absent>')!r}",
                                "low", "Defense-in-depth header; enables MIME-sniffing attacks only together with "
                                "other weaknesses. Fixed rule severity.", "high", "confirmed", "CWE-693",
                                "Send `X-Content-Type-Options: nosniff` on all responses.", evidence_seq=seq))
        if is_html and "content-security-policy" not in h:
            hits.append(RuleHit("HDR-CSP", "Content-Security-Policy header missing on HTML response",
                                "HTML response without a Content-Security-Policy header.", "low",
                                "No CSP removes a mitigation layer against XSS; no XSS was tested or verified.",
                                "high", "confirmed", "CWE-693",
                                "Define a restrictive Content-Security-Policy (start with default-src 'self').",
                                evidence_seq=seq))
        csp = h.get("content-security-policy", "")
        if is_html and "x-frame-options" not in h and "frame-ancestors" not in csp:
            hits.append(RuleHit("HDR-FRAME", "Clickjacking protection missing",
                                "HTML response has neither X-Frame-Options nor CSP frame-ancestors.", "low",
                                "Page may be framed by other origins; impact depends on page actions.", "high",
                                "confirmed", "CWE-1021",
                                "Send `Content-Security-Policy: frame-ancestors 'none'` (or X-Frame-Options: DENY).",
                                evidence_seq=seq))
        if target["scheme"] == "https" and "strict-transport-security" not in h:
            hits.append(RuleHit("HDR-HSTS", "HSTS not enabled", "HTTPS response without Strict-Transport-Security.",
                                "medium", "Allows protocol downgrade on first visit / stripped links.", "high",
                                "confirmed", "CWE-319",
                                "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains`.", evidence_seq=seq))
        for c in _set_cookies(ex):
            name = c.split("=", 1)[0].strip()[:64]
            attrs = [a.strip().lower() for a in c.split(";")[1:]]
            missing = []
            if "httponly" not in attrs:
                missing.append("HttpOnly")
            if target["scheme"] == "https" and "secure" not in attrs:
                missing.append("Secure")
            if not any(a.startswith("samesite") for a in attrs):
                missing.append("SameSite")
            if missing:
                hits.append(RuleHit("COOKIE-FLAGS", f"Cookie '{name}' missing {', '.join(missing)}",
                                    f"Set-Cookie for '{name}' lacks: {', '.join(missing)} (value not stored in finding).",
                                    "low", "Cookie attribute weaknesses increase exposure if another flaw exists; "
                                    "cookie sensitivity not determined.", "high", "confirmed",
                                    "CWE-1004" if "HttpOnly" in missing else "CWE-1275",
                                    "Set HttpOnly, Secure (on HTTPS) and SameSite=Lax/Strict on session cookies.",
                                    key=name, evidence_seq=seq))
        for hdr in ("server", "x-powered-by"):
            v = h.get(hdr, "")
            m = VERSION_RE.search(v)
            if m:
                hits.append(RuleHit("BANNER-VERSION", f"Software version disclosed in {hdr} header",
                                    f"{hdr} header contains version token {m.group(0)!r} (untrusted target text).",
                                    "info", "Banner text is attacker/target controlled and unverified; it is NOT "
                                    "evidence that the named version or any vulnerability is present.", "medium",
                                    "suspected", "CWE-200", f"Remove or genericise the {hdr} header.",
                                    key=hdr, evidence_seq=seq))
    elif tool_id == "http.allowed_methods":
        allow = h.get("allow", "")
        risky = sorted({m.strip().upper() for m in allow.split(",")} & {"TRACE", "PUT", "DELETE", "CONNECT", "PATCH"})
        if risky:
            hits.append(RuleHit("METHODS-ADVERTISED", f"Potentially dangerous HTTP methods advertised: {', '.join(risky)}",
                                f"OPTIONS response Allow header lists {', '.join(risky)}. Methods were NOT invoked.",
                                "low", "Advertisement only; whether these methods are actually enabled and harmful "
                                "is unverified (verification would require invoking them).", "medium", "suspected",
                                "CWE-749", "Disable unused methods at the server/proxy and keep Allow accurate.",
                                evidence_seq=seq))
    return hits


def finding_fingerprint(rule_id: str, service: str, key: str) -> str:
    return sha256_hex(canonical_json({"rule": rule_id, "service": service, "key": key}))


def record_findings(conn: Connection, tenant_id, assessment_id, job: dict, asset_id, evidence_ids: dict[int, Any],
                    hits: list[RuleHit]) -> list[uuid.UUID]:
    service = f"{job['target']['scheme']}://{job['target']['host']}:{job['target']['port']}"
    created = []
    for hit in hits:
        fp = finding_fingerprint(hit.rule_id, service, hit.key)
        ev = [str(evidence_ids[hit.evidence_seq])]
        fid = conn.execute(text(
            "INSERT INTO findings (tenant_id, assessment_id, asset_id, job_id, check_id, rule_id, title, observed_behavior, "
            "severity, severity_rationale, confidence, verification_status, cwe, remediation, evidence_ids, fingerprint) "
            "VALUES (:t,:a,:asset,:j,:check,:rule,:title,:obs,:sev,:rat,:conf,:ver,:cwe,:rem,CAST(:ev AS uuid[]),:fp) "
            "ON CONFLICT (assessment_id, fingerprint) DO UPDATE SET updated_at = now(), "
            "evidence_ids = (SELECT array_agg(DISTINCT x) FROM unnest(findings.evidence_ids || EXCLUDED.evidence_ids) x) "
            "RETURNING id, (xmax = 0) AS inserted"),
            {"t": str(tenant_id), "a": str(assessment_id), "asset": str(asset_id), "j": str(job["id"]),
             "check": job["tool_id"], "rule": hit.rule_id, "title": hit.title, "obs": hit.observed,
             "sev": hit.severity, "rat": hit.rationale, "conf": hit.confidence, "ver": hit.verification,
             "cwe": hit.cwe, "rem": hit.remediation, "ev": "{" + ",".join(ev) + "}", "fp": fp}).first()
        if fid.inserted:
            audit.record(conn, tenant_id, "system:evidence", "finding.created",
                         {"finding_id": str(fid.id), "rule_id": hit.rule_id, "severity": hit.severity,
                          "verification": hit.verification, "evidence_ids": ev}, assessment_id)
        created.append(fid.id)
    return created
