"""Finding-rule catalog (requirement DA-09; spec pp. 12-13): one deterministic entry per rule with its CWE
mapping, OWASP Top 10 (2021) category, CVSS 4.0 base vector, or an explicit reason it is not scored.

The catalog is authoritative: findings may only carry a CWE listed for their rule, and scores come only from the
vectors here (FIRST v4.0 algorithm via `cvss`). Nothing is estimated by a model.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from asvas.scoring import RULE_VECTORS

CWE_NAMES = {
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-295": "Improper Certificate Validation",
    "CWE-297": "Improper Validation of Certificate with Host Mismatch",
    "CWE-298": "Improper Validation of Certificate Expiration",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-614": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
    "CWE-693": "Protection Mechanism Failure",
    "CWE-749": "Exposed Dangerous Method or Function",
    "CWE-1004": "Sensitive Cookie Without 'HttpOnly' Flag",
    "CWE-1021": "Improper Restriction of Rendered UI Layers or Frames",
    "CWE-1275": "Sensitive Cookie with Improper SameSite Attribute",
}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    cwe: str | None                      # primary CWE (None only for non-weakness observations)
    owasp: str | None                    # OWASP Top 10 2021 category
    alt_cwes: tuple[str, ...] = field(default=())   # other CWEs a finding of this rule may carry
    unscored_reason: str | None = None   # required when there is no CVSS vector

    @property
    def cvss_vector(self) -> str | None:
        return RULE_VECTORS.get(self.rule_id)

    def allowed_cwes(self) -> set[str | None]:
        return {self.cwe, *self.alt_cwes}


_SUSPECTED = "suspected finding from untrusted target text; not a demonstrated weakness, so not scored"
RULES: dict[str, Rule] = {r.rule_id: r for r in [
    Rule("HDR-XCTO", "CWE-693", "A05:2021 Security Misconfiguration"),
    Rule("HDR-CSP", "CWE-693", "A05:2021 Security Misconfiguration"),
    Rule("HDR-FRAME", "CWE-1021", "A05:2021 Security Misconfiguration"),
    Rule("HDR-HSTS", "CWE-319", "A02:2021 Cryptographic Failures"),
    Rule("COOKIE-FLAGS", "CWE-1004", "A05:2021 Security Misconfiguration", ("CWE-1275", "CWE-614")),
    Rule("TLS-UNTRUSTED", "CWE-295", "A07:2021 Identification and Authentication Failures"),
    Rule("TLS-HOSTNAME", "CWE-297", "A07:2021 Identification and Authentication Failures"),
    Rule("TLS-EXPIRED", "CWE-298", "A07:2021 Identification and Authentication Failures"),
    Rule("TLS-EXPIRING", None, None, unscored_reason="operational notice (certificate still valid); not a weakness"),
    Rule("TLS-LEGACY", "CWE-327", "A02:2021 Cryptographic Failures"),
    Rule("BANNER-VERSION", "CWE-200", "A05:2021 Security Misconfiguration", unscored_reason=_SUSPECTED),
    Rule("METHODS-ADVERTISED", "CWE-749", "A05:2021 Security Misconfiguration", unscored_reason=_SUSPECTED),
]}


def catalog() -> list[dict]:
    from asvas.scoring import score
    out = []
    for r in RULES.values():
        vector, base, sev = score(r.rule_id)
        out.append({"rule_id": r.rule_id, "cwe": r.cwe, "cwe_name": CWE_NAMES.get(r.cwe or ""),
                    "alt_cwes": [{"cwe": c, "name": CWE_NAMES[c]} for c in r.alt_cwes], "owasp_top10_2021": r.owasp,
                    "cvss_vector": vector, "cvss_base_score": base, "cvss_severity": sev,
                    "unscored_reason": r.unscored_reason})
    return out


def check_hit_cwe(rule_id: str, cwe: str | None) -> str | None:
    """Return the CWE to store; raises if a rule emits a CWE its catalog entry does not allow."""
    r = RULES.get(rule_id)
    if r is None:
        raise ValueError(f"rule {rule_id} is not in the rule catalog")
    if cwe not in r.allowed_cwes():
        raise ValueError(f"rule {rule_id} emitted {cwe}, catalog allows {sorted(map(str, r.allowed_cwes()))}")
    return cwe
