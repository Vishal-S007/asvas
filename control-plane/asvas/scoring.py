"""CVSS v4.0 scoring for finding rules (spec pp. 12-13; requirement DA-09).

Each rule carries a fixed CVSS-B vector (base metrics only — no threat or environmental metrics, and no
exploitation was performed). Scores are computed with the FIRST v4.0 algorithm as implemented by the
`cvss` library (Red Hat Product Security, LGPLv3+); nothing here is estimated by a model.
Rules whose observations are not demonstrable weaknesses (banner/advertised-method "suspected" findings,
upcoming expiry) are deliberately unscored rather than given a misleading number.
"""

from __future__ import annotations

from cvss import CVSS4

RULE_VECTORS: dict[str, str] = {
    "HDR-XCTO": "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
    "HDR-CSP": "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "HDR-FRAME": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
    "HDR-HSTS": "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "COOKIE-FLAGS": "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "TLS-UNTRUSTED": "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "TLS-HOSTNAME": "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "TLS-LEGACY": "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "TLS-EXPIRED": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N",
}


def score(rule_id: str) -> tuple[str | None, float | None, str | None]:
    vector = RULE_VECTORS.get(rule_id)
    if vector is None:
        return None, None, None
    c = CVSS4(vector)
    return vector, float(c.base_score), c.severity.lower()
