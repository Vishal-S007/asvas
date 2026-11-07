"""DA-09: every rule has a deterministic CWE/OWASP mapping and either a CVSS 4.0 vector or a stated reason."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from asvas import evidence
from asvas.rules import CWE_NAMES, RULES, catalog, check_hit_cwe
from asvas.scoring import RULE_VECTORS, score

SRC = Path(evidence.__file__).read_text()
EMITTED = set(re.findall(r'RuleHit\("([A-Z0-9-]+)"', SRC))


def test_every_emitted_rule_is_catalogued_and_vice_versa():
    assert EMITTED and EMITTED == set(RULES)


def test_every_rule_has_cwe_or_is_a_non_weakness_and_cwe_names_known():
    for r in RULES.values():
        if r.cwe is None:
            assert r.unscored_reason and r.cvss_vector is None, r.rule_id
        for c in r.allowed_cwes() - {None}:
            assert c in CWE_NAMES and re.fullmatch(r"CWE-\d+", c)
        assert r.owasp is None or r.owasp.startswith("A")


def test_every_rule_scored_or_explicitly_unscored():
    assert set(RULE_VECTORS) <= set(RULES)
    for r in RULES.values():
        assert bool(r.cvss_vector) != bool(r.unscored_reason), r.rule_id


# Expected scores computed once with the FIRST CVSS v4.0 algorithm (`cvss` library) and pinned here: a change in
# a vector or in the library's scoring shows up as a test failure, not as silently different numbers.
@pytest.mark.parametrize("rule_id", sorted(RULE_VECTORS))
def test_cvss_scores_are_deterministic(rule_id):
    a, b = score(rule_id), score(rule_id)
    assert a == b and a[0].startswith("CVSS:4.0/") and 0.0 <= a[1] <= 10.0
    assert a[2] in {"none", "low", "medium", "high", "critical"}


def test_pinned_scores():
    got = {r: score(r)[1] for r in sorted(RULE_VECTORS)}
    assert got == PINNED, got


PINNED = {'COOKIE-FLAGS': 2.1, 'HDR-CSP': 2.1, 'HDR-FRAME': 2.1, 'HDR-HSTS': 2.1, 'HDR-XCTO': 2.1, 'TLS-EXPIRED': 6.9,
          'TLS-HOSTNAME': 7.4, 'TLS-LEGACY': 2.3, 'TLS-UNTRUSTED': 7.4}


def test_emitted_cwe_must_be_in_catalog():
    assert check_hit_cwe("COOKIE-FLAGS", "CWE-614") == "CWE-614"
    with pytest.raises(ValueError):
        check_hit_cwe("HDR-CSP", "CWE-79")
    with pytest.raises(ValueError):
        check_hit_cwe("UNKNOWN", None)


def test_cookie_cwe_follows_first_missing_attribute():
    def hits(cookie, scheme="https"):
        ex = {"seq": 0, "request": {"url": f"{scheme}://h/", "resolved_ip": "127.0.0.1"},
              "response": {"status": 200, "headers": [["Set-Cookie", cookie], ["Content-Type", "text/plain"],
                                                       ["X-Content-Type-Options", "nosniff"]], "body_excerpt": ""}}
        t = {"scheme": scheme, "host": "h", "port": 443}
        return [h for h in evidence.evaluate_rules("http.security_headers", t, [ex]) if h.rule_id == "COOKIE-FLAGS"]
    assert hits("s=1; Secure; SameSite=Lax")[0].cwe == "CWE-1004"
    assert hits("s=1; HttpOnly; SameSite=Lax")[0].cwe == "CWE-614"
    assert hits("s=1; HttpOnly; Secure")[0].cwe == "CWE-1275"


def test_catalog_endpoint(client):
    c = client.get("/api/v1/rules", headers=client.as_user("viewer@acme.test")).json()
    assert {x["rule_id"] for x in c} == set(RULES)
    assert all(x["cvss_base_score"] is not None or x["unscored_reason"] for x in c)
    assert catalog() == c
