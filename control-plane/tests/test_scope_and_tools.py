"""Scope rejection, destination validation and tool-parameter validation (deterministic, no I/O)."""

import datetime as dt

import pytest
from pydantic import ValidationError

from asvas.scope import Scope, TestingPolicy, check_authorization_window, check_target
from asvas.tools import ToolParamError, validate_params
from tests.conftest import scope_body


def scope(**kw):
    return Scope.model_validate(scope_body(**kw)["scope"])


def fixed(mapping):
    return lambda h: mapping[h]


@pytest.mark.parametrize("cidr", ["0.0.0.0/0", "10.0.0.0/8", "::/0"])
def test_overly_broad_cidr_rejected(cidr):
    with pytest.raises(ValidationError, match="too broad"):
        scope(cidrs=(cidr,), host="10.1.1.1")


def test_ip_target_outside_allowed_cidrs_rejected():
    with pytest.raises(ValidationError, match="not inside allowed_cidrs"):
        scope(host="10.9.9.9", cidrs=("10.1.0.0/24",))


@pytest.mark.parametrize("host", ["http://x.test", "*.x.test", "x.test/path", "a b", "-bad.test"])
def test_malformed_hosts_rejected(host):
    with pytest.raises(ValidationError):
        scope(host=host)


def test_authorization_window_required_and_bounded():
    with pytest.raises(ValidationError):
        scope(valid_minutes=(10, 5))
    with pytest.raises(ValidationError, match="90 days"):
        scope(valid_minutes=(0, 60 * 24 * 100))
    s = scope(valid_minutes=(-120, -60))
    assert check_authorization_window(s) == ["authorization window has expired"]
    assert check_authorization_window(scope(valid_minutes=(60, 120))) == ["authorization window has not started"]


def test_high_risk_always_requires_approval():
    with pytest.raises(ValidationError, match="high-risk"):
        TestingPolicy(approval_required_risk_tiers=["medium"])


def test_policy_hard_limits():
    with pytest.raises(ValidationError):
        TestingPolicy(job_timeout_seconds=301)
    with pytest.raises(ValidationError):
        TestingPolicy(max_plan_depth=16)
    with pytest.raises(ValidationError):
        TestingPolicy(allowed_tools=["shell.exec"])


def test_check_target_in_scope_ok():
    assert check_target(scope(), "http", "127.0.0.1", 18080) == []


@pytest.mark.parametrize("scheme,host,port,needle", [
    ("http", "8.8.8.8", 80, "not a scope target"),
    ("http", "127.0.0.1", 22, "port 22 is not in scope"),
    ("https", "127.0.0.1", 18080, "scheme https"),
])
def test_check_target_rejections(scheme, host, port, needle):
    reasons = check_target(scope(), scheme, host, port)
    assert any(needle in r for r in reasons), reasons


def test_hostname_resolving_out_of_scope_rejected():
    s = scope(host="app.test.internal", cidrs=("10.20.0.0/24",))
    assert check_target(s, "http", "app.test.internal", 18080, fixed({"app.test.internal": ["10.20.0.5"]})) == []
    bad = check_target(s, "http", "app.test.internal", 18080, fixed({"app.test.internal": ["10.20.0.5", "8.8.4.4"]}))
    assert any("8.8.4.4 is outside allowed_cidrs" in r for r in bad)


def test_metadata_and_link_local_always_forbidden():
    s = scope(host="meta.test", cidrs=("169.254.0.0/16",))
    reasons = check_target(s, "http", "meta.test", 18080, fixed({"meta.test": ["169.254.169.254"]}))
    assert any("globally forbidden" in r for r in reasons)


def test_loopback_protected_ports(monkeypatch):
    s = scope(ports=(5432, 18080))
    assert any("protected" in r for r in check_target(s, "http", "127.0.0.1", 5432))
    from asvas.config import get_settings
    monkeypatch.setattr(get_settings(), "allow_loopback_targets", False)
    assert any("loopback targets are disabled" in r for r in check_target(s, "http", "127.0.0.1", 18080))


# -------------------------------------------------------------------- tool parameters

@pytest.mark.parametrize("tool,params,needle", [
    ("http.security_headers", {"path": "/;id"}, "path"),
    ("http.security_headers", {"path": "/$(reboot)"}, "path"),
    ("http.security_headers", {"path": "/../../etc/passwd"}, "path"),
    ("http.security_headers", {"path": "/?q=1"}, "path"),
    ("http.security_headers", {"path": "/", "cmd": "id"}, "Extra inputs"),
    ("http.security_headers", {"method": "DELETE"}, "method"),
    ("http.security_headers", {"max_redirects": 10}, "max_redirects"),
    ("http.security_headers", {"max_redirects": "1"}, "max_redirects"),
    ("http.allowed_methods", {"path": "relative"}, "path"),
    ("shell.exec", {"command": "id"}, "unknown tool"),
])
def test_invalid_tool_params_rejected(tool, params, needle):
    with pytest.raises(ToolParamError, match=needle):
        validate_params(tool, params)


def test_valid_params_normalised():
    assert validate_params("http.security_headers", {"path": "/a/b"}) == {"path": "/a/b", "method": "GET", "max_redirects": 3}


def test_naive_datetimes_rejected():
    body = scope_body()
    body["scope"]["authorization"]["valid_from"] = dt.datetime.now().replace(tzinfo=None).isoformat()
    with pytest.raises(ValidationError):
        Scope.model_validate(body["scope"])


def test_tls_rules_from_evidence():
    from asvas.evidence import evaluate_rules
    ok = {"probe": "default", "handshake": True, "version": "TLS 1.3", "self_signed": False,
          "days_until_expiry": 200, "expiry_warning_days": 30}
    ex = [{"seq": 0, "tls": ok}, {"seq": 1, "tls": {"probe": "legacy-only", "handshake": False}}]
    assert evaluate_rules("tls.configuration", {"scheme": "https"}, ex) == []
    bad = dict(ok, verify_error="x509: unknown authority", hostname_error="x509: not valid for 1.2.3.4", days_until_expiry=-1)
    ex = [{"seq": 0, "tls": bad}, {"seq": 1, "tls": {"probe": "legacy-only", "handshake": True, "version": "TLS 1.0"}}]
    rules = {h.rule_id for h in evaluate_rules("tls.configuration", {"scheme": "https"}, ex)}
    assert rules == {"TLS-UNTRUSTED", "TLS-HOSTNAME", "TLS-EXPIRED", "TLS-LEGACY"}


def test_tls_tool_requires_https_scheme():
    from asvas.planning.providers import PlanProposal
    from asvas.planning.validate import validate_proposal
    s = Scope.model_validate(scope_body()["scope"])
    p = PlanProposal(steps=[{"step_id": "t", "tool_id": "tls.configuration", "target": {"scheme": "http", "host": "127.0.0.1",
                             "port": 18080}, "params": {}, "rationale": "r"}], done=True, summary="x")
    pol = TestingPolicy(allowed_tools=["tls.configuration"]).model_dump()
    out = validate_proposal(p, s, pol, set(), 0, 0)
    assert not out.accepted and "does not support scheme" in " ".join(out.rejected[0][1])


def test_cvss_scores_are_computed_not_guessed():
    from asvas.scoring import RULE_VECTORS, score
    assert score("METHODS-ADVERTISED") == (None, None, None)
    for rule, vec in RULE_VECTORS.items():
        v, s, sev = score(rule)
        assert v == vec and 0.0 <= s <= 10.0 and sev in ("none", "low", "medium", "high", "critical")
    # FIRST reference: AV:N/AC:L/AT:N/PR:N/UI:N with full C/I/A impact on the vulnerable system = 9.3
    from cvss import CVSS4
    assert float(CVSS4("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N").base_score) == 9.3


def test_suspected_rules_unscored():
    from asvas.scoring import score
    assert score("BANNER-VERSION")[0] is None
