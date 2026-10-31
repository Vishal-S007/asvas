package asvas.decision_test

import rego.v1

import data.asvas.decision

base := {
	"action": {
		"tool_id": "http.security_headers", "risk_tier": "low", "category": "non_destructive",
		"max_requests": 4, "requests_per_second": 2, "timeout_seconds": 20,
	},
	"target": {"scheme": "http", "host": "app.test.internal", "port": 8080, "resolved_ips": ["10.20.0.5"]},
	"scope": {
		"targets": [{"host": "app.test.internal", "ports": [8080], "schemes": ["http"]}],
		"allowed_cidrs": ["10.20.0.0/24"], "excluded_cidrs": ["10.20.0.128/25"],
		"authorization": {"valid_from": "2026-01-01T00:00:00Z", "valid_until": "2026-12-31T00:00:00Z"},
	},
	"policy": {
		"allowed_tools": ["http.security_headers", "http.allowed_methods"],
		"approval_required_risk_tiers": ["high"], "max_requests_per_second": 2, "job_timeout_seconds": 20,
	},
	"approval": {"present": false},
	"context": {"now_unix": 1790000000, "loopback_allowed": false, "protected_ports": [5432, 6379], "halted": false},
}

test_allows_in_scope_low_risk if {
	d := decision.decision with input as base
	d.allow
	count(d.deny_reasons) == 0
}

test_default_deny_empty_input if {
	not decision.allow with input as {}
}

test_denies_out_of_scope_ip if {
	d := decision.decision with input as object.union(base, {"target": object.union(base.target, {"resolved_ips": ["8.8.8.8"]})})
	not d.allow
	"8.8.8.8 is outside allowed_cidrs" in d.deny_reasons
}

test_denies_rebinding_mixed_answers if {
	# A hostname that resolves to one in-scope and one out-of-scope address must be denied.
	d := decision.decision with input as object.union(base, {"target": object.union(base.target, {"resolved_ips": ["10.20.0.5", "169.254.169.254"]})})
	not d.allow
	"169.254.169.254 is in a globally forbidden network" in d.deny_reasons
}

test_denies_excluded if {
	d := decision.decision with input as object.union(base, {"target": object.union(base.target, {"resolved_ips": ["10.20.0.200"]})})
	not d.allow
}

test_denies_unknown_host if {
	d := decision.decision with input as object.union(base, {"target": object.union(base.target, {"host": "evil.example"})})
	not d.allow
}

test_denies_wrong_port if {
	d := decision.decision with input as object.union(base, {"target": object.union(base.target, {"port": 22})})
	not d.allow
}

test_denies_destructive if {
	d := decision.decision with input as object.union(base, {"action": object.union(base.action, {"category": "destructive"})})
	not d.allow
	"destructive actions are not permitted" in d.deny_reasons
}

test_denies_unknown_tool if {
	d := decision.decision with input as object.union(base, {"action": object.union(base.action, {"tool_id": "shell.exec"})})
	not d.allow
}

test_denies_loopback_when_disabled if {
	inp := object.union(base, {
		"target": object.union(base.target, {"resolved_ips": ["127.0.0.1"]}),
		"scope": object.union(base.scope, {"allowed_cidrs": ["127.0.0.1/32"]}),
	})
	not decision.allow with input as inp
}

test_denies_protected_port_on_loopback if {
	inp := object.union(base, {
		"target": object.union(base.target, {"resolved_ips": ["127.0.0.1"], "port": 5432}),
		"scope": object.union(base.scope, {"allowed_cidrs": ["127.0.0.1/32"], "targets": [{"host": "app.test.internal", "ports": [5432], "schemes": ["http"]}]}),
		"context": object.union(base.context, {"loopback_allowed": true}),
	})
	d := decision.decision with input as inp
	not d.allow
	"port 5432 on loopback is a protected platform port" in d.deny_reasons
}

test_medium_requires_approval_when_policy_says if {
	inp := object.union(base, {
		"action": object.union(base.action, {"tool_id": "http.allowed_methods", "risk_tier": "medium", "max_requests": 1}),
		"policy": object.union(base.policy, {"approval_required_risk_tiers": ["medium", "high"]}),
	})
	d := decision.decision with input as inp
	not d.allow
	d.require_approval
}

test_medium_allowed_with_valid_approval if {
	inp := object.union(base, {
		"action": object.union(base.action, {"tool_id": "http.allowed_methods", "risk_tier": "medium", "max_requests": 1}),
		"policy": object.union(base.policy, {"approval_required_risk_tiers": ["medium", "high"]}),
		"approval": {"present": true, "verified": true, "expires_unix": 1790000100},
	})
	decision.allow with input as inp
}

test_expired_approval_denied if {
	inp := object.union(base, {
		"action": object.union(base.action, {"tool_id": "http.allowed_methods", "risk_tier": "medium", "max_requests": 1}),
		"policy": object.union(base.policy, {"approval_required_risk_tiers": ["medium", "high"]}),
		"approval": {"present": true, "verified": true, "expires_unix": 1789999999},
	})
	not decision.allow with input as inp
}

test_unverified_approval_denied if {
	inp := object.union(base, {
		"action": object.union(base.action, {"tool_id": "http.allowed_methods", "risk_tier": "medium", "max_requests": 1}),
		"policy": object.union(base.policy, {"approval_required_risk_tiers": ["medium", "high"]}),
		"approval": {"present": true, "verified": false, "expires_unix": 1790000100},
	})
	not decision.allow with input as inp
}

test_tool_not_in_policy if {
	d := decision.decision with input as object.union(base, {"policy": object.union(base.policy, {"allowed_tools": ["http.allowed_methods"]})})
	not d.allow
}

test_authorization_expired if {
	d := decision.decision with input as object.union(base, {"context": object.union(base.context, {"now_unix": 1800000000})})
	not d.allow
	"authorization window not active" in d.deny_reasons
}

test_halted if {
	not decision.allow with input as object.union(base, {"context": object.union(base.context, {"halted": true})})
}

test_budget_and_rate_caps if {
	not decision.allow with input as object.union(base, {"action": object.union(base.action, {"max_requests": 50})})
	not decision.allow with input as object.union(base, {"action": object.union(base.action, {"requests_per_second": 9})})
	not decision.allow with input as object.union(base, {"action": object.union(base.action, {"timeout_seconds": 301})})
}

test_tls_tool_requires_https if {
	inp := object.union(base, {
		"action": object.union(base.action, {"tool_id": "tls.configuration", "max_requests": 2}),
		"policy": object.union(base.policy, {"allowed_tools": ["tls.configuration"]}),
	})
	d := decision.decision with input as inp
	"tool does not support this target scheme" in d.deny_reasons
	https := object.union(inp, {
		"target": object.union(base.target, {"scheme": "https"}),
		"scope": object.union(base.scope, {"targets": [{"host": "app.test.internal", "ports": [8080], "schemes": ["https"]}]}),
	})
	decision.allow with input as https
}

test_kernel_egress_requirement if {
	inp := object.union(base, {"policy": object.union(base.policy, {"require_kernel_egress": true})})
	decision.allow with input as inp
	not decision.allow with input as object.union(inp, {"context": object.union(base.context, {"plane": "execution", "kernel_egress": false})})
	decision.allow with input as object.union(inp, {"context": object.union(base.context, {"plane": "execution", "kernel_egress": true})})
}
