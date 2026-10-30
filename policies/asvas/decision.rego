# ASVAS execution guardrails (spec pp. 3-4, 27, 75). Default deny.
#
# Evaluated twice, independently:
#   1. by the OPA server queried from the control plane before a job is created/dispatched;
#   2. by the Go execution plane (embedded OPA, same files) immediately before execution.
# The scope comes from the signed assessment document in `input.scope`; nothing in this file names targets.
package asvas.decision

import rego.v1

catalog := {
	"http.security_headers": {"risk_tier": "low", "category": "non_destructive", "max_requests": 4},
	"http.allowed_methods": {"risk_tier": "medium", "category": "non_destructive", "max_requests": 1},
}

forbidden_cidrs := [
	"0.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
	"::/128", "fe80::/10", "ff00::/8",
]

loopback_cidrs := ["127.0.0.0/8", "::1/128"]

tool := catalog[input.action.tool_id]

# ---- deny reasons (each is independent; any one blocks execution) ----

deny contains "unknown tool" if not catalog[input.action.tool_id]

deny contains "risk tier mismatch with catalog" if tool.risk_tier != input.action.risk_tier

deny contains "destructive actions are not permitted" if input.action.category == "destructive"

deny contains "production changes require human authorization" if {
	input.action.category == "production_change"
	not approval_valid
}

deny contains "category mismatch with catalog" if tool.category != input.action.category

deny contains "tool not allowed by testing policy" if {
	not input.action.tool_id in input.policy.allowed_tools
}

deny contains "assessment emergency-stopped or cancelled" if input.context.halted == true

deny contains "authorization window not active" if {
	not authorization_active
}

deny contains msg if {
	not scope_target
	msg := sprintf("target %s:%d (%s) is not an in-scope target", [input.target.host, input.target.port, input.target.scheme])
}

deny contains "no resolved addresses supplied" if count(input.target.resolved_ips) == 0

deny contains msg if {
	some ip in input.target.resolved_ips
	not ip_in_any(ip, input.scope.allowed_cidrs)
	msg := sprintf("%s is outside allowed_cidrs", [ip])
}

deny contains msg if {
	some ip in input.target.resolved_ips
	ip_in_any(ip, object.get(input.scope, "excluded_cidrs", []))
	msg := sprintf("%s is inside excluded_cidrs", [ip])
}

deny contains msg if {
	some ip in input.target.resolved_ips
	ip_in_any(ip, forbidden_cidrs)
	msg := sprintf("%s is in a globally forbidden network", [ip])
}

deny contains msg if {
	some ip in input.target.resolved_ips
	ip_in_any(ip, loopback_cidrs)
	not input.context.loopback_allowed
	msg := sprintf("%s is loopback and loopback targets are disabled", [ip])
}

deny contains msg if {
	some ip in input.target.resolved_ips
	ip_in_any(ip, loopback_cidrs)
	input.target.port in input.context.protected_ports
	msg := sprintf("port %d on loopback is a protected platform port", [input.target.port])
}

deny contains "request budget exceeds policy" if input.action.max_requests > tool.max_requests

deny contains "request rate exceeds policy" if input.action.requests_per_second > input.policy.max_requests_per_second

deny contains "timeout exceeds policy" if input.action.timeout_seconds > input.policy.job_timeout_seconds

deny contains "timeout exceeds hard limit (300 s)" if input.action.timeout_seconds > 300

# ---- approval ----

require_approval if tool.risk_tier in input.policy.approval_required_risk_tiers

require_approval if tool.risk_tier == "high"

require_approval if input.action.category == "production_change"

approval_valid if {
	input.approval.present == true
	input.approval.verified == true
	input.approval.expires_unix > input.context.now_unix
}

# ---- helpers ----

ip_in_any(ip, cidrs) if {
	some c in cidrs
	net.cidr_contains(c, ip)
}

scope_target if {
	some t in input.scope.targets
	t.host == input.target.host
	input.target.port in t.ports
	input.target.scheme in t.schemes
}

authorization_active if {
	from := time.parse_rfc3339_ns(input.scope.authorization.valid_from)
	until := time.parse_rfc3339_ns(input.scope.authorization.valid_until)
	now := input.context.now_unix * 1000000000
	from <= now
	now < until
}

# ---- decision document ----

default allow := false

allow if {
	count(deny) == 0
	not require_approval
}

allow if {
	count(deny) == 0
	require_approval
	approval_valid
}

decision := {
	"allow": allow,
	"require_approval": require_approval_bool,
	"approval_satisfied": approval_valid_bool,
	"deny_reasons": sort([r | some r in deny]),
}

require_approval_bool if require_approval

else := false

approval_valid_bool if approval_valid

else := false
