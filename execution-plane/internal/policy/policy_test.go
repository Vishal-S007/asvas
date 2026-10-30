package policy

import (
	"context"
	"testing"
)

func TestLoadsSharedBundleAndFailsClosed(t *testing.T) {
	e, err := Load(context.Background(), "../../../policies")
	if err != nil {
		t.Fatal(err)
	}
	if d := e.Evaluate(context.Background(), map[string]any{}); d.Allow {
		t.Fatal("empty input allowed")
	}
	in := map[string]any{
		"action": map[string]any{"tool_id": "http.security_headers", "risk_tier": "low", "category": "non_destructive",
			"max_requests": 4, "requests_per_second": 2, "timeout_seconds": 20},
		"target": map[string]any{"scheme": "http", "host": "127.0.0.1", "port": 18080, "resolved_ips": []any{"127.0.0.1"}},
		"scope": map[string]any{"targets": []any{map[string]any{"host": "127.0.0.1", "ports": []any{18080}, "schemes": []any{"http"}}},
			"allowed_cidrs": []any{"127.0.0.1/32"},
			"authorization": map[string]any{"valid_from": "2026-01-01T00:00:00Z", "valid_until": "2027-01-01T00:00:00Z"}},
		"policy":   map[string]any{"allowed_tools": []any{"http.security_headers"}, "approval_required_risk_tiers": []any{"high"}, "max_requests_per_second": 2, "job_timeout_seconds": 20},
		"approval": map[string]any{"present": false},
		"context":  map[string]any{"now_unix": 1790000000, "loopback_allowed": true, "protected_ports": []any{5432}, "halted": false},
	}
	if d := e.Evaluate(context.Background(), in); !d.Allow {
		t.Fatalf("expected allow, got %+v", d)
	}
	in["context"].(map[string]any)["loopback_allowed"] = false
	if d := e.Evaluate(context.Background(), in); d.Allow {
		t.Fatal("loopback allowed while disabled")
	}
}
