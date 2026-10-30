package netguard

import (
	"context"
	"net/netip"
	"testing"
)

func fake(m map[string][]string) Resolver {
	return func(_ context.Context, h string) ([]netip.Addr, error) {
		var out []netip.Addr
		for _, s := range m[h] {
			out = append(out, netip.MustParseAddr(s))
		}
		return out, nil
	}
}

func TestRebindingMixedAnswersDropped(t *testing.T) {
	r := fake(map[string][]string{"app.test": {"10.0.0.5", "169.254.169.254"}, "ok.test": {"10.0.0.6"}})
	eps, rej := BuildAllowlist(context.Background(), Config{}, r,
		[]ScopeTarget{{"app.test", []int{80}, []string{"http"}}, {"ok.test", []int{80}, []string{"http"}}},
		[]string{"10.0.0.0/24"}, nil)
	if len(eps) != 1 || eps[0].Host != "ok.test" {
		t.Fatalf("expected only ok.test, got %+v", eps)
	}
	if len(rej["app.test:80"]) == 0 {
		t.Fatal("expected rejection reasons for app.test")
	}
}

func TestLoopbackAndProtectedPorts(t *testing.T) {
	lo := netip.MustParseAddr("127.0.0.1")
	if len(Violations(Config{}, lo, 18080, []string{"127.0.0.1/32"}, nil)) == 0 {
		t.Fatal("loopback allowed while disabled")
	}
	if len(Violations(Config{AllowLoopback: true, ProtectedPorts: []int{5432}}, lo, 18080, []string{"127.0.0.1/32"}, nil)) != 0 {
		t.Fatal("in-scope loopback denied while enabled")
	}
	if len(Violations(Config{AllowLoopback: true, ProtectedPorts: []int{5432}}, lo, 5432, []string{"127.0.0.1/32"}, nil)) == 0 {
		t.Fatal("protected port allowed")
	}
}

func TestOutOfScopeAndExcluded(t *testing.T) {
	if len(Violations(Config{}, netip.MustParseAddr("8.8.8.8"), 80, []string{"10.0.0.0/24"}, nil)) == 0 {
		t.Fatal("out of scope allowed")
	}
	if len(Violations(Config{}, netip.MustParseAddr("10.0.0.200"), 80, []string{"10.0.0.0/24"}, []string{"10.0.0.128/25"})) == 0 {
		t.Fatal("excluded allowed")
	}
}
