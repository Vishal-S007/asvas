package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/asvas/execution-plane/internal/netguard"
)

func TestTLSCheckRecordsUntrustedAndRejectsLegacy(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	port, _ := strconv.Atoi(srv.URL[strings.LastIndex(srv.URL, ":")+1:])
	ep := netguard.Endpoint{Scheme: "https", Host: "127.0.0.1", Port: port, IPs: []string{"127.0.0.1"}}
	r := RunTLS(context.Background(), Spec{ToolID: "tls.configuration", Target: ep, Allow: []netguard.Endpoint{ep},
		MaxRequests: 2, TimeoutMS: 4000, ExpiryDays: 30})
	if len(r.Exchanges) != 2 || r.RequestsUsed != 2 {
		t.Fatalf("expected 2 probes, got %+v", r)
	}
	d, legacy := r.Exchanges[0].TLS, r.Exchanges[1].TLS
	if !d.Handshake || d.VerifyError == "" || d.LeafSHA256 == "" {
		t.Fatalf("default probe: %+v", d)
	}
	if legacy.Handshake { // Go's test server only speaks TLS 1.2+
		t.Fatalf("legacy probe unexpectedly succeeded: %+v", legacy)
	}
}

func TestTLSCheckHonoursRequestBudget(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	port, _ := strconv.Atoi(srv.URL[strings.LastIndex(srv.URL, ":")+1:])
	ep := netguard.Endpoint{Scheme: "https", Host: "127.0.0.1", Port: port, IPs: []string{"127.0.0.1"}}
	r := RunTLS(context.Background(), Spec{Target: ep, MaxRequests: 1, TimeoutMS: 4000, ExpiryDays: 30})
	if r.RequestsUsed != 1 || len(r.Exchanges) != 1 {
		t.Fatalf("budget not honoured: %d", r.RequestsUsed)
	}
}
