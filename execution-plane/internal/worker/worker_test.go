package worker

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/asvas/execution-plane/gen/asvasrpc/execution/v1"
	"github.com/asvas/execution-plane/internal/canonical"
	"github.com/asvas/execution-plane/internal/envelope"
	"github.com/asvas/execution-plane/internal/netguard"
	"github.com/asvas/execution-plane/internal/policy"
	"github.com/asvas/execution-plane/internal/sandbox"
	"github.com/redis/go-redis/v9"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

const master = "go-test-master-key"

// The sandbox re-executes the current binary; in tests that is this test binary.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && (os.Args[1] == "sandbox-child" || os.Args[1] == "egress-probe") {
		os.Exit(sandbox.ChildMain(os.Args[1]))
	}
	sandbox.BaseUID = 63000
	// The sandbox UID must be able to execute the re-exec'd binary; go test builds it in a private dir.
	if os.Geteuid() == 0 {
		dir, _ := os.MkdirTemp("", "asvas-sbx")
		_ = os.Chmod(dir, 0o755)
		self, _ := os.Executable()
		b, _ := os.ReadFile(self)
		exe := dir + "/worker.test"
		_ = os.WriteFile(exe, b, 0o755)
		os.Setenv("ASVAS_SANDBOX_EXE", exe)
		code := m.Run()
		os.RemoveAll(dir)
		os.Exit(code)
	}
	os.Exit(m.Run())
}

type fixture struct {
	w     *Worker
	rdb   *redis.Client
	port  int
	hits  *atomic.Int32
	close func()
}

func setup(t *testing.T, resolver netguard.Resolver) *fixture {
	t.Helper()
	rdb := testRedis(t)
	rdb.FlushDB(context.Background())
	pol, err := policy.Load(context.Background(), "../../../policies")
	if err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/slow" {
			select {
			case <-time.After(60 * time.Second):
			case <-r.Context().Done():
			}
			return
		}
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, "<html>ok</html>")
	}))
	port, _ := strconv.Atoi(srv.URL[strings.LastIndex(srv.URL, ":")+1:])
	sb, err := sandbox.NewDevProcess(2)
	if err != nil {
		t.Fatal(err)
	}
	if resolver == nil {
		resolver = netguard.SystemResolver
	}
	w := New(Config{WorkerID: "go-test", Slots: 2, MasterKey: master, Resolver: resolver,
		Net: netguard.Config{AllowLoopback: true, ProtectedPorts: []int{5432}}}, rdb, pol, sb, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return &fixture{w: w, rdb: rdb, port: port, hits: &hits, close: func() {
		srv.Close()
		if sb.Egress() != nil {
			sb.Egress().Teardown()
		}
	}}
}

// testRedis connects to the plain dev/CI Redis, or to the TLS-only dev Redis (scripts/dev-tls-services.sh)
// verified against the dev CA. Skips when neither is reachable.
func testRedis(t *testing.T) *redis.Client {
	t.Helper()
	urls := []string{envOr("TEST_REDIS_URL_GO", "redis://localhost:6379/14"), "rediss://localhost:6380/14"}
	for _, u := range urls {
		opt, err := redis.ParseURL(u)
		if err != nil {
			continue
		}
		if opt.TLSConfig != nil {
			pem, err := os.ReadFile("../../../var/certs/ca.crt")
			if err != nil {
				continue
			}
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(pem)
			opt.TLSConfig.RootCAs = pool
		}
		opt.MaxRetries = -1 // probe quickly; fall through to the next candidate
		rdb := redis.NewClient(opt)
		if rdb.Ping(context.Background()).Err() == nil {
			return rdb
		}
		rdb.Close()
	}
	t.Skip("redis not available (plain or TLS)")
	return nil
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func (f *fixture) envelope(mut func(map[string]any)) map[string]any {
	now := time.Now()
	e := map[string]any{
		"v": 1, "job_id": "11111111-1111-4111-8111-111111111111", "attempt": 1,
		"tenant_id": "22222222-2222-4222-8222-222222222222", "assessment_id": "33333333-3333-4333-8333-333333333333",
		"tool_id": "http.security_headers", "risk_tier": "low", "category": "non_destructive",
		"target":       map[string]any{"scheme": "http", "host": "127.0.0.1", "port": f.port},
		"params":       map[string]any{"path": "/", "method": "GET", "max_redirects": 0},
		"max_requests": 4, "requests_per_second": 2, "timeout_seconds": 5,
		"deadline_unix": now.Add(20 * time.Second).Unix(), "issued_unix": now.Unix(),
		"scope": map[string]any{"targets": []any{map[string]any{"host": "127.0.0.1", "ports": []any{f.port}, "schemes": []any{"http"}}},
			"allowed_cidrs": []any{"127.0.0.1/32"}, "excluded_cidrs": []any{},
			"authorization": map[string]any{"statement": "s", "reference": "r", "authorized_by": "a",
				"valid_from": now.Add(-time.Hour).UTC().Format(time.RFC3339), "valid_until": now.Add(time.Hour).UTC().Format(time.RFC3339)}},
		"policy": map[string]any{"allowed_tools": []any{"http.security_headers", "http.allowed_methods"},
			"approval_required_risk_tiers": []any{"medium", "high"}, "max_requests_per_second": 2, "job_timeout_seconds": 20},
		"approval": nil,
	}
	if mut != nil {
		mut(e)
	}
	return e
}

var paramField = map[string]string{"http.security_headers": "security_headers", "http.allowed_methods": "allowed_methods",
	"tls.configuration": "tls"}

// encode turns the test's map form of an envelope into the protobuf wire bytes the control plane sends.
// Inputs that cannot be expressed in the typed contract (unknown fields, free-form params) fail here.
func encode(e map[string]any) ([]byte, error) {
	m := map[string]any{}
	for k, v := range e {
		m[k] = v
	}
	delete(m, "v")
	m["version"] = envelope.WireVersion
	field, ok := paramField[m["tool_id"].(string)]
	if !ok {
		field = "security_headers"
	}
	m[field] = m["params"]
	delete(m, "params")
	if m["approval"] == nil {
		delete(m, "approval")
	}
	js, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var msg pb.JobEnvelope
	if err := protojson.Unmarshal(js, &msg); err != nil {
		return nil, err
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(&msg)
}

func sign(t *testing.T, e map[string]any) ([]byte, string) {
	data, err := encode(e)
	if err != nil {
		t.Fatal(err)
	}
	return data, canonical.HMACHexBytes(canonical.DerivedKey(master, "envelope"), data)
}

func (f *fixture) exec(t *testing.T, e map[string]any) Result {
	data, sig := sign(t, e)
	env, err := envelope.OpenPB(data, sig, canonical.DerivedKey(master, "envelope"))
	if err != nil {
		t.Fatal(err)
	}
	return f.w.Execute(context.Background(), 1, env)
}

func approve(t *testing.T, e map[string]any, bindingFrom map[string]any) {
	b, _ := json.Marshal(bindingFrom)
	env := &envelope.Envelope{}
	_ = json.Unmarshal(b, env)
	bh, err := env.BindingHash()
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(10 * time.Minute).Unix()
	msg, _ := canonical.Marshal(map[string]any{"approval_id": "a1", "binding_hash": bh, "expires_unix": exp})
	e["approval"] = map[string]any{"approval_id": "a1", "binding_hash": bh, "expires_unix": exp,
		"token": canonical.HMACHex(canonical.DerivedKey(master, "approval"), msg)}
}

func TestAllowedJobRunsInSandbox(t *testing.T) {
	f := setup(t, nil)
	defer f.close()
	r := f.exec(t, f.envelope(nil))
	if r.Status != "SUCCEEDED" || len(r.Exchanges) != 1 || r.Exchanges[0].Response.Status != 200 {
		t.Fatalf("unexpected %+v", r)
	}
	if r.Attestation["credential_verified"] != true || r.Attestation["credential_id"] == "" {
		t.Fatalf("sandbox result not bound to a per-run credential (PO-16): %v", r.Attestation)
	}
	if r.Attestation["nonewprivs"] != "1" {
		t.Fatalf("no_new_privs not set in sandbox: %v", r.Attestation)
	}
	if os.Geteuid() == 0 && (r.Attestation["capeff"] != "0000000000000000" || r.Attestation["uid"].(float64) < 63000) {
		t.Fatalf("sandbox not privilege-dropped: %v", r.Attestation)
	}
}

func TestCompromisedControlPlaneOutOfScopeDenied(t *testing.T) {
	// Validly signed envelope whose target is not in its own scope (e.g. a buggy/compromised control plane).
	f := setup(t, nil)
	defer f.close()
	r := f.exec(t, f.envelope(func(e map[string]any) {
		e["target"] = map[string]any{"scheme": "http", "host": "169.254.169.254", "port": 80}
	}))
	if r.Status != "DENIED" || f.hits.Load() != 0 {
		t.Fatalf("expected DENIED with no traffic, got %s %s", r.Status, r.Error)
	}
}

func TestProtectedPortDenied(t *testing.T) {
	f := setup(t, nil)
	defer f.close()
	r := f.exec(t, f.envelope(func(e map[string]any) {
		e["target"] = map[string]any{"scheme": "http", "host": "127.0.0.1", "port": 5432}
		e["scope"].(map[string]any)["targets"] = []any{map[string]any{"host": "127.0.0.1", "ports": []any{5432}, "schemes": []any{"http"}}}
	}))
	if r.Status != "DENIED" || !strings.Contains(r.Error, "protected") {
		t.Fatalf("got %s %s", r.Status, r.Error)
	}
}

func TestApprovalRequiredAndBoundToParams(t *testing.T) {
	f := setup(t, nil)
	defer f.close()
	medium := func(e map[string]any) {
		e["tool_id"], e["risk_tier"], e["max_requests"] = "http.allowed_methods", "medium", 1
		e["params"] = map[string]any{"path": "/"}
	}
	if r := f.exec(t, f.envelope(medium)); r.Status != "DENIED" {
		t.Fatalf("medium without approval: %s", r.Status)
	}
	ok := f.envelope(medium)
	approve(t, ok, ok)
	if r := f.exec(t, ok); r.Status != "SUCCEEDED" {
		t.Fatalf("approved job: %s %s", r.Status, r.Error)
	}
	// Parameters changed after approval: the old approval must not be reusable.
	tampered := f.envelope(medium)
	approve(t, tampered, f.envelope(medium))
	tampered["params"] = map[string]any{"path": "/admin"}
	if r := f.exec(t, tampered); r.Status != "DENIED" {
		t.Fatalf("tampered params accepted: %s", r.Status)
	}
	// Forged token.
	forged := f.envelope(medium)
	approve(t, forged, forged)
	forged["approval"].(map[string]any)["token"] = strings.Repeat("ab", 32)
	if r := f.exec(t, forged); r.Status != "DENIED" {
		t.Fatalf("forged token accepted")
	}
	// Expired approval.
	expired := f.envelope(medium)
	approve(t, expired, expired)
	a := expired["approval"].(map[string]any)
	a["expires_unix"] = time.Now().Add(-time.Second).Unix()
	msg, _ := canonical.Marshal(map[string]any{"approval_id": "a1", "binding_hash": a["binding_hash"], "expires_unix": a["expires_unix"]})
	a["token"] = canonical.HMACHex(canonical.DerivedKey(master, "approval"), msg)
	if r := f.exec(t, expired); r.Status != "DENIED" {
		t.Fatalf("expired approval accepted")
	}
}

func TestInvalidEnvelopesRejected(t *testing.T) {
	f := setup(t, nil)
	defer f.close()
	key := canonical.DerivedKey(master, "envelope")
	data, sig := sign(t, f.envelope(nil))
	if _, err := envelope.OpenPB(data, strings.Repeat("0", 64), key); err == nil {
		t.Fatal("bad signature accepted")
	}
	tampered := append([]byte{}, data...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := envelope.OpenPB(tampered, sig, key); err == nil {
		t.Fatal("modified bytes accepted")
	}
	// A correctly signed message carrying a field this build does not know must be rejected.
	withUnknown := protowire.AppendTag(append([]byte{}, data...), 99, protowire.BytesType)
	withUnknown = protowire.AppendString(withUnknown, "shell:id")
	if _, err := envelope.OpenPB(withUnknown, canonical.HMACHexBytes(key, withUnknown), key); err == nil ||
		!strings.Contains(err.Error(), "unknown fields") {
		t.Fatalf("unknown field accepted: %v", err)
	}
	cases := map[string]func(map[string]any){
		"unknown top-level field": func(e map[string]any) { e["shell"] = "id" },
		"unknown tool":            func(e map[string]any) { e["tool_id"] = "shell.exec" },
		"params for another tool": func(e map[string]any) { e["tool_id"] = "tls.configuration"; e["risk_tier"] = "low" },
		"param injection": func(e map[string]any) {
			e["params"] = map[string]any{"path": "/;id", "method": "GET", "max_redirects": 0}
		},
		"extra param": func(e map[string]any) {
			e["params"] = map[string]any{"path": "/", "method": "GET", "max_redirects": 0, "cmd": "x"}
		},
		"bad method": func(e map[string]any) {
			e["params"] = map[string]any{"path": "/", "method": "DELETE", "max_redirects": 0}
		},
		"timeout > 300": func(e map[string]any) { e["timeout_seconds"] = 301 },
	}
	for name, mut := range cases {
		data, err := encode(f.envelope(mut))
		if err != nil {
			continue // not even expressible in the typed contract
		}
		if _, err := envelope.OpenPB(data, canonical.HMACHexBytes(key, data), key); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDNSRebindingDetected(t *testing.T) {
	var n atomic.Int32
	flip := func(_ context.Context, h string) ([]netip.Addr, error) {
		if n.Add(1) == 1 { // first answer differs from the allowlist build
			return []netip.Addr{netip.MustParseAddr("127.0.0.2")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	f := setup(t, flip)
	defer f.close()
	r := f.exec(t, f.envelope(func(e map[string]any) {
		e["target"] = map[string]any{"scheme": "http", "host": "rebind.test", "port": f.port}
		e["scope"].(map[string]any)["targets"] = []any{map[string]any{"host": "rebind.test", "ports": []any{f.port}, "schemes": []any{"http"}}}
		e["scope"].(map[string]any)["allowed_cidrs"] = []any{"127.0.0.0/30"}
	}))
	if r.Status != "DENIED" || !strings.Contains(r.Error, "rebinding") {
		t.Fatalf("got %s %s", r.Status, r.Error)
	}
}

func TestTimeoutKillsSandbox(t *testing.T) {
	f := setup(t, nil)
	defer f.close()
	start := time.Now()
	r := f.exec(t, f.envelope(func(e map[string]any) {
		e["params"] = map[string]any{"path": "/slow", "method": "GET", "max_redirects": 0}
		e["timeout_seconds"] = 2
	}))
	if r.Status != "TIMED_OUT" && r.Status != "FAILED" {
		t.Fatalf("got %s %s", r.Status, r.Error)
	}
	if time.Since(start) > 8*time.Second {
		t.Fatalf("timeout not enforced: %v", time.Since(start))
	}
}

func TestCancellationKillsRunningJob(t *testing.T) {
	f := setup(t, nil)
	defer f.close()
	done := make(chan Result, 1)
	e := f.envelope(func(e map[string]any) {
		e["params"] = map[string]any{"path": "/slow", "method": "GET", "max_redirects": 0}
		e["timeout_seconds"] = 20
	})
	go func() { done <- f.exec(t, e) }()
	deadline := time.Now().Add(5 * time.Second)
	for f.hits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	start := time.Now()
	if n := f.w.KillMatching("22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333", "test"); n != 1 {
		t.Fatalf("expected to signal 1 job, signalled %d", n)
	}
	r := <-done
	if r.Status != "CANCELLED" || time.Since(start) > 3*time.Second {
		t.Fatalf("got %s after %v", r.Status, time.Since(start))
	}
}

func TestHaltedAndDuplicate(t *testing.T) {
	f := setup(t, nil)
	defer f.close()
	ctx := context.Background()
	f.rdb.Set(ctx, "asvas:halt:assessment:33333333-3333-4333-8333-333333333333", "1", time.Minute)
	if r := f.exec(t, f.envelope(nil)); r.Status != "CANCELLED" {
		t.Fatalf("halted assessment executed: %s", r.Status)
	}
	f.rdb.Del(ctx, "asvas:halt:assessment:33333333-3333-4333-8333-333333333333")
	data, sig := sign(t, f.envelope(nil))
	body := base64.StdEncoding.EncodeToString(data)
	msg := redis.XMessage{ID: "1-1", Values: map[string]any{"envelope_pb": body, "sig": sig}}
	f.w.handle(ctx, 1, msg)
	f.w.handle(ctx, 1, msg)
	if n := f.rdb.XLen(ctx, Results).Val(); n != 1 {
		t.Fatalf("duplicate delivery produced %d results", n)
	}
	if f.hits.Load() != 1 {
		t.Fatalf("target hit %d times", f.hits.Load())
	}
	// Forged envelope: dropped without any result or traffic.
	f.w.handle(ctx, 1, redis.XMessage{ID: "1-2", Values: map[string]any{"envelope_pb": body, "sig": strings.Repeat("0", 64)}})
	if n := f.rdb.XLen(ctx, Results).Val(); n != 1 || f.hits.Load() != 1 {
		t.Fatal("forged envelope had an effect")
	}
	_ = fmt.Sprint()
}

func TestKernelEgressBlocksNonAllowlisted(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("nftables egress requires root")
	}
	f := setup(t, nil)
	defer f.close()
	sb := f.w.sb.(*sandbox.DevProcess)
	if sb.Egress() == nil {
		t.Skip("nft unavailable")
	}
	// The probe runs as a sandbox UID with an EMPTY allow-set; the listener exists, so only the kernel rule can refuse it.
	ok, detail := sb.SelfTest(context.Background(), f.port)
	if !ok {
		t.Fatalf("sandbox reached a non-allowlisted port: %s", detail)
	}
	if f.hits.Load() != 0 {
		t.Fatal("target was contacted")
	}
}

func TestKernelEgressRequirementEnforced(t *testing.T) {
	f := setup(t, nil)
	defer f.close()
	sb := f.w.sb.(*sandbox.DevProcess)
	req := func(e map[string]any) { e["policy"].(map[string]any)["require_kernel_egress"] = true }
	sb.SetEgressMode("app-pinned-only (simulated: nftables unavailable)")
	if r := f.exec(t, f.envelope(req)); r.Status != "DENIED" || !strings.Contains(r.Error, "kernel egress") {
		t.Fatalf("ran without kernel egress: %s %s", r.Status, r.Error)
	}
	if sb.Egress() != nil {
		sb.SetEgressMode("nftables-per-uid+app-pinned")
		if r := f.exec(t, f.envelope(req)); r.Status != "SUCCEEDED" {
			t.Fatalf("enforced egress but denied: %s %s", r.Status, r.Error)
		}
	}
}
