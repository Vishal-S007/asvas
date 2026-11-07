package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/asvas/execution-plane/internal/checks"
	"github.com/asvas/execution-plane/internal/netguard"
)

// fakeFirecracker simulates the parts of Firecracker the backend uses: the API socket and, once the VM is
// started, the host side of the vsock device forwarding CONNECT 5000 to a guest agent (ServeGuestConn).
// It lets the boot sequence, job channel and credential checks run without KVM. It is NOT a microVM.
type fakeFirecracker struct {
	mu      sync.Mutex
	calls   []apiCall
	guest   func(c net.Conn) // guest agent behaviour
	started chan struct{}
}

func (ff *fakeFirecracker) start(ctx context.Context, _ int, jail string, args []string) (*exec.Cmd, error) {
	cmd := exec.Command("sleep", "30") // stands in for the jailer process (killed by the backend)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	ln, err := net.Listen("unix", filepath.Join(jail, "run", "firecracker.socket"))
	if err != nil {
		return nil, err
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		ff.mu.Lock()
		ff.calls = append(ff.calls, apiCall{r.Method, r.URL.Path, body})
		ff.mu.Unlock()
		if r.URL.Path == "/actions" || r.URL.Path == "/snapshot/load" {
			go ff.vsock(jail)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.Listener = ln
	srv.Start()
	go func() { <-ctx.Done(); srv.Close() }()
	return cmd, nil
}

func (ff *fakeFirecracker) vsock(jail string) {
	ln, err := net.Listen("unix", filepath.Join(jail, "run", "vsock.sock"))
	if err != nil {
		return
	}
	defer ln.Close()
	c, err := ln.Accept()
	if err != nil {
		return
	}
	line, _ := bufio.NewReader(c).ReadString('\n')
	if strings.TrimSpace(line) != fmt.Sprintf("CONNECT %d", GuestAgentPort) {
		c.Close()
		return
	}
	fmt.Fprintf(c, "OK 1073741824\n")
	ff.guest(c)
}

func testFC(t *testing.T, snapshot string, guest func(net.Conn)) (*Firecracker, *fakeFirecracker) {
	t.Helper()
	dir := t.TempDir()
	for _, f := range []string{"vmlinux", "rootfs.ext4"} {
		_ = os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644)
	}
	if snapshot != "" {
		_ = os.MkdirAll(snapshot, 0o755)
		_ = os.WriteFile(filepath.Join(snapshot, "vmstate"), []byte("s"), 0o644)
		_ = os.WriteFile(filepath.Join(snapshot, "mem"), []byte("m"), 0o644)
	}
	iss, _ := NewIssuer()
	cfg := FirecrackerConfig{FirecrackerBin: "/usr/bin/firecracker", JailerBin: "/usr/bin/jailer",
		KernelImage: filepath.Join(dir, "vmlinux"), RootFS: filepath.Join(dir, "rootfs.ext4"), SnapshotDir: snapshot,
		ChrootBase: shortDir(t), BaseUID: 64000, VCPUs: 1, MemMiB: 256, BootTimeout: 3 * time.Second}
	f := newFirecracker(cfg, iss)
	ff := &fakeFirecracker{guest: guest}
	f.startVM = ff.start
	return f, ff
}

// unix socket paths are limited to 108 bytes; t.TempDir() paths are too long for jail/<id>/root/run/x.sock
func shortDir(t *testing.T) string {
	d, err := os.MkdirTemp("/tmp", "fc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func honestGuest(c net.Conn) {
	_ = ServeGuestConn(context.Background(), c, map[string]any{"guest_agent": "test"})
}

func spec() checks.Spec {
	// a port nothing listens on: the check records a connection error, which is fine for protocol testing
	return checks.Spec{ToolID: "http.security_headers", Target: netguard.Endpoint{Scheme: "http", Host: "127.0.0.1", Port: 1, IPs: []string{"127.0.0.1"}},
		Path: "/", MaxRequests: 1, RPS: 1, TimeoutMS: 1000,
		Allow: []netguard.Endpoint{{Scheme: "http", Host: "127.0.0.1", Port: 1, IPs: []string{"127.0.0.1"}}}}
}

func TestColdBootSequenceReadOnlyRootfsAndSignedResult(t *testing.T) {
	f, ff := testFC(t, "", honestGuest)
	res, err := f.Run(context.Background(), 2, spec())
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{}
	for _, c := range ff.calls {
		paths = append(paths, c.Path)
		if c.Path == "/drives/rootfs" && c.Body.(map[string]any)["is_read_only"] != true {
			t.Fatal("rootfs not attached read-only")
		}
	}
	want := "/machine-config /boot-source /drives/rootfs /vsock /actions"
	if strings.Join(paths, " ") != want {
		t.Fatalf("boot sequence %v, want %s", paths, want)
	}
	if res.Attestation["credential_verified"] != true || res.Attestation["rootfs_read_only"] != true ||
		res.Attestation["backend"] != "firecracker" || res.Attestation["snapshot_restore"] != false {
		t.Fatalf("attestation %v", res.Attestation)
	}
	if res.RequestsUsed > 1 {
		t.Fatalf("budget exceeded: %d", res.RequestsUsed)
	}
	if _, err := os.Stat(f.cfg.ChrootBase + "/firecracker"); err == nil {
		entries, _ := os.ReadDir(f.cfg.ChrootBase + "/firecracker")
		if len(entries) != 0 {
			t.Fatalf("jail not cleaned up: %v", entries)
		}
	}
}

func TestSnapshotRestorePath(t *testing.T) {
	f, ff := testFC(t, filepath.Join(t.TempDir(), "snap"), honestGuest)
	res, err := f.Run(context.Background(), 0, spec())
	if err != nil {
		t.Fatal(err)
	}
	if len(ff.calls) != 1 || ff.calls[0].Path != "/snapshot/load" || res.Attestation["snapshot_restore"] != true {
		t.Fatalf("calls %+v", ff.calls)
	}
}

func TestForgedGuestResultRejected(t *testing.T) {
	forger := func(c net.Conn) {
		var s checks.Spec
		_ = readFrame(c, &s)
		other, _ := NewIssuer()
		cred, _ := other.Issue(0, time.Minute)
		r := checks.Result{RequestsUsed: 0}
		_ = SignResult(&cred, &r) // signed with a credential that is not this run's
		_ = writeFrame(c, r)
	}
	f, _ := testFC(t, "", forger)
	if _, err := f.Run(context.Background(), 1, spec()); err == nil || !strings.Contains(err.Error(), "PO-16") {
		t.Fatalf("forged result accepted: %v", err)
	}
}

func TestSilentGuestTimesOut(t *testing.T) {
	f, _ := testFC(t, "", func(c net.Conn) { time.Sleep(5 * time.Second) })
	f.cfg.BootTimeout = 300 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := f.Run(ctx, 1, spec()); err == nil {
		t.Fatal("expected timeout")
	}
}

func TestJailerArgsAndHostCheck(t *testing.T) {
	f, _ := testFC(t, "", honestGuest)
	f.cfg.NetnsPrefix = "asvas-fc"
	a := strings.Join(f.JailerArgs("vm1", 3), " ")
	for _, want := range []string{"--uid 64003", "--gid 64003", "--new-pid-ns", "--netns /var/run/netns/asvas-fc-3",
		"--chroot-base-dir", "-- --api-sock /run/firecracker.socket"} {
		if !strings.Contains(a, want) {
			t.Fatalf("jailer args %q lack %q", a, want)
		}
	}
	missing := FirecrackerConfig{FirecrackerBin: "/nonexistent/fc", JailerBin: "/nonexistent/j", KernelImage: "/x", RootFS: "/y"}.HostCheck()
	if _, err := os.Stat("/dev/kvm"); err != nil && !strings.Contains(strings.Join(missing, ";"), "/dev/kvm") {
		t.Fatalf("host check did not report missing KVM: %v", missing)
	}
	if _, err := NewFirecracker(FirecrackerConfig{FirecrackerBin: "/nonexistent"}); !errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("expected ErrBackendUnavailable, got %v", err)
	}
}

func TestFrameLimit(t *testing.T) {
	a, b := net.Pipe()
	go func() { _, _ = a.Write([]byte{0xff, 0xff, 0xff, 0xff}); a.Close() }()
	var v map[string]any
	if err := readFrame(b, &v); err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("oversized frame accepted: %v", err)
	}
}

func TestTapEgressRules(t *testing.T) {
	rs := tapRuleset(2)
	for _, want := range []string{`iifname "asvastap1" ip daddr . tcp dport @allow4_1 accept`, `iifname "asvastap1" counter drop`,
		`iifname "asvastap0" drop`} {
		if !strings.Contains(rs, want) {
			t.Fatalf("ruleset lacks %q:\n%s", want, rs)
		}
	}
	var got []string
	e := &TapEgress{slots: 2, apply: func(s string) error { got = append(got, s); return nil }}
	if err := e.Allow(1, []netguard.Endpoint{{Port: 443, IPs: []string{"192.0.2.10"}}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got[0], "add element inet asvas_fc allow4_1 { 192.0.2.10 . 443 }") {
		t.Fatalf("allow: %q", got[0])
	}
	if err := e.Allow(0, []netguard.Endpoint{{Port: 443, IPs: []string{"2001:db8::1"}}}); err == nil {
		t.Fatal("IPv6 should be refused for VMs")
	}
	if os.Geteuid() == 0 {
		if _, err := exec.LookPath("nft"); err == nil { // the generated ruleset must be accepted by the kernel
			real, err := NewTapEgress(2)
			if err != nil {
				t.Fatalf("nft rejected tap ruleset: %v", err)
			}
			if err := real.Allow(1, []netguard.Endpoint{{Port: 443, IPs: []string{"192.0.2.10"}}}); err != nil {
				t.Fatal(err)
			}
			real.Teardown()
		}
	}
}
