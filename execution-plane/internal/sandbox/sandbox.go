// Package sandbox runs one tool invocation in an isolated execution environment.
//
// Backends:
//   - devprocess  (APPROVED DEVELOPMENT SUBSTITUTE): a re-exec'd child process running as a dedicated
//     per-slot UID with no capabilities, no_new_privs, rlimits, empty environment, own process group
//     (killed as a group), and kernel egress filtering by UID via nftables. It shares the host kernel.
//     It is NOT equivalent to a Firecracker microVM and must not be described as such.
//   - firecracker (REQUIRED BY SPEC, NOT IMPLEMENTED): needs a KVM-capable host; refuses to start.
package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/asvas/execution-plane/internal/checks"
	"github.com/asvas/execution-plane/internal/netguard"
	"golang.org/x/sys/unix"
)

var ErrBackendUnavailable = errors.New("execution backend unavailable on this host")

type Info struct {
	Backend        string `json:"backend"`
	IsolationLevel string `json:"isolation_level"`
	EgressMode     string `json:"egress_mode"`
	Note           string `json:"note"`
}

type Backend interface {
	Info() Info
	Run(ctx context.Context, slot int, spec checks.Spec) (checks.Result, error)
}

// ---------------------------------------------------------------------------------- firecracker

type Firecracker struct{}

func NewFirecracker() (*Firecracker, error) {
	if _, err := os.Stat("/dev/kvm"); err != nil {
		return nil, fmt.Errorf("%w: /dev/kvm not present (Firecracker requires KVM)", ErrBackendUnavailable)
	}
	return nil, fmt.Errorf("%w: Firecracker backend is not implemented yet (requirement PO-10)", ErrBackendUnavailable)
}

// ---------------------------------------------------------------------------------- devprocess

const BaseUID = 61000

type DevProcess struct {
	exe    string
	asRoot bool
	egress *Egress
	maxOut int64
	info   Info
}

func NewDevProcess(slots int) (*DevProcess, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	d := &DevProcess{exe: exe, asRoot: os.Geteuid() == 0, maxOut: 2 << 20}
	level := "dev-process: separate UID, no capabilities, no_new_privs, rlimits (shared kernel; NOT a microVM)"
	if !d.asRoot {
		level = "dev-process-degraded: same UID as executor (executor not running as root)"
	}
	mode := "app-pinned-only"
	if d.asRoot {
		if eg, err := NewEgress(slots); err == nil {
			d.egress = eg
			mode = "nftables-per-uid+app-pinned"
		} else {
			mode = "app-pinned-only (nftables unavailable: " + err.Error() + ")"
		}
	}
	d.info = Info{Backend: "devprocess", IsolationLevel: level, EgressMode: mode,
		Note: "Approved development substitute for Firecracker; not equivalent isolation."}
	return d, nil
}

func (d *DevProcess) Info() Info { return d.info }

func (d *DevProcess) SetEgressMode(mode string) { d.info.EgressMode = mode }

func (d *DevProcess) Egress() *Egress { return d.egress }

func (d *DevProcess) Run(ctx context.Context, slot int, spec checks.Spec) (checks.Result, error) {
	if d.egress != nil {
		if err := d.egress.Allow(slot, spec.Allow); err != nil {
			return checks.Result{}, fmt.Errorf("egress programming failed: %w", err)
		}
		defer d.egress.Clear(slot)
	}
	in, _ := json.Marshal(spec)
	return d.runChild(ctx, slot, "sandbox-child", in)
}

func (d *DevProcess) runChild(ctx context.Context, slot int, mode string, stdin []byte) (checks.Result, error) {
	cmd := exec.Command(d.exe, mode)
	cmd.Env = []string{} // no proxy variables, no secrets
	cmd.Dir = "/"
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &out, n: d.maxOut}
	cmd.Stderr = &limitedWriter{w: &errb, n: 64 << 10}
	attr := &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if d.asRoot {
		uid := uint32(BaseUID + slot)
		attr.Credential = &syscall.Credential{Uid: uid, Gid: uid, Groups: []uint32{}}
	}
	cmd.SysProcAttr = attr
	if err := cmd.Start(); err != nil {
		return checks.Result{}, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		var r checks.Result
		if jerr := json.Unmarshal(out.Bytes(), &r); jerr != nil {
			return r, fmt.Errorf("sandbox child failed (%v): %s", err, strings.TrimSpace(errb.String()))
		}
		return r, nil
	case <-ctx.Done():
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) // whole process group
		<-done
		return checks.Result{}, ctx.Err()
	}
}

// SelfTest proves the sandbox cannot reach a destination that is not in its allowlist.
func (d *DevProcess) SelfTest(ctx context.Context, probePort int) (bool, string) {
	spec := checks.Spec{ToolID: "egress-probe", Target: netguard.Endpoint{Host: "127.0.0.1", Port: probePort}}
	in, _ := json.Marshal(spec)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	r, err := d.runChild(ctx, 0, "egress-probe", in)
	if err != nil {
		return false, err.Error()
	}
	return r.Error != "", r.Error
}

type limitedWriter struct {
	w io.Writer
	n int64
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n <= 0 {
		return len(p), nil
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.w.Write(p)
	l.n -= int64(n)
	return len(p), err
}

// ---------------------------------------------------------------------------------- child side

// ChildInit hardens the current (child) process before any tool code runs.
func ChildInit() map[string]any {
	att := map[string]any{"uid": os.Getuid(), "gid": os.Getgid()}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		fmt.Fprintln(os.Stderr, "no_new_privs failed:", err)
		os.Exit(70)
	}
	limits := map[int]uint64{unix.RLIMIT_NOFILE: 64, unix.RLIMIT_CORE: 0, unix.RLIMIT_FSIZE: 0,
		unix.RLIMIT_AS: 4 << 30, unix.RLIMIT_CPU: 60}
	for res, v := range limits {
		if err := unix.Setrlimit(res, &unix.Rlimit{Cur: v, Max: v}); err != nil {
			fmt.Fprintln(os.Stderr, "setrlimit failed:", err)
			os.Exit(70)
		}
	}
	if b, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			for _, k := range []string{"CapEff", "CapPrm", "NoNewPrivs", "Seccomp"} {
				if strings.HasPrefix(line, k+":") {
					att[strings.ToLower(k)] = strings.TrimSpace(strings.TrimPrefix(line, k+":"))
				}
			}
		}
	}
	return att
}

func ChildMain(mode string) int {
	att := ChildInit()
	var spec checks.Spec
	if err := json.NewDecoder(io.LimitReader(os.Stdin, 1<<20)).Decode(&spec); err != nil {
		fmt.Fprintln(os.Stderr, "bad spec:", err)
		return 65
	}
	var res checks.Result
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(max(1000, spec.TimeoutMS))*time.Millisecond)
	defer cancel()
	if mode == "egress-probe" {
		c, err := (&netDialer{}).dial(ctx, fmt.Sprintf("127.0.0.1:%d", spec.Target.Port))
		if err == nil {
			c.Close()
		} else {
			res.Error = err.Error()
		}
	} else {
		res = checks.Run(ctx, spec)
	}
	res.Attestation = att
	_ = json.NewEncoder(os.Stdout).Encode(res)
	return 0
}
