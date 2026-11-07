// Package sandbox runs one tool invocation in an isolated execution environment.
//
// Backends:
//   - devprocess  (APPROVED DEVELOPMENT SUBSTITUTE): a re-exec'd child process running as a dedicated
//     per-slot UID with no capabilities, no_new_privs, rlimits, empty environment, own process group
//     (killed as a group), and kernel egress filtering by UID via nftables. It shares the host kernel.
//     It is NOT equivalent to a Firecracker microVM and must not be described as such.
//   - firecracker (REQUIRED BY SPEC): one jailed Firecracker microVM per job (firecracker.go). Implemented and
//     unit-tested against a simulated Firecracker API and guest; NOT yet run on a KVM host (none available
//     during development). Refuses to start without /dev/kvm, the binaries, kernel and read-only rootfs.
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
	"github.com/asvas/execution-plane/internal/ebpfmon"
	"github.com/asvas/execution-plane/internal/netguard"
	"golang.org/x/sys/unix"
)

var ErrBackendUnavailable = errors.New("execution backend unavailable on this host")

type Info struct {
	Backend        string `json:"backend"`
	IsolationLevel string `json:"isolation_level"`
	EgressMode     string `json:"egress_mode"`
	Note           string `json:"note"`
	SyscallMonitor string `json:"syscall_monitor"`
}

type Backend interface {
	Info() Info
	Run(ctx context.Context, slot int, spec checks.Spec) (checks.Result, error)
}

// ---------------------------------------------------------------------------------- devprocess

// BaseUID is the first sandbox UID; slot i runs as BaseUID+i. Distinct executors on one host need distinct
// ranges (ASVAS_SANDBOX_BASE_UID) because nftables egress rules are keyed by UID.
var BaseUID = 61000

type DevProcess struct {
	exe    string
	asRoot bool
	egress *Egress
	maxOut int64
	info   Info
	issuer *Issuer
	mon    *ebpfmon.Monitor
}

func NewDevProcess(slots int) (*DevProcess, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if override := os.Getenv("ASVAS_SANDBOX_EXE"); override != "" { // used by tests (binary must be readable by sandbox UIDs)
		exe = override
	}
	iss, err := NewIssuer()
	if err != nil {
		return nil, err
	}
	d := &DevProcess{exe: exe, asRoot: os.Geteuid() == 0, maxOut: 2 << 20, issuer: iss}
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
	monState := "not running (executor is not root)"
	if d.asRoot && os.Getenv("ASVAS_SYSCALL_MONITOR") != "off" {
		if m, err := ebpfmon.New(ebpfmon.DefaultDeny); err == nil {
			d.mon = m
			monState = "ebpf: raw_syscalls tracepoint, in-kernel SIGKILL on denied syscalls (PO-12)"
		} else {
			monState = "unavailable: " + err.Error()
		}
	}
	d.info = Info{Backend: "devprocess", IsolationLevel: level, EgressMode: mode, SyscallMonitor: monState,
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
	ttl := time.Duration(max(1000, spec.TimeoutMS))*time.Millisecond + 5*time.Second
	cred, err := d.issuer.Issue(slot, ttl)
	if err != nil {
		return checks.Result{}, err
	}
	defer cred.Wipe()
	spec.Credential, _ = json.Marshal(cred)
	in, _ := json.Marshal(spec)
	res, err := d.runChild(ctx, slot, "sandbox-child", in)
	if err != nil {
		return res, err
	}
	if verr := VerifyResult(cred, res, time.Now()); verr != nil {
		return checks.Result{}, fmt.Errorf("sandbox result rejected (PO-16): %w", verr)
	}
	if res.Attestation == nil {
		res.Attestation = map[string]any{}
	}
	res.Attestation["credential_id"] = cred.ID
	res.Attestation["credential_expires_unix_ms"] = cred.ExpiresMS
	res.Attestation["credential_verified"] = true
	res.CredMAC = ""
	return res, nil
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
	var cgID uint64
	if d.mon != nil && (mode == "sandbox-child" || mode == "exec-probe") {
		fd, id, _, err := ebpfmon.SandboxCgroup(fmt.Sprintf("asvas-sandbox-%d", BaseUID), slot)
		if err != nil {
			return checks.Result{}, fmt.Errorf("syscall monitor cgroup: %w", err)
		}
		defer syscall.Close(fd)
		attr.UseCgroupFD, attr.CgroupFD, cgID = true, fd, id
	}
	cmd.SysProcAttr = attr
	if err := cmd.Start(); err != nil {
		return checks.Result{}, err
	}
	if cgID != 0 { // exec of the sandbox binary itself has completed; everything from here on is monitored
		if err := d.mon.Watch(cgID); err != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			return checks.Result{}, fmt.Errorf("syscall monitor watch: %w", err)
		}
		defer func() { _ = d.mon.Unwatch(cgID); d.mon.Forget(cgID) }()
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if cgID != 0 {
			if v, hit := d.mon.Violation(cgID); hit {
				return checks.Result{}, fmt.Errorf("sandbox killed by syscall monitor (PO-12): denied syscall %s", v.Name)
			}
		}
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

// SyscallSelfTest proves the syscall monitor kills a sandbox that tries a denied syscall (execve).
func (d *DevProcess) SyscallSelfTest(ctx context.Context) (bool, string) {
	if d.mon == nil {
		return false, "monitor not running"
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := d.runChild(ctx, 0, "exec-probe", []byte("{}"))
	if err != nil && strings.Contains(err.Error(), "denied syscall execve") {
		return true, err.Error()
	}
	return false, fmt.Sprintf("probe was not killed by the monitor (err=%v)", err)
}

func (d *DevProcess) SetSyscallMonitor(state string) { d.info.SyscallMonitor = state }

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
	if mode == "exec-probe" { // syscall-monitor self-test: must be killed at execve
		_ = syscall.Exec("/bin/true", []string{"true"}, nil)
		res.Error = "exec-probe: execve was NOT blocked"
	} else if mode == "egress-probe" {
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
	var cred Credential
	if len(spec.Credential) > 0 {
		if err := json.Unmarshal(spec.Credential, &cred); err == nil {
			if err := SignResult(&cred, &res); err != nil {
				fmt.Fprintln(os.Stderr, "credential:", err)
			}
			cred.Wipe()
		}
	}
	spec.Credential = nil
	_ = json.NewEncoder(os.Stdout).Encode(res)
	return 0
}
