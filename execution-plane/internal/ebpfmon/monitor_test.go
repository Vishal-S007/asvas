//go:build linux

package ebpfmon

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// Child modes (the test binary re-executes itself): wait for one byte on stdin, then do the action.
func TestMain(m *testing.M) {
	switch os.Getenv("EBPFMON_CHILD") {
	case "exec":
		_, _ = os.Stdin.Read(make([]byte, 1))
		_ = syscall.Exec("/bin/true", []string{"true"}, nil)
		os.Exit(3) // only reached if exec failed without killing us
	case "benign":
		_, _ = os.Stdin.Read(make([]byte, 1))
		_, _ = os.Stdout.WriteString("ok")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func monitor(t *testing.T) *Monitor {
	t.Helper()
	m, err := New(DefaultDeny)
	if errors.Is(err, ErrUnavailable) {
		t.Skipf("eBPF monitor not available here: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	return m
}

// run starts the child in the slot cgroup, optionally watches it, releases it and returns its wait status and
// the time from release to exit.
func run(t *testing.T, m *Monitor, mode string, slot int, watch bool) (syscall.WaitStatus, time.Duration, uint64) {
	t.Helper()
	fd, id, path, err := SandboxCgroup("asvas-ebpfmon-test", slot)
	if err != nil {
		t.Skipf("cgroup v2 not usable: %v", err)
	}
	defer syscall.Close(fd)
	defer os.Remove(path)
	exe, _ := os.Executable()
	cmd := exec.Command(exe)
	cmd.Env = []string{"EBPFMON_CHILD=" + mode}
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
	stdin, _ := cmd.StdinPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if watch {
		if err := m.Watch(id); err != nil {
			t.Fatal(err)
		}
		defer m.Unwatch(id)
	}
	t0 := time.Now()
	_, _ = stdin.Write([]byte{1})
	_ = cmd.Wait()
	return cmd.ProcessState.Sys().(syscall.WaitStatus), time.Since(t0), id
}

func TestDeniedSyscallKilledInKernel(t *testing.T) {
	m := monitor(t)
	ws, took, id := run(t, m, "exec", 1, true)
	if !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("expected SIGKILL, got %v", ws)
	}
	v, ok := m.Violation(id)
	if !ok || v.Name != "execve" {
		t.Fatalf("violation not recorded: %+v %v", v, ok)
	}
	t.Logf("execve in watched sandbox cgroup: SIGKILL, release-to-exit %v (includes Go scheduling of the child)", took)
	if took > 50*time.Millisecond {
		t.Errorf("kill took %v (> 50 ms target)", took)
	}
}

func TestUnwatchedAndBenignProcessesUnaffected(t *testing.T) {
	m := monitor(t)
	if ws, _, _ := run(t, m, "exec", 2, false); ws.ExitStatus() != 0 {
		t.Fatalf("unwatched exec should succeed (/bin/true), got %v", ws)
	}
	if ws, _, id := run(t, m, "benign", 3, true); ws.ExitStatus() != 0 || ws.Signaled() {
		t.Fatalf("benign watched process was disturbed: %v", ws)
	} else if _, ok := m.Violation(id); ok {
		t.Fatal("violation recorded for benign process")
	}
}
