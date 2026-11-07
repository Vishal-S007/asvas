//go:build linux

// Package ebpfmon is the syscall monitor for sandboxes (requirement PO-12; spec pp. 2, 6, 63).
//
// An eBPF program on the raw_syscalls:sys_enter tracepoint checks whether the calling task belongs to a watched
// sandbox cgroup and whether the syscall number is on the deny list. If both, it sends SIGKILL to the task from
// inside the kernel (bpf_send_signal) at syscall entry, so the syscall never runs, and records the cgroup and
// syscall number in a map that the executor reports. No userspace round trip is involved in the kill.
//
// The program is assembled in Go (cilium/ebpf asm) so no C toolchain is needed at build time.
// Requirements: Linux with CONFIG_BPF_SYSCALL, CONFIG_BPF_EVENTS, tracefs, cgroup v2, and CAP_BPF+CAP_PERFMON
// (or root). Without them New returns ErrUnavailable and the executor reports the monitor as absent.
package ebpfmon

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

var ErrUnavailable = errors.New("eBPF syscall monitor unavailable")

// DefaultDeny lists x86-64 syscalls a sandboxed check never needs after start-up: running other programs,
// debugging/injecting into processes, changing namespaces or mounts, loading kernel code or BPF, keyrings.
var DefaultDeny = map[string]uint32{
	"execve": 59, "execveat": 322, "ptrace": 101, "process_vm_readv": 310, "process_vm_writev": 311,
	"mount": 165, "umount2": 166, "pivot_root": 155, "chroot": 161, "unshare": 272, "setns": 308,
	"init_module": 175, "finit_module": 313, "delete_module": 176, "kexec_load": 246, "kexec_file_load": 320,
	"bpf": 321, "perf_event_open": 298, "keyctl": 250, "add_key": 248, "request_key": 249,
	"reboot": 169, "swapon": 167, "swapoff": 168, "iopl": 172, "ioperm": 173, "open_by_handle_at": 304,
	"userfaultfd": 323, "mount_setattr": 442, "fsopen": 430, "fsmount": 432, "move_mount": 429,
}

type Monitor struct {
	cgroups, denied, kills *ebpf.Map
	prog                   *ebpf.Program
	tp                     link.Link
}

// Violation is what the kernel recorded for a killed sandbox.
type Violation struct {
	CgroupID uint64
	Syscall  uint32
	Name     string
}

func New(deny map[string]uint32) (*Monitor, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("%w: needs root (CAP_BPF, CAP_PERFMON)", ErrUnavailable)
	}
	if _, err := os.Stat("/sys/kernel/tracing/events/raw_syscalls/sys_enter"); err != nil {
		if _, err2 := os.Stat("/sys/kernel/debug/tracing/events/raw_syscalls/sys_enter"); err2 != nil {
			return nil, fmt.Errorf("%w: tracefs raw_syscalls tracepoint not available", ErrUnavailable)
		}
	}
	m := &Monitor{}
	var err error
	if m.cgroups, err = ebpf.NewMap(&ebpf.MapSpec{Name: "asvas_cgroups", Type: ebpf.Hash, KeySize: 8, ValueSize: 1, MaxEntries: 1024}); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if m.denied, err = ebpf.NewMap(&ebpf.MapSpec{Name: "asvas_denied", Type: ebpf.Hash, KeySize: 4, ValueSize: 1, MaxEntries: 512}); err != nil {
		m.Close()
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if m.kills, err = ebpf.NewMap(&ebpf.MapSpec{Name: "asvas_kills", Type: ebpf.Hash, KeySize: 8, ValueSize: 4, MaxEntries: 1024}); err != nil {
		m.Close()
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	for _, nr := range deny {
		if err := m.denied.Put(nr, uint8(1)); err != nil {
			m.Close()
			return nil, err
		}
	}
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1), // ctx
		asm.FnGetCurrentCgroupId.Call(),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
		asm.LoadMapPtr(asm.R1, m.cgroups.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.LoadMem(asm.R7, asm.R6, 8, asm.DWord), // raw_syscalls:sys_enter "long id" at offset 8
		asm.StoreMem(asm.RFP, -12, asm.R7, asm.Word),
		asm.LoadMapPtr(asm.R1, m.denied.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -12),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.Mov.Imm(asm.R1, int32(syscall.SIGKILL)),
		asm.FnSendSignal.Call(),
		asm.LoadMapPtr(asm.R1, m.kills.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -12),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	}
	m.prog, err = ebpf.NewProgram(&ebpf.ProgramSpec{Name: "asvas_sysmon", Type: ebpf.TracePoint, License: "GPL",
		Instructions: insns})
	if err != nil {
		m.Close()
		return nil, fmt.Errorf("%w: program load: %v", ErrUnavailable, err)
	}
	if m.tp, err = link.Tracepoint("raw_syscalls", "sys_enter", m.prog, nil); err != nil {
		m.Close()
		return nil, fmt.Errorf("%w: attach: %v", ErrUnavailable, err)
	}
	return m, nil
}

func (m *Monitor) Watch(cgroupID uint64) error   { return m.cgroups.Put(cgroupID, uint8(1)) }
func (m *Monitor) Unwatch(cgroupID uint64) error { return m.cgroups.Delete(cgroupID) }

// Forget drops the recorded violation for a cgroup (call after reporting it).
func (m *Monitor) Forget(cgroupID uint64) { _ = m.kills.Delete(cgroupID) }

// Violation returns what was killed in the cgroup, if anything.
func (m *Monitor) Violation(cgroupID uint64) (Violation, bool) {
	var nr uint32
	if err := m.kills.Lookup(cgroupID, &nr); err != nil {
		return Violation{}, false
	}
	v := Violation{CgroupID: cgroupID, Syscall: nr, Name: fmt.Sprintf("nr %d", nr)}
	for n, x := range DefaultDeny {
		if x == nr {
			v.Name = n
		}
	}
	return v, true
}

func (m *Monitor) Close() {
	for _, c := range []interface{ Close() error }{m.tp, m.prog, m.kills, m.denied, m.cgroups} {
		if c != nil && !isNil(c) {
			_ = c.Close()
		}
	}
}

func isNil(c interface{ Close() error }) bool {
	switch v := c.(type) {
	case link.Link:
		return v == nil
	case *ebpf.Program:
		return v == nil
	case *ebpf.Map:
		return v == nil
	}
	return false
}
