//go:build linux

// asvas-guest-agent is PID 1 inside the Firecracker microVM (PO-10). It mounts nothing writable, listens on
// virtio-vsock port 5000, runs exactly one job per connection with the per-run credential (PO-16) and returns
// the signed result. The VM is destroyed by the host after each job.
package main

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/asvas/execution-plane/internal/sandbox"
	"golang.org/x/sys/unix"
)

func main() {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		fatal("vsock socket: %v", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: sandbox.GuestAgentPort}); err != nil {
		fatal("vsock bind: %v", err)
	}
	if err := unix.Listen(fd, 4); err != nil {
		fatal("vsock listen: %v", err)
	}
	ln, err := net.FileListener(os.NewFile(uintptr(fd), "vsock"))
	if err != nil {
		fatal("listener: %v", err)
	}
	att := map[string]any{"guest_agent": "asvas-guest-agent", "pid": os.Getpid(), "uid": os.Getuid()}
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		_ = sandbox.ServeGuestConn(context.Background(), c, att)
	}
}

func fatal(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "asvas-guest-agent: "+f+"\n", a...)
	_ = unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
	os.Exit(1)
}
