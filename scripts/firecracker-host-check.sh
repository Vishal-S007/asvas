#!/usr/bin/env bash
# Checks whether this host can run the Firecracker backend (PO-10) and the eBPF monitor (PO-12).
# Exit 0 only if everything required is present. It changes nothing.
set -uo pipefail
FC="${ASVAS_FC_BIN:-/usr/local/bin/firecracker}"; JAILER="${ASVAS_FC_JAILER:-/usr/local/bin/jailer}"
KERNEL="${ASVAS_FC_KERNEL:-/var/lib/asvas/fc/vmlinux}"; ROOTFS="${ASVAS_FC_ROOTFS:-/var/lib/asvas/fc/rootfs.ext4}"
fail=0
ok()   { echo "  ok    $*"; }
bad()  { echo "  MISSING $*"; fail=1; }
echo "Firecracker backend:"
[ -c /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ] && ok "/dev/kvm accessible" || bad "/dev/kvm (bare metal or nested-virt-enabled VM required)"
grep -qE 'vmx|svm' /proc/cpuinfo && ok "CPU virtualization flags" || bad "CPU virtualization flags (vmx/svm)"
[ -x "$FC" ] && ok "firecracker $("$FC" --version 2>/dev/null | head -1)" || bad "$FC"
[ -x "$JAILER" ] && ok "jailer" || bad "$JAILER"
[ -f "$KERNEL" ] && ok "guest kernel $KERNEL" || bad "guest kernel $KERNEL"
[ -f "$ROOTFS" ] && ok "rootfs $ROOTFS" || bad "rootfs $ROOTFS (scripts/build-firecracker-rootfs.sh)"
[ "$(id -u)" = 0 ] && ok "running as root (jailer)" || bad "root (jailer needs it)"
command -v nft >/dev/null && ok "nftables" || bad "nft"
[ -d /sys/fs/cgroup ] && grep -q cgroup2 /proc/mounts && ok "cgroup v2" || bad "cgroup v2"
modprobe -n vhost_vsock >/dev/null 2>&1 || lsmod 2>/dev/null | grep -q vhost_vsock && ok "vhost_vsock" || echo "  warn  vhost_vsock module not confirmed (Firecracker vsock uses its own device; usually fine)"
echo "eBPF syscall monitor:"
[ -d /sys/kernel/tracing/events/raw_syscalls ] || [ -d /sys/kernel/debug/tracing/events/raw_syscalls ] \
  && ok "tracefs raw_syscalls" || bad "tracefs (mount -t tracefs nodev /sys/kernel/tracing)"
[ -e /sys/fs/bpf ] && ok "bpf fs" || echo "  warn  /sys/fs/bpf not mounted (not required)"
[ $fail = 0 ] && echo "READY" || echo "NOT READY"
exit $fail
