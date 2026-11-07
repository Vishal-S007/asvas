package sandbox

// Firecracker backend (requirement PO-10; spec pp. 2, 6, 30-31, 63-64, 75).
//
// One microVM per job, started through the Firecracker jailer (chroot, dedicated uid/gid, new PID and network
// namespace, cgroups), with:
//   - a read-only root filesystem containing only the static guest agent (scripts/build-firecracker-rootfs.sh);
//   - no network unless the job has endpoints: a per-slot tap device in a per-slot netns whose nftables forward
//     chain allows exactly the job's validated ip:port pairs (scripts/firecracker-host-setup.sh);
//   - a virtio-vsock job channel (vsockproto.go) carrying the Spec and the per-run credential (PO-16);
//   - snapshot restore when ASVAS_FC_SNAPSHOT_DIR holds a prepared snapshot (fast start), else a cold boot;
//   - the whole jailer process group killed and the chroot removed after the job, success or not.
//
// STATUS: implemented and unit-tested against a simulated Firecracker API server and guest agent. It has NOT
// been run on a KVM host. Do not claim microVM isolation until scripts/firecracker-host-check.sh passes and the
// integration run in docs/firecracker-runbook.md has been completed on real hardware.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/asvas/execution-plane/internal/checks"
)

type FirecrackerConfig struct {
	FirecrackerBin, JailerBin string
	KernelImage, RootFS       string // RootFS is attached read-only
	SnapshotDir               string // optional: vmstate + mem prepared by the runbook
	ChrootBase                string // jailer --chroot-base-dir
	BaseUID                   int    // slot i runs as BaseUID+i inside the jail
	VCPUs, MemMiB             int
	BootTimeout               time.Duration
	NetnsPrefix               string // per-slot netns created by firecracker-host-setup.sh ("" = no network)
}

func FirecrackerConfigFromEnv() FirecrackerConfig {
	atoi := func(k string, d int) int {
		if v, err := strconv.Atoi(os.Getenv(k)); err == nil {
			return v
		}
		return d
	}
	get := func(k, d string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return d
	}
	return FirecrackerConfig{
		FirecrackerBin: get("ASVAS_FC_BIN", "/usr/local/bin/firecracker"),
		JailerBin:      get("ASVAS_FC_JAILER", "/usr/local/bin/jailer"),
		KernelImage:    get("ASVAS_FC_KERNEL", "/var/lib/asvas/fc/vmlinux"),
		RootFS:         get("ASVAS_FC_ROOTFS", "/var/lib/asvas/fc/rootfs.ext4"),
		SnapshotDir:    os.Getenv("ASVAS_FC_SNAPSHOT_DIR"),
		ChrootBase:     get("ASVAS_FC_CHROOT_BASE", "/srv/asvas-jailer"),
		BaseUID:        atoi("ASVAS_FC_BASE_UID", 64000),
		VCPUs:          atoi("ASVAS_FC_VCPUS", 1),
		MemMiB:         atoi("ASVAS_FC_MEM_MIB", 256),
		BootTimeout:    time.Duration(atoi("ASVAS_FC_BOOT_TIMEOUT_MS", 3000)) * time.Millisecond,
		NetnsPrefix:    get("ASVAS_FC_NETNS_PREFIX", "asvas-fc"),
	}
}

type Firecracker struct {
	cfg    FirecrackerConfig
	issuer *Issuer
	info   Info
	egress *TapEgress
	// hooks for tests (a simulated Firecracker); nil in production
	startVM func(ctx context.Context, slot int, jailDir string, args []string) (*exec.Cmd, error)
}

// HostCheck lists what is missing for the Firecracker backend on this host (empty = ready).
func (c FirecrackerConfig) HostCheck() []string {
	var missing []string
	if f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0); err != nil {
		missing = append(missing, "/dev/kvm not usable: "+err.Error())
	} else {
		f.Close()
	}
	for _, p := range []string{c.FirecrackerBin, c.JailerBin, c.KernelImage, c.RootFS} {
		if _, err := os.Stat(p); err != nil {
			missing = append(missing, p+" missing")
		}
	}
	if os.Geteuid() != 0 {
		missing = append(missing, "executor must run as root to use the jailer")
	}
	return missing
}

func NewFirecracker(cfg FirecrackerConfig) (*Firecracker, error) {
	if m := cfg.HostCheck(); len(m) > 0 {
		return nil, fmt.Errorf("%w: %v", ErrBackendUnavailable, m)
	}
	iss, err := NewIssuer()
	if err != nil {
		return nil, err
	}
	f := newFirecracker(cfg, iss)
	if cfg.NetnsPrefix != "" {
		if f.egress, err = NewTapEgress(slotsFromEnv()); err != nil {
			return nil, fmt.Errorf("%w: tap egress rules: %v", ErrBackendUnavailable, err)
		}
	}
	return f, nil
}

func slotsFromEnv() int {
	if n, err := strconv.Atoi(os.Getenv("ASVAS_SLOTS")); err == nil && n > 0 {
		return n
	}
	return 4
}

func newFirecracker(cfg FirecrackerConfig, iss *Issuer) *Firecracker {
	return &Firecracker{cfg: cfg, issuer: iss, info: Info{Backend: "firecracker",
		IsolationLevel: "firecracker microVM per job (jailer: chroot, own uid, PID/net namespaces; read-only rootfs)",
		EgressMode:     "per-slot tap + nftables allow-set (host setup script)", SyscallMonitor: "guest kernel boundary",
		Note: "Firecracker backend: verify with scripts/firecracker-host-check.sh before relying on it."}}
}

func (f *Firecracker) Info() Info { return f.info }

func (f *Firecracker) vmID(slot int) string {
	return fmt.Sprintf("asvas-%d-%d", slot, time.Now().UnixNano())
}

// JailerArgs builds the jailer command line for one VM.
func (f *Firecracker) JailerArgs(id string, slot int) []string {
	uid := strconv.Itoa(f.cfg.BaseUID + slot)
	args := []string{"--id", id, "--exec-file", f.cfg.FirecrackerBin, "--uid", uid, "--gid", uid,
		"--chroot-base-dir", f.cfg.ChrootBase, "--new-pid-ns", "--cgroup-version", "2",
		"--cgroup", "cpu.max=100000 100000", "--cgroup", fmt.Sprintf("memory.max=%d", (f.cfg.MemMiB+64)<<20)}
	if f.cfg.NetnsPrefix != "" {
		args = append(args, "--netns", fmt.Sprintf("/var/run/netns/%s-%d", f.cfg.NetnsPrefix, slot))
	}
	return append(args, "--", "--api-sock", "/run/firecracker.socket", "--level", "Warning")
}

type apiCall struct {
	Method, Path string
	Body         any
}

// BootCalls is the Firecracker API sequence for a cold boot (or a snapshot restore when snapshot is true).
func (f *Firecracker) BootCalls(slot int, snapshot bool) []apiCall {
	vsock := map[string]any{"vsock_id": "jobs", "guest_cid": 3, "uds_path": "/run/vsock.sock"}
	if snapshot {
		return []apiCall{{"PUT", "/snapshot/load", map[string]any{
			"snapshot_path": "/snapshot/vmstate", "mem_backend": map[string]any{"backend_type": "File", "backend_path": "/snapshot/mem"},
			"resume_vm": true}}}
	}
	calls := []apiCall{
		{"PUT", "/machine-config", map[string]any{"vcpu_count": f.cfg.VCPUs, "mem_size_mib": f.cfg.MemMiB, "smt": false}},
		{"PUT", "/boot-source", map[string]any{"kernel_image_path": "/vmlinux",
			"boot_args": fmt.Sprintf("console=ttyS0 reboot=k panic=1 pci=off ro init=/sbin/asvas-guest-agent "+
				"ip=172.31.%d.2::172.31.%d.1:255.255.255.252::eth0:off", slot, slot)}},
		{"PUT", "/drives/rootfs", map[string]any{"drive_id": "rootfs", "path_on_host": "/rootfs.ext4",
			"is_root_device": true, "is_read_only": true}},
		{"PUT", "/vsock", vsock},
	}
	if f.cfg.NetnsPrefix != "" {
		calls = append(calls, apiCall{"PUT", "/network-interfaces/eth0", map[string]any{"iface_id": "eth0",
			"host_dev_name": TapName(slot)}})
	}
	return append(calls, apiCall{"PUT", "/actions", map[string]any{"action_type": "InstanceStart"}})
}

func apiClient(sock string) *http.Client {
	return &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		}}}
}

func doCalls(ctx context.Context, sock string, calls []apiCall) error {
	c := apiClient(sock)
	for _, call := range calls {
		b, _ := json.Marshal(call.Body)
		req, _ := http.NewRequestWithContext(ctx, call.Method, "http://localhost"+call.Path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			return fmt.Errorf("firecracker API %s %s: %w", call.Method, call.Path, err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			return fmt.Errorf("firecracker API %s %s: HTTP %d %s", call.Method, call.Path, resp.StatusCode, body)
		}
	}
	return nil
}

func waitFile(ctx context.Context, p string) error {
	for {
		if _, err := os.Stat(p); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s did not appear: %w", p, ctx.Err())
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func (f *Firecracker) Run(ctx context.Context, slot int, spec checks.Spec) (checks.Result, error) {
	ttl := time.Duration(max(1000, spec.TimeoutMS))*time.Millisecond + f.cfg.BootTimeout + 5*time.Second
	cred, err := f.issuer.Issue(slot, ttl)
	if err != nil {
		return checks.Result{}, err
	}
	defer cred.Wipe()
	spec.Credential, _ = json.Marshal(cred)

	if f.egress != nil {
		if err := f.egress.Allow(slot, spec.Allow); err != nil {
			return checks.Result{}, fmt.Errorf("egress programming failed: %w", err)
		}
		defer f.egress.Clear(slot)
	}
	id := f.vmID(slot)
	jail := filepath.Join(f.cfg.ChrootBase, filepath.Base(f.cfg.FirecrackerBin), id, "root")
	defer os.RemoveAll(filepath.Dir(jail))
	if err := f.stage(jail); err != nil {
		return checks.Result{}, fmt.Errorf("staging VM files: %w", err)
	}
	start := f.startVM
	if start == nil {
		start = f.startJailer
	}
	cmd, err := start(ctx, slot, jail, f.JailerArgs(id, slot))
	if err != nil {
		return checks.Result{}, fmt.Errorf("starting jailer: %w", err)
	}
	defer func() { // the VM never outlives the job
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_, _ = cmd.Process.Wait()
	}()
	bctx, cancel := context.WithTimeout(ctx, f.cfg.BootTimeout)
	defer cancel()
	t0 := time.Now()
	sock := filepath.Join(jail, "run", "firecracker.socket")
	if err := waitFile(bctx, sock); err != nil {
		return checks.Result{}, err
	}
	snap := f.cfg.SnapshotDir != ""
	if err := doCalls(bctx, sock, f.BootCalls(slot, snap)); err != nil {
		return checks.Result{}, err
	}
	conn, err := dialGuest(bctx, filepath.Join(jail, "run", "vsock.sock"))
	if err != nil {
		return checks.Result{}, err
	}
	defer conn.Close()
	ready := time.Since(t0)
	res, err := exchange(ctx, conn, spec)
	if err != nil {
		return checks.Result{}, err
	}
	if verr := VerifyResult(cred, res, time.Now()); verr != nil {
		return checks.Result{}, fmt.Errorf("guest result rejected (PO-16): %w", verr)
	}
	if res.Attestation == nil {
		res.Attestation = map[string]any{}
	}
	res.Attestation["backend"] = "firecracker"
	res.Attestation["vm_id"] = id
	res.Attestation["vm_ready_ms"] = ready.Milliseconds()
	res.Attestation["snapshot_restore"] = snap
	res.Attestation["rootfs_read_only"] = true
	res.Attestation["credential_id"] = cred.ID
	res.Attestation["credential_verified"] = true
	res.CredMAC = ""
	return res, nil
}

// stage hard-links (or copies) kernel, read-only rootfs and optional snapshot into the jail.
func (f *Firecracker) stage(jail string) error {
	if err := os.MkdirAll(filepath.Join(jail, "run"), 0o755); err != nil {
		return err
	}
	files := map[string]string{f.cfg.KernelImage: "vmlinux", f.cfg.RootFS: "rootfs.ext4"}
	if f.cfg.SnapshotDir != "" {
		_ = os.MkdirAll(filepath.Join(jail, "snapshot"), 0o755)
		files[filepath.Join(f.cfg.SnapshotDir, "vmstate")] = "snapshot/vmstate"
		files[filepath.Join(f.cfg.SnapshotDir, "mem")] = "snapshot/mem"
	}
	for src, dst := range files {
		d := filepath.Join(jail, dst)
		if err := os.Link(src, d); err != nil {
			if err := copyFile(src, d); err != nil {
				return err
			}
		}
		_ = os.Chmod(d, 0o444) // read-only inside the jail
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func (f *Firecracker) startJailer(_ context.Context, _ int, _ string, args []string) (*exec.Cmd, error) {
	cmd := exec.Command(f.cfg.JailerBin, args...)
	cmd.Env = []string{}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	return cmd, cmd.Start()
}
