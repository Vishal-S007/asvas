# Firecracker backend runbook (PO-10) and syscall monitor (PO-12)

Status as of 2026-11-08:

| Part | State |
|---|---|
| eBPF syscall monitor (PO-12) | **Running and tested** on the development host (kernel 6.18): denied syscall (execve) in a watched sandbox cgroup is killed in-kernel; release-to-exit measured 0.9–1.7 ms in tests; executor self-test at startup. |
| Firecracker backend code (PO-10) | Implemented (`execution-plane/internal/sandbox/firecracker.go`, guest agent `cmd/asvas-guest-agent`, tap egress rules). Tested against a **simulated** Firecracker API + guest only. |
| Firecracker on real hardware | **Not run.** The development host has no `/dev/kvm`. Until the steps below pass on a KVM host, ASVAS must not be described as providing microVM isolation. |

## 1. Host requirements

Run `sudo scripts/firecracker-host-check.sh`. It must print `READY`. You need:

* bare-metal Linux (or a VM with nested virtualization enabled) exposing `/dev/kvm`; x86-64;
* Firecracker and jailer binaries (release v1.x from github.com/firecracker-microvm/firecracker) at
  `/usr/local/bin/{firecracker,jailer}` (or set `ASVAS_FC_BIN`, `ASVAS_FC_JAILER`);
* a guest kernel `vmlinux` built with `CONFIG_VIRTIO_VSOCKETS`, `CONFIG_VIRTIO_NET`, `CONFIG_IP_PNP` (kernel `ip=`
  argument) and `CONFIG_EXT4_FS` (Firecracker's CI guest kernel config is a good starting point);
* root (jailer), nftables, cgroup v2, tracefs mounted at `/sys/kernel/tracing` for the syscall monitor.

No paid infrastructure is provisioned by this project. Choose and pay for a host yourself.

## 2. Build artefacts

```bash
scripts/build-firecracker-rootfs.sh /var/lib/asvas/fc/rootfs.ext4    # static agent as init + CA bundle, 64 MiB ext4
cp <your vmlinux> /var/lib/asvas/fc/vmlinux
sudo scripts/firecracker-host-setup.sh 4 <uplink-iface>             # netns asvas-fc-N + tap asvastapN per slot
```

## 3. Integration run (must be done before claiming PO-10)

```bash
sudo ASVAS_EXECUTION_BACKEND=firecracker ASVAS_SLOTS=4 execution-plane/bin/asvas-executor
# then, from the repo: run the demo against the local test target
ASVAS_API_URL=https://localhost:8000 ASVAS_CA_FILE=var/certs/ca.crt python3 scripts/demo.py
```

Pass criteria — record the actual numbers in docs/progress.md:

1. Demo completes with the same 6 findings as the dev backend.
2. Every `tool.result` audit event shows `sandbox_attestation.backend = firecracker`, `rootfs_read_only = true`,
   `credential_verified = true`, and a distinct `vm_id`.
3. `ps`/`ls /srv/asvas-jailer/firecracker` show no VM process or jail left after each job.
4. With an endpoint missing from the allow-set, the guest cannot connect (nft counter on `asvastapN ... drop` rises).
5. Boot/restore time (`vm_ready_ms`) recorded for cold boot and, after creating a snapshot (below), for restore.
   The spec's < 850 ms target is a goal to measure, not a claim.

## 4. Snapshots (optional, faster start)

Boot one VM with the same config, wait until the guest agent listens, then
`PUT /vm {"state":"Paused"}` and `PUT /snapshot/create {"snapshot_type":"Full","snapshot_path":"/snapshot/vmstate","mem_file_path":"/snapshot/mem"}`
via the API socket; copy both files to a directory and set `ASVAS_FC_SNAPSHOT_DIR`. All VMs restored from one
snapshot share guest memory contents at restore time (e.g. RNG state); the per-job credential is delivered after
restore over vsock, so it is not part of the snapshot.

## 5. Known limitations

* IPv4 only for VM egress.
* Guest network config relies on the kernel `ip=` argument.
* The jailer's cgroup limits (`cpu.max`, `memory.max`) are fixed per VM; tune via `ASVAS_FC_MEM_MIB`.
