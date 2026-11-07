//go:build linux

package ebpfmon

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// CgroupRoot finds the cgroup v2 mount (unified or hybrid "unified" mount).
func CgroupRoot() (string, error) {
	for _, p := range []string{"/sys/fs/cgroup/unified", "/sys/fs/cgroup"} {
		var st syscall.Statfs_t
		if syscall.Statfs(p, &st) == nil && st.Type == 0x63677270 { // CGROUP2_SUPER_MAGIC
			return p, nil
		}
	}
	return "", fmt.Errorf("%w: no cgroup v2 mount", ErrUnavailable)
}

// SandboxCgroup creates (if needed) a per-slot cgroup and returns an open directory fd for clone-into-cgroup
// plus the cgroup id that bpf_get_current_cgroup_id reports (the directory's inode number).
func SandboxCgroup(name string, slot int) (dirFD int, id uint64, path string, err error) {
	root, err := CgroupRoot()
	if err != nil {
		return -1, 0, "", err
	}
	path = filepath.Join(root, name, fmt.Sprintf("slot-%d", slot))
	if err := os.MkdirAll(path, 0o755); err != nil {
		return -1, 0, "", err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, 0, "", err
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		syscall.Close(fd)
		return -1, 0, "", err
	}
	return fd, st.Ino, path, nil
}
