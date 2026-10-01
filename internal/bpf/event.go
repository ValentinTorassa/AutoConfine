package bpf

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
	"time"

	"github.com/ValentinTorassa/autoconfine/internal/models"
)

// eventSize is sizeof(struct syscall_event) in syscalls.bpf.c.
const eventSize = 48

// Target is the cgroup v2 subtree to record: its ID (the inode of its
// directory under /sys/fs/cgroup) and its depth below the root.
type Target struct {
	CgroupID uint64
	Level    uint32
	Path     string
}

// cgroupLevel is the depth of a cgroup v2 path: "/" is 0, "/a/b" is 2.
// bpf_get_current_ancestor_cgroup_id(level) returns the ancestor at that depth.
func cgroupLevel(path string) uint32 {
	path = strings.Trim(path, "/")
	if path == "" {
		return 0
	}
	return uint32(strings.Count(path, "/") + 1)
}

// isContainerCgroup accepts only paths created for a container, so a stray
// host PID cannot make the probe record a host service or a login session.
func isContainerCgroup(path string) bool {
	for _, marker := range []string{"docker-", "/docker/", "libpod-", "kubepods", "crio-", "containerd"} {
		if strings.Contains(path, marker) {
			return true
		}
	}
	return false
}

// decodeEvent turns one ring buffer record into an event. bootWall is the wall
// clock time at CLOCK_MONOTONIC zero, so the kernel timestamp becomes a real
// time instead of the moment user space happened to read the record.
func decodeEvent(raw []byte, image string, bootWall time.Time) (models.SyscallEvent, bool) {
	if len(raw) < eventSize {
		return models.SyscallEvent{}, false
	}
	number := binary.LittleEndian.Uint32(raw[24:28])
	name, known := syscallNamesAMD64[number]
	if !known {
		name = "syscall_" + strconv.FormatUint(uint64(number), 10)
	}
	comm := raw[32:48]
	if i := bytes.IndexByte(comm, 0); i >= 0 {
		comm = comm[:i]
	}
	return models.SyscallEvent{
		Timestamp: bootWall.Add(time.Duration(binary.LittleEndian.Uint64(raw[0:8]))).UTC(),
		Image:     image,
		PID:       int(binary.LittleEndian.Uint32(raw[16:20])),
		TID:       int(binary.LittleEndian.Uint32(raw[20:24])),
		Comm:      string(comm),
		Syscall:   name,
		Number:    int(number),
		Errno:     int(binary.LittleEndian.Uint32(raw[28:32])), // sys_exit only
		Phase:     "observed-ebpf",
	}, true
}
