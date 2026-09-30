package bpf

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestDecodeEventUsesKernelTimestampAndComm(t *testing.T) {
	raw := make([]byte, eventSize)
	binary.LittleEndian.PutUint64(raw[0:8], uint64(5*time.Second))
	binary.LittleEndian.PutUint64(raw[8:16], 777)
	binary.LittleEndian.PutUint32(raw[16:20], 4242)
	binary.LittleEndian.PutUint32(raw[20:24], 4243)
	binary.LittleEndian.PutUint32(raw[24:28], 257) // openat
	copy(raw[32:48], "nginx\x00garbage")
	boot := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

	event, ok := decodeEvent(raw, "nginx:latest", boot)
	if !ok {
		t.Fatal("decode failed")
	}
	if !event.Timestamp.Equal(boot.Add(5 * time.Second)) {
		t.Fatalf("timestamp %v", event.Timestamp)
	}
	if event.Syscall != "openat" || event.Number != 257 || event.PID != 4242 || event.TID != 4243 {
		t.Fatalf("event %+v", event)
	}
	if event.Comm != "nginx" || event.Phase != "observed-ebpf" || event.Image != "nginx:latest" {
		t.Fatalf("event %+v", event)
	}
	if _, ok := decodeEvent(raw[:32], "x", boot); ok {
		t.Fatal("a 32-byte record from the old object must not decode")
	}
}

func TestUnknownSyscallNumberKeepsItsNumber(t *testing.T) {
	raw := make([]byte, eventSize)
	binary.LittleEndian.PutUint32(raw[24:28], 9999)
	event, _ := decodeEvent(raw, "x", time.Unix(0, 0))
	if event.Syscall != "syscall_9999" {
		t.Fatalf("got %q", event.Syscall)
	}
}

func TestCgroupLevelAndContainerMarkers(t *testing.T) {
	cases := map[string]uint32{"/": 0, "/machine.slice/libpod-abc.scope": 2, "/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-abc.scope/container": 6}
	for path, want := range cases {
		if got := cgroupLevel(path); got != want {
			t.Errorf("cgroupLevel(%q) = %d, want %d", path, got, want)
		}
	}
	for _, path := range []string{"/machine.slice/libpod-abc.scope", "/system.slice/docker-abc.scope", "/kubepods/burstable/pod1/abc"} {
		if !isContainerCgroup(path) {
			t.Errorf("%s should be a container cgroup", path)
		}
	}
	for _, path := range []string{"/user.slice/user-1000.slice/session-2.scope", "/system.slice/sshd.service"} {
		if isContainerCgroup(path) {
			t.Errorf("%s must be refused", path)
		}
	}
}
