//go:build linux

package bpf

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ValentinTorassa/autoconfine/internal/models"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed syscalls_bpfel.o
var syscallObject []byte

type EBPFProbe struct {
	PID    int
	mu     sync.Mutex
	reader *ringbuf.Reader
	stop   bool
}

func NewEBPFProbe(pid int) *EBPFProbe { return &EBPFProbe{PID: pid} }

// cgroupID selects exactly the host cgroup of a running disposable container.
func cgroupID(pid int) (uint64, error) {
	if pid <= 0 {
		return 0, errors.New("a running container host PID is required")
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "0::") {
			continue
		}
		path := strings.TrimPrefix(line, "0::")
		if path == "/" {
			return 0, errors.New("refusing to trace the host root cgroup")
		}
		if !strings.Contains(path, "docker-") && !strings.Contains(path, "/docker/") &&
			!strings.Contains(path, "libpod-") && !strings.Contains(path, "kubepods") {
			return 0, errors.New("target PID is not in a recognized container cgroup")
		}
		stat := &syscall.Stat_t{}
		if err := syscall.Stat(filepath.Join("/sys/fs/cgroup", path), stat); err != nil {
			return 0, err
		}
		return stat.Ino, nil
	}
	return 0, errors.New("target process is not in cgroup v2")
}

func (e *EBPFProbe) Attach(image string, events chan<- models.SyscallEvent) error {
	defer close(events)
	if runtime.GOARCH != "amd64" {
		return fmt.Errorf("eBPF syscall names unsupported on %s", runtime.GOARCH)
	}
	group, err := cgroupID(e.PID)
	if err != nil {
		return fmt.Errorf("target cgroup: %w", err)
	}
	// Modern kernels account BPF maps to cgroups. A rootless container may be
	// unable to raise RLIMIT_MEMLOCK even when the loader can still proceed.
	_ = rlimit.RemoveMemlock()
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(syscallObject))
	if err != nil {
		return fmt.Errorf("load eBPF object: %w", err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load eBPF collection: %w", err)
	}
	defer collection.Close()
	key := uint32(0)
	if err := collection.Maps["target_cgroup"].Put(key, group); err != nil {
		return err
	}
	attached, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sys_enter", Program: collection.Programs["trace_sys_enter"]})
	if err != nil {
		return fmt.Errorf("attach raw tracepoint: %w", err)
	}
	defer attached.Close()
	reader, err := ringbuf.NewReader(collection.Maps["events"])
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.reader = reader
	if e.stop {
		reader.Close()
	}
	e.mu.Unlock()
	defer reader.Close()
	for {
		record, err := reader.Read()
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil
		}
		if err != nil {
			return err
		}
		if len(record.RawSample) < 32 {
			continue
		}
		number := binary.LittleEndian.Uint32(record.RawSample[24:28])
		name, known := syscallNamesAMD64[number]
		if !known {
			name = "syscall_" + strconv.FormatUint(uint64(number), 10)
		}
		event := models.SyscallEvent{
			Timestamp: time.Now().UTC(), Image: image,
			PID:     int(binary.LittleEndian.Uint32(record.RawSample[16:20])),
			TID:     int(binary.LittleEndian.Uint32(record.RawSample[20:24])),
			Syscall: name, Number: int(number), Phase: "observed-ebpf",
		}
		select {
		case events <- event:
		default:
			return errors.New("trace consumer cannot keep up; refusing incomplete trace")
		}
	}
}

func (e *EBPFProbe) Detach() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stop = true
	if e.reader != nil {
		e.reader.Close()
	}
}
