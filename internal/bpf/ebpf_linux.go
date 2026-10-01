//go:build linux

package bpf

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ValentinTorassa/autoconfine/internal/models"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:embed syscalls_bpfel.o
var syscallObject []byte

// EBPFProbe records the syscalls of one container cgroup subtree.
type EBPFProbe struct {
	PID   int
	Hook  Hook // SysEnter unless set
	mu    sync.Mutex
	ready chan error
	once  sync.Once

	reader *ringbuf.Reader
	stop   bool
}

func NewEBPFProbe(pid int) *EBPFProbe { return &EBPFProbe{PID: pid, ready: make(chan error, 1)} }

// programs maps each hook to its program in syscalls.bpf.c and the raw
// tracepoint it attaches to.
var programs = map[Hook]struct{ name, tracepoint string }{
	SysEnter: {"trace_sys_enter", "sys_enter"},
	SysExit:  {"trace_sys_exit", "sys_exit"},
}

// Ready delivers nil once the program is attached (or the error that stopped
// it), so a caller starts the container only after capture is live.
func (e *EBPFProbe) Ready() <-chan error { return e.ready }

func (e *EBPFProbe) signal(err error) { e.once.Do(func() { e.ready <- err }) }

// cgroupTarget resolves the cgroup v2 of a container process to its ID and depth.
func cgroupTarget(pid int) (Target, error) {
	if pid <= 0 {
		return Target{}, errors.New("a container host PID is required")
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return Target{}, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "0::") {
			continue
		}
		path := strings.TrimPrefix(line, "0::")
		if path == "/" {
			return Target{}, errors.New("refusing to trace the host root cgroup")
		}
		if !isContainerCgroup(path) {
			return Target{}, errors.New("target PID is not in a recognized container cgroup")
		}
		stat := &syscall.Stat_t{}
		if err := syscall.Stat(filepath.Join("/sys/fs/cgroup", path), stat); err != nil {
			return Target{}, err
		}
		return Target{CgroupID: stat.Ino, Level: cgroupLevel(path), Path: path}, nil
	}
	return Target{}, errors.New("target process is not in cgroup v2")
}

// bootWallClock is the wall time at which CLOCK_MONOTONIC read zero.
func bootWallClock() (time.Time, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return time.Time{}, err
	}
	return time.Now().Add(-time.Duration(ts.Nano())), nil
}

func (e *EBPFProbe) Attach(image string, events chan<- models.SyscallEvent) (err error) {
	defer close(events)
	defer func() { e.signal(err) }() // a failure before attaching reaches the waiter
	if runtime.GOARCH != "amd64" {
		return fmt.Errorf("eBPF syscall names unsupported on %s", runtime.GOARCH)
	}
	program, ok := programs[e.Hook]
	if !ok {
		return fmt.Errorf("unknown hook %d", e.Hook)
	}
	target, err := cgroupTarget(e.PID)
	if err != nil {
		return fmt.Errorf("target cgroup: %w", err)
	}
	bootWall, err := bootWallClock()
	if err != nil {
		return fmt.Errorf("monotonic clock: %w", err)
	}
	// Modern kernels account BPF maps to cgroups. A rootless container may be
	// unable to raise RLIMIT_MEMLOCK even when the loader can still proceed.
	_ = rlimit.RemoveMemlock()
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(syscallObject))
	if err != nil {
		return fmt.Errorf("load eBPF object: %w", err)
	}
	// Load only the program in use, so the other one never has to pass the
	// verifier for this capture to work.
	for name := range spec.Programs {
		if name != program.name {
			delete(spec.Programs, name)
		}
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load eBPF collection: %w", err)
	}
	defer collection.Close()
	key := uint32(0)
	value := struct {
		CgroupID uint64
		Level    uint32
		Pad      uint32
	}{target.CgroupID, target.Level, 0}
	if err := collection.Maps["target_cgroup"].Put(key, value); err != nil {
		return err
	}
	reader, err := ringbuf.NewReader(collection.Maps["events"])
	if err != nil {
		return err
	}
	defer reader.Close()
	attached, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: program.tracepoint, Program: collection.Programs[program.name]})
	if err != nil {
		return fmt.Errorf("attach raw tracepoint: %w", err)
	}
	defer attached.Close()
	e.mu.Lock()
	e.reader = reader
	stopped := e.stop
	e.mu.Unlock()
	e.signal(nil)
	if stopped {
		_ = reader.Flush()
	}

	for {
		record, err := reader.Read()
		if errors.Is(err, ringbuf.ErrFlushed) || errors.Is(err, ringbuf.ErrClosed) {
			break
		}
		if err != nil {
			return err
		}
		event, ok := decodeEvent(record.RawSample, image, bootWall)
		if !ok {
			return fmt.Errorf("short ring buffer record (%d bytes); object and decoder disagree", len(record.RawSample))
		}
		select {
		case events <- event:
		default:
			return errors.New("trace consumer cannot keep up; refusing incomplete trace")
		}
	}
	// The kernel side drops silently when the ring buffer is full (or, at
	// sys_exit, when it cannot read the syscall number); the per-CPU counter
	// is the only record of it, and any drop makes the trace partial.
	var perCPU []uint64
	if err := collection.Maps["drops"].Lookup(key, &perCPU); err != nil {
		return fmt.Errorf("read drop counter: %w", err)
	}
	var dropped uint64
	for _, n := range perCPU {
		dropped += n
	}
	if dropped > 0 {
		return fmt.Errorf("the kernel dropped %d events (ring buffer full or unreadable syscall number); refusing incomplete trace", dropped)
	}
	return nil
}

// Detach ends the capture. It flushes the reader instead of closing it, so the
// records already in the ring buffer still reach the consumer before Attach
// returns: closing discarded them, and the last syscalls before a container
// exits are often the ones that explain why it did.
func (e *EBPFProbe) Detach() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stop = true
	if e.reader != nil {
		_ = e.reader.Flush()
	}
}
