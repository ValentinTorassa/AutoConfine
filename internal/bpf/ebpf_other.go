//go:build !linux

package bpf

import (
	"errors"

	"github.com/ValentinTorassa/autoconfine/internal/models"
)

// EBPFProbe is unavailable outside Linux: /proc, cgroup v2 and eBPF are Linux
// features. The type exists so the rest of the tool builds everywhere.
type EBPFProbe struct {
	PID   int
	Hook  Hook
	ready chan error
}

var errUnsupported = errors.New("real syscall capture requires Linux with eBPF and cgroup v2")

func NewEBPFProbe(pid int) *EBPFProbe {
	ready := make(chan error, 1)
	ready <- errUnsupported
	return &EBPFProbe{PID: pid, ready: ready}
}

func (e *EBPFProbe) Ready() <-chan error { return e.ready }

func (e *EBPFProbe) Attach(image string, events chan<- models.SyscallEvent) error {
	close(events)
	return errUnsupported
}

func (e *EBPFProbe) Detach() {}
