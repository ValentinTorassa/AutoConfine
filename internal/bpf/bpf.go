package bpf

import (
	"time"

	"github.com/ValentinTorassa/autoconfine/internal/models"
)

// Hook is the syscall tracepoint a probe records at.
type Hook int

const (
	// SysEnter sees every syscall that seccomp lets run: all of them when no
	// profile is applied (learn) or when the profile only logs (audit).
	SysEnter Hook = iota
	// SysExit also sees the syscalls a profile denies with an errno, which
	// seccomp keeps from reaching sys_enter but which still return. A call
	// that never returns (exit, exit_group, a killed process) is not seen.
	SysExit
)

// Probe define la interfaz para observar syscalls.
type Probe interface {
	Attach(image string, events chan<- models.SyscallEvent) error
	Detach()
	// Ready entrega nil cuando la captura ya está activa, o el error si no pudo
	// activarse. Solo después conviene arrancar el contenedor.
	Ready() <-chan error
}

// NoopProbe simula observación para pruebas sin acceso a eBPF.
type NoopProbe struct {
	stop  chan struct{}
	ready chan error
}

// NewNoopProbe crea una sonda de prueba.
func NewNoopProbe() *NoopProbe {
	ready := make(chan error, 1)
	ready <- nil
	return &NoopProbe{stop: make(chan struct{}), ready: ready}
}

// Ready está listo desde el inicio: la simulación no tiene nada que cargar.
func (n *NoopProbe) Ready() <-chan error { return n.ready }

// Attach emite eventos sintéticos de syscalls comunes de contenedores.
func (n *NoopProbe) Attach(image string, events chan<- models.SyscallEvent) error {
	common := []string{"openat", "close", "read", "write", "epoll_pwait", "futex", "mmap", "brk", "clone", "exit_group"}
	i := 0
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	defer close(events)

	for {
		select {
		case <-n.stop:
			return nil
		case t := <-ticker.C:
			select {
			case events <- models.SyscallEvent{
				Timestamp: t,
				Image:     image,
				PID:       1000 + i%5,
				Comm:      "app",
				Syscall:   common[i%len(common)],
				Phase:     "synthetic",
			}:
				i++
			case <-n.stop:
				return nil
			}
		}
	}
}

// Detach finaliza la sonda.
func (n *NoopProbe) Detach() {
	close(n.stop)
}
