package models

import "time"

// SyscallEvent representa una syscall observada.
type SyscallEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	ContainerID string    `json:"container_id,omitempty"`
	Image       string    `json:"image,omitempty"`
	PID         int       `json:"pid"`
	TID         int       `json:"tid"`
	Comm        string    `json:"comm"`
	Executable  string    `json:"executable,omitempty"`
	Syscall     string    `json:"syscall"`
	Number      int       `json:"syscall_number,omitempty"`
	Phase       string    `json:"phase,omitempty"`
	// CaptureMode says what the trace can cover: "from-exec" (attached before
	// the container started), "attached" (joined a running container, so its
	// startup is missing) or "synthetic".
	CaptureMode string `json:"capture_mode,omitempty"`
	Result      int    `json:"result,omitempty"`
	Errno       int    `json:"errno,omitempty"`
}

// TraceSummary resume una traza aprendida.
type TraceSummary struct {
	Image            string   `json:"image"`
	Duration         string   `json:"duration"`
	EventsCount      int      `json:"events_count"`
	UniqueSyscalls   []string `json:"unique_syscalls"`
	DefaultAllowed   int      `json:"default_allowed"`
	GeneratedAllowed int      `json:"generated_allowed"`
}

// DriftEvent representa una syscall fuera del perfil observado.
type DriftEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	Syscall     string    `json:"syscall"`
	ContainerID string    `json:"container_id,omitempty"`
	Image       string    `json:"image,omitempty"`
	PID         int       `json:"pid"`
	Comm        string    `json:"comm"`
	Profile     string    `json:"profile"`
}
