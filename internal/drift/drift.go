package drift

import (
	"encoding/json"
	"io"
	"time"
)

// Event describe una syscall fuera del perfil aprendido.
type Event struct {
	Timestamp   time.Time `json:"timestamp"`
	Syscall     string    `json:"syscall"`
	ContainerID string    `json:"container_id,omitempty"`
	Image       string    `json:"image,omitempty"`
	PID         int       `json:"pid,omitempty"`
	Comm        string    `json:"comm,omitempty"`
	Profile     string    `json:"profile,omitempty"`
	// Live monitoring only: what the applied profile does with the call
	// (SCMP_ACT_ERRNO denies it, SCMP_ACT_LOG in audit mode lets it run),
	// and the errno it returned when the probe saw it at sys_exit.
	Action string `json:"action,omitempty"`
	Errno  int    `json:"errno,omitempty"`
}

// Reporter escribe eventos de drift.
type Reporter interface {
	Report(Event) error
}

// JSONReporter emite eventos de drift como JSONL.
type JSONReporter struct {
	w   io.Writer
	enc *json.Encoder
}

// NewJSONReporter crea un reporter JSONL.
func NewJSONReporter(w io.Writer) *JSONReporter {
	return &JSONReporter{w: w, enc: json.NewEncoder(w)}
}

// Report escribe un evento de drift.
func (j *JSONReporter) Report(e Event) error {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	return j.enc.Encode(e)
}

// Allowed decide si una syscall está dentro del perfil.
func Allowed(profile map[string]bool, syscall string) bool {
	return profile[syscall]
}

// ProfileSet convierte una lista de syscalls permitidas en un set.
func ProfileSet(allowed []string) map[string]bool {
	set := make(map[string]bool, len(allowed))
	for _, s := range allowed {
		set[s] = true
	}
	return set
}
