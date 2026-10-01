package drift

import (
	"fmt"
	"sort"
	"time"

	"github.com/ValentinTorassa/autoconfine/internal/models"
)

// Monitor checks syscalls against a profile as a probe delivers them and
// reports each one outside it as it arrives.
type Monitor struct {
	Allowed     map[string]bool
	Profile     string // copied into each report
	ContainerID string
	// Action is what the applied profile does with a syscall outside it.
	Action   string
	Reporter Reporter
}

// Count is one syscall outside the profile and where it was first seen.
type Count struct {
	Syscall string    `json:"syscall"`
	Events  int       `json:"events"`
	First   time.Time `json:"first"`
	PID     int       `json:"pid"`
	Comm    string    `json:"comm"`
}

// Summary is what a monitored run observed.
type Summary struct {
	// Started is set once the entrypoint's execve is seen. Events before it
	// are the OCI runtime setting the container up, not checked (the same
	// cut learn --from-start makes before recording).
	Started  bool    `json:"started"`
	Events   int     `json:"events"`  // checked, from the execve on
	Outside  int     `json:"outside"` // of those, outside the profile
	Syscalls []Count `json:"syscalls"`
}

// Watch consumes events until the channel is closed and returns what it saw,
// with the syscalls outside the profile ordered by how often they occurred.
// A failing Reporter stops the reports but not the counting, so the probe is
// never left blocked.
func (m *Monitor) Watch(events <-chan models.SyscallEvent) (*Summary, error) {
	s := &Summary{}
	counts := make(map[string]*Count)
	var reportErr error
	for evt := range events {
		if !s.Started {
			if !evt.IsExec() {
				continue
			}
			s.Started = true
		}
		s.Events++
		if Allowed(m.Allowed, evt.Syscall) {
			continue
		}
		s.Outside++
		c := counts[evt.Syscall]
		if c == nil {
			c = &Count{Syscall: evt.Syscall, First: evt.Timestamp, PID: evt.PID, Comm: evt.Comm}
			counts[evt.Syscall] = c
		}
		c.Events++
		if reportErr == nil {
			reportErr = m.Reporter.Report(Event{Timestamp: evt.Timestamp, Syscall: evt.Syscall,
				ContainerID: m.ContainerID, PID: evt.PID, Comm: evt.Comm, Profile: m.Profile,
				Action: m.Action, Errno: evt.Errno})
		}
	}
	for _, c := range counts {
		s.Syscalls = append(s.Syscalls, *c)
	}
	sort.Slice(s.Syscalls, func(i, j int) bool {
		a, b := s.Syscalls[i], s.Syscalls[j]
		if a.Events != b.Events {
			return a.Events > b.Events
		}
		return a.Syscall < b.Syscall
	})
	if reportErr != nil {
		return s, fmt.Errorf("reportar drift: %w", reportErr)
	}
	return s, nil
}
