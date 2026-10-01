package drift

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ValentinTorassa/autoconfine/internal/models"
)

func feed(names ...string) <-chan models.SyscallEvent {
	events := make(chan models.SyscallEvent, len(names))
	start := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	for i, name := range names {
		events <- models.SyscallEvent{Timestamp: start.Add(time.Duration(i) * time.Millisecond),
			Syscall: name, PID: 4242 + i, Comm: "app", Errno: 1}
	}
	close(events)
	return events
}

func TestWatchReportsOutsideProfileFromExecOn(t *testing.T) {
	var buf bytes.Buffer
	m := &Monitor{Allowed: ProfileSet([]string{"execve", "brk", "openat"}), Profile: "p.json",
		ContainerID: "c1", Action: "SCMP_ACT_ERRNO", Reporter: NewJSONReporter(&buf)}
	// mount and futex come from the runtime before the entrypoint's execve.
	s, err := m.Watch(feed("mount", "futex", "execve", "brk", "ptrace", "openat", "ptrace", "bind"))
	if err != nil {
		t.Fatal(err)
	}
	if !s.Started || s.Events != 6 || s.Outside != 3 {
		t.Fatalf("summary %+v", s)
	}
	if len(s.Syscalls) != 2 || s.Syscalls[0].Syscall != "ptrace" || s.Syscalls[0].Events != 2 ||
		s.Syscalls[0].PID != 4246 || s.Syscalls[1].Syscall != "bind" {
		t.Fatalf("counts %+v", s.Syscalls)
	}

	var reported []Event
	sc := bufio.NewScanner(&buf)
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		reported = append(reported, e)
	}
	if len(reported) != 3 || reported[0].Syscall != "ptrace" || reported[2].Syscall != "bind" {
		t.Fatalf("reported %+v", reported)
	}
	if e := reported[0]; e.Action != "SCMP_ACT_ERRNO" || e.ContainerID != "c1" || e.Profile != "p.json" || e.Errno != 1 || e.Timestamp.IsZero() {
		t.Fatalf("event %+v", e)
	}
}

func TestWatchWithoutExecChecksNothing(t *testing.T) {
	m := &Monitor{Allowed: ProfileSet([]string{"read"}), Reporter: NewJSONReporter(&bytes.Buffer{})}
	s, err := m.Watch(feed("mount", "pivot_root", "seccomp"))
	if err != nil || s.Started || s.Events != 0 || s.Outside != 0 {
		t.Fatalf("summary %+v err %v", s, err)
	}
}

type failingReporter struct{ calls int }

func (f *failingReporter) Report(Event) error { f.calls++; return errors.New("disk full") }

func TestWatchKeepsCountingWhenReportsFail(t *testing.T) {
	rep := &failingReporter{}
	m := &Monitor{Allowed: ProfileSet([]string{"execve"}), Reporter: rep}
	s, err := m.Watch(feed("execve", "ptrace", "ptrace", "bind"))
	if err == nil || s == nil || s.Outside != 3 || rep.calls != 1 {
		t.Fatalf("summary %+v err %v calls %d", s, err, rep.calls)
	}
}
