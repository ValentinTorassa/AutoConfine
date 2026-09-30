package traceio

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempTrace(t *testing.T, lines []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trace.jsonl")
	if err := os.WriteFile(path, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range lines {
		if _, err := file.WriteString(line + "\n"); err != nil {
			t.Fatal(err)
		}
	}
	file.Close()
	return path
}

func TestReadSyscalls(t *testing.T) {
	path := writeTempTrace(t, []string{
		`{"syscall":"openat","pid":1}`,
		`{"syscall":"close","pid":1}`,
		`{"malformed",`,
		`{"syscall":"openat","pid":2}`,
	})
	counts, err := ReadSyscalls(path)
	if err != nil {
		t.Fatal(err)
	}
	if counts["openat"] != 2 {
		t.Fatalf("openat count = %d, want 2", counts["openat"])
	}
	if counts["close"] != 1 {
		t.Fatalf("close count = %d, want 1", counts["close"])
	}
}

func TestUniqueSyscalls(t *testing.T) {
	counts := map[string]int{"z": 0, "a": 0, "m": 0}
	got := UniqueSyscalls(counts)
	want := []string{"a", "m", "z"}
	for i, v := range want {
		if got[i] != v {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestReadWriteEvents(t *testing.T) {
	path := writeTempTrace(t, []string{
		`{"syscall":"openat","pid":1,"timestamp":"2026-06-19T12:00:00Z"}`,
	})
	events, err := ReadEvents(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Syscall != "openat" {
		t.Fatalf("events = %+v", events)
	}
}

func TestScanSyscallsDoesNotInheritPreviousName(t *testing.T) {
	var notice strings.Builder
	Malformed = &notice
	defer func() { Malformed = os.Stderr }()
	counts, err := scanSyscalls(strings.NewReader("{\"syscall\":\"read\"}\n{\"pid\":3}\nbroken\n{\"syscall\":\"read\"}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if counts["read"] != 2 || len(counts) != 1 {
		t.Fatalf("counts %v", counts)
	}
	if !strings.Contains(notice.String(), "2 líneas") {
		t.Fatalf("notice %q", notice.String())
	}
}
