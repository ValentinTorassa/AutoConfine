package profile

import (
	"os"
	"path/filepath"
	"testing"
)

func sampleTrace(t *testing.T, name string, lines []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
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

func TestAnalyzeTrace(t *testing.T) {
	trace := sampleTrace(t, "trace.jsonl", []string{
		`{"syscall":"openat","pid":1}`,
		`{"syscall":"close","pid":1}`,
		`{"syscall":"read","pid":1}`,
		`{"syscall":"openat","pid":2}`,
	})
	stats, err := AnalyzeTrace(trace, 304)
	if err != nil {
		t.Fatal(err)
	}
	if stats.GeneratedAllowed != 3 {
		t.Fatalf("allowed = %d, want 3", stats.GeneratedAllowed)
	}
	if stats.TraceSource != "unknown" || stats.EventsCount != 4 {
		t.Fatalf("source/count = %s/%d", stats.TraceSource, stats.EventsCount)
	}
	if stats.ReductionPercent <= 0 {
		t.Fatalf("reduction should be positive, got %f", stats.ReductionPercent)
	}

	report := filepath.Join(t.TempDir(), "report.md")
	if err := WriteReport(stats, trace, report); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("report is empty")
	}
}

func TestAnalyzeTraceLabelsObservedSource(t *testing.T) {
	trace := sampleTrace(t, "observed.jsonl", []string{
		`{"syscall":"openat","phase":"observed-ebpf"}`,
		`{"syscall":"close","phase":"observed-ebpf"}`,
	})
	stats, err := AnalyzeTrace(trace, 304)
	if err != nil {
		t.Fatal(err)
	}
	if stats.TraceSource != "observed-ebpf" || stats.EventsCount != 2 {
		t.Fatalf("source/count = %s/%d", stats.TraceSource, stats.EventsCount)
	}
}

func TestCompareTraces(t *testing.T) {
	a := sampleTrace(t, "a.jsonl", []string{
		`{"syscall":"openat","pid":1}`,
		`{"syscall":"close","pid":1}`,
	})
	b := sampleTrace(t, "b.jsonl", []string{
		`{"syscall":"openat","pid":1}`,
		`{"syscall":"read","pid":1}`,
	})
	res, err := CompareTraces(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Added) != 1 || res.Added[0] != "read" {
		t.Fatalf("added = %v, want [read]", res.Added)
	}
	if len(res.Removed) != 1 || res.Removed[0] != "close" {
		t.Fatalf("removed = %v, want [close]", res.Removed)
	}
	if len(res.Common) != 1 || res.Common[0] != "openat" {
		t.Fatalf("common = %v, want [openat]", res.Common)
	}
}

func TestMergeTraces(t *testing.T) {
	a := sampleTrace(t, "a.jsonl", []string{
		`{"syscall":"openat","pid":1,"timestamp":"2026-06-19T12:00:00Z"}`,
	})
	b := sampleTrace(t, "b.jsonl", []string{
		`{"syscall":"close","pid":2,"timestamp":"2026-06-19T12:00:01Z"}`,
	})
	out := filepath.Join(t.TempDir(), "merged.jsonl")
	if err := MergeTraces([]string{a, b}, out); err != nil {
		t.Fatal(err)
	}
	stats, err := AnalyzeTrace(out, 304)
	if err != nil {
		t.Fatal(err)
	}
	if stats.GeneratedAllowed != 2 {
		t.Fatalf("allowed = %d, want 2", stats.GeneratedAllowed)
	}
}
