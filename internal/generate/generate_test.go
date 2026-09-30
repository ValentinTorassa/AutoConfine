package generate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateProfile(t *testing.T) {
	dir := t.TempDir()
	trace := filepath.Join(dir, "trace.jsonl")
	out := filepath.Join(dir, "profile.json")

	lines := []string{
		`{"syscall":"openat","pid":1,"phase":"observed-ebpf"}`,
		`{"syscall":"close","pid":1,"phase":"observed-ebpf"}`,
		`{"syscall":"read","pid":1,"phase":"observed-ebpf"}`,
		`{"syscall":"openat","pid":2,"phase":"observed-ebpf"}`,
	}
	if err := os.WriteFile(trace, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(trace, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range lines {
		if _, err := file.WriteString(line + "\n"); err != nil {
			t.Fatal(err)
		}
	}
	file.Close()

	gen := NewGenerator(Config{})
	if _, err := gen.Generate(trace, out); err != nil {
		t.Fatalf("generate: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}

	var profile SeccompProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if profile.DefaultAction != "SCMP_ACT_ERRNO" {
		t.Fatalf("defaultAction = %s, want SCMP_ACT_ERRNO", profile.DefaultAction)
	}
	if len(profile.Architectures) != 1 || profile.Architectures[0] != "SCMP_ARCH_X86_64" {
		t.Fatalf("unexpected architectures: %v", profile.Architectures)
	}
	if len(profile.Syscalls) != 1 {
		t.Fatalf("syscalls len = %d, want 1", len(profile.Syscalls))
	}
	got := len(profile.Syscalls[0].Names)
	if got != 3 {
		t.Fatalf("names len = %d, want 3", got)
	}
}

func TestUnknownSyscallDoesNotWriteProfile(t *testing.T) {
	dir := t.TempDir()
	trace := filepath.Join(dir, "trace.jsonl")
	out := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(trace, []byte("{\"syscall\":\"syscall_9999\",\"phase\":\"observed-ebpf\"}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewGenerator(Config{}).Generate(trace, out); err == nil {
		t.Fatal("expected unknown syscall error")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("profile should not exist")
	}
}

func writeTrace(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trace.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// drift already refused traces that were not observed with eBPF; generate
// built a profile from them without a word.
func TestSyntheticTraceNeedsExplicitFlag(t *testing.T) {
	for _, line := range []string{`{"syscall":"read","phase":"synthetic"}`, `{"syscall":"read"}`} {
		trace := writeTrace(t, line)
		out := filepath.Join(t.TempDir(), "p.json")
		if _, err := NewGenerator(Config{}).Generate(trace, out); err == nil || !strings.Contains(err.Error(), "--allow-synthetic") {
			t.Fatalf("%s: err %v", line, err)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatal("no profile may be written for a refused trace")
		}
		res, err := NewGenerator(Config{AllowSynthetic: true}).Generate(trace, out)
		if err != nil || len(res.Warnings) == 0 {
			t.Fatalf("allowed synthetic must warn: %+v %v", res, err)
		}
	}
}

// A line without "syscall" used to inherit the previous line's name, and
// malformed lines vanished without a trace.
func TestLinesWithoutSyscallAreCountedNotInherited(t *testing.T) {
	trace := writeTrace(t,
		`{"syscall":"mprotect","phase":"observed-ebpf"}`,
		`{"pid":7,"phase":"observed-ebpf"}`,
		`not json`,
		`{"syscall":"read","phase":"observed-ebpf","capture_mode":"attached"}`,
	)
	out := filepath.Join(t.TempDir(), "p.json")
	res, err := NewGenerator(Config{}).Generate(trace, out)
	if err != nil {
		t.Fatal(err)
	}
	if res.Events != 2 || res.Malformed != 2 {
		t.Fatalf("result %+v", res)
	}
	joined := strings.Join(res.Warnings, " | ")
	if !strings.Contains(joined, "--from-start") || !strings.Contains(joined, "2 líneas") {
		t.Fatalf("warnings %q", joined)
	}
	data, _ := os.ReadFile(out)
	var profile SeccompProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(profile.Syscalls[0].Names, ","); got != "mprotect,read" {
		t.Fatalf("names %s", got)
	}
}
