package generate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateProfile(t *testing.T) {
	dir := t.TempDir()
	trace := filepath.Join(dir, "trace.jsonl")
	out := filepath.Join(dir, "profile.json")

	lines := []string{
		`{"syscall":"openat","pid":1}`,
		`{"syscall":"close","pid":1}`,
		`{"syscall":"read","pid":1}`,
		`{"syscall":"openat","pid":2}`,
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
	if err := gen.Generate(trace, out); err != nil {
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
	if err := os.WriteFile(trace, []byte("{\"syscall\":\"syscall_9999\"}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := NewGenerator(Config{}).Generate(trace, out); err == nil {
		t.Fatal("expected unknown syscall error")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("profile should not exist")
	}
}
