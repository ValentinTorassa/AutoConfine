//go:build linux

package bpf

import (
	"bytes"
	"errors"
	"os"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// Parsing the embedded object needs no privileges; it catches an object that
// no longer matches what the Go side expects (map names, types, sizes).
func TestEmbeddedObjectMatchesDecoder(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(syscallObject))
	if err != nil {
		t.Fatal(err)
	}
	for hook, program := range programs {
		p := spec.Programs[program.name]
		if p == nil {
			t.Fatalf("hook %d: program %s missing", hook, program.name)
		}
		if p.Type != ebpf.RawTracepoint || p.SectionName != "raw_tracepoint/"+program.tracepoint {
			t.Errorf("program %s: type %v section %s", program.name, p.Type, p.SectionName)
		}
	}
	want := map[string]struct {
		typ       ebpf.MapType
		valueSize uint32
	}{
		"target_cgroup": {ebpf.Array, 16},
		"drops":         {ebpf.PerCPUArray, 8},
		"events":        {ebpf.RingBuf, 0},
	}
	for name, w := range want {
		m := spec.Maps[name]
		if m == nil {
			t.Fatalf("map %s missing", name)
		}
		if m.Type != w.typ || m.ValueSize != w.valueSize {
			t.Errorf("map %s: type %v value %d, want %v %d", name, m.Type, m.ValueSize, w.typ, w.valueSize)
		}
	}
	if bytes.Contains(syscallObject, []byte("/home/")) {
		t.Error("the committed object embeds a home directory path; rebuild with make bpf")
	}
}

// trace_sys_exit reads the syscall number at PT_REGS_ORIG_AX (120) in
// syscalls.bpf.c; reading the kernel's BTF needs no privileges.
func TestPtRegsOrigAXOffset(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("the probe only names amd64 syscalls")
	}
	spec, err := btf.LoadKernelSpec()
	if errors.Is(err, ebpf.ErrNotSupported) || errors.Is(err, os.ErrPermission) {
		t.Skipf("no kernel BTF: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	var regs *btf.Struct
	if err := spec.TypeByName("pt_regs", &regs); err != nil {
		t.Fatal(err)
	}
	for _, m := range regs.Members {
		if m.Name == "orig_ax" {
			if got := m.Offset.Bytes(); got != 120 {
				t.Fatalf("pt_regs.orig_ax at %d, the probe reads 120", got)
			}
			return
		}
	}
	t.Fatal("pt_regs has no orig_ax")
}
