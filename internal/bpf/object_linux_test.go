//go:build linux

package bpf

import (
	"bytes"
	"testing"

	"github.com/cilium/ebpf"
)

// Parsing the embedded object needs no privileges; it catches an object that
// no longer matches what the Go side expects (map names, types, sizes).
func TestEmbeddedObjectMatchesDecoder(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(syscallObject))
	if err != nil {
		t.Fatal(err)
	}
	if spec.Programs["trace_sys_enter"] == nil {
		t.Fatal("program trace_sys_enter missing")
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
