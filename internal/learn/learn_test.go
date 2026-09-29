package learn

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTracerRequiresImage(t *testing.T) {
	tracer := NewTracer(Config{})
	if err := tracer.Run(); err == nil {
		t.Fatal("se esperaba error por imagen vacía")
	}
}

func TestTracerProducesTrace(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "trace.jsonl")
	tracer := NewTracer(Config{
		Image:     "test",
		Duration:  200 * time.Millisecond,
		Output:    out,
		Synthetic: true,
	})

	if err := tracer.Run(); err != nil {
		t.Fatalf("run: %v", err)
	}

	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() == 0 {
		t.Fatal("la traza está vacía")
	}
}
