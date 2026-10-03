package learn

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ValentinTorassa/autoconfine/internal/bpf"
	"github.com/ValentinTorassa/autoconfine/internal/models"
	"github.com/ValentinTorassa/autoconfine/internal/traceio"
)

// log records the order of runtime and probe steps.
type stepLog struct {
	mu    sync.Mutex
	steps []string
}

func (l *stepLog) add(s string) { l.mu.Lock(); l.steps = append(l.steps, s); l.mu.Unlock() }
func (l *stepLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.steps, ",")
}

type fakeRuntime struct {
	log      *stepLog
	started  chan struct{}
	startErr error
}

func (f *fakeRuntime) Create(image string, args, command []string) (string, error) {
	step := "create:" + image + ":" + strings.Join(args, " ")
	if len(command) > 0 {
		step += ":" + strings.Join(command, " ")
	}
	f.log.add(step)
	return "c1", nil
}
func (f *fakeRuntime) Init(id string) (int, error) { f.log.add("init"); return 4242, nil }
func (f *fakeRuntime) Start(id string) error {
	f.log.add("start")
	if f.startErr == nil {
		close(f.started)
	}
	return f.startErr
}
func (f *fakeRuntime) Remove(id string) error { f.log.add("remove"); return nil }

// fakeProbe emits runtime-setup noise, then the entrypoint's execve and its
// syscalls, but only once the container has been started.
type fakeProbe struct {
	log       *stepLog
	started   <-chan struct{}
	ready     chan error
	attachErr error
	stop      chan struct{}
	once      sync.Once
	emitted   chan struct{} // closed, if set, once the events are sent
}

func (p *fakeProbe) Ready() <-chan error { return p.ready }
func (p *fakeProbe) Detach()             { p.once.Do(func() { close(p.stop) }) }
func (p *fakeProbe) Attach(image string, events chan<- models.SyscallEvent) error {
	defer close(events)
	if p.attachErr != nil {
		p.ready <- p.attachErr
		return p.attachErr
	}
	p.log.add("attach")
	p.ready <- nil
	select {
	case <-p.started:
	case <-p.stop:
		return nil
	}
	for _, name := range []string{"futex", "read", "execve", "brk", "openat", "bind"} {
		events <- models.SyscallEvent{Syscall: name, Phase: "observed-ebpf", PID: 4242}
	}
	if p.emitted != nil {
		close(p.emitted)
	}
	<-p.stop
	return nil
}

func newFakeTracer(t *testing.T, cfg Config, rt *fakeRuntime, probe *fakeProbe) (*Tracer, *bytes.Buffer) {
	t.Helper()
	warn := &bytes.Buffer{}
	tr := NewTracer(cfg)
	tr.runtime = rt
	tr.newProbe = func(pid int) bpf.Probe {
		if pid != 4242 {
			t.Errorf("probe got pid %d, want the init PID 4242", pid)
		}
		return probe
	}
	tr.warn = warn
	return tr, warn
}

func TestFromStartAttachesBeforeStartAndKeepsOnlyPostExec(t *testing.T) {
	log := &stepLog{}
	started := make(chan struct{})
	rt := &fakeRuntime{log: log, started: started}
	probe := &fakeProbe{log: log, started: started, ready: make(chan error, 1), stop: make(chan struct{})}
	out := filepath.Join(t.TempDir(), "trace.jsonl")
	tr, _ := newFakeTracer(t, Config{Image: "nginx", Duration: 150 * time.Millisecond, Output: out, FromStart: true, CreateArgs: []string{"-p", "8080:80"}}, rt, probe)

	if err := tr.Run(); err != nil {
		t.Fatal(err)
	}
	if got := log.String(); got != "create:nginx:-p 8080:80,init,attach,start,remove" {
		t.Fatalf("steps %s", got)
	}
	events, err := traceio.ReadEvents(out)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range events {
		names = append(names, e.Syscall)
		if e.CaptureMode != "from-exec" {
			t.Fatalf("capture mode %q", e.CaptureMode)
		}
	}
	if strings.Join(names, ",") != "execve,brk,openat,bind" {
		t.Fatalf("recorded %v; runtime setup before execve must be dropped", names)
	}
}

func TestFromStartNeverStartsWhenCaptureFails(t *testing.T) {
	log := &stepLog{}
	rt := &fakeRuntime{log: log, started: make(chan struct{})}
	probe := &fakeProbe{log: log, ready: make(chan error, 1), stop: make(chan struct{}), attachErr: errors.New("no CAP_BPF")}
	tr, _ := newFakeTracer(t, Config{Image: "nginx", Duration: time.Second, Output: filepath.Join(t.TempDir(), "t.jsonl"), FromStart: true}, rt, probe)

	err := tr.Run()
	if err == nil || !strings.Contains(err.Error(), "no CAP_BPF") {
		t.Fatalf("err %v", err)
	}
	if got := log.String(); got != "create:nginx:,init,remove" {
		t.Fatalf("steps %s: the container must not start without capture", got)
	}
}

func TestPIDModeWarnsThatStartupIsMissing(t *testing.T) {
	log := &stepLog{}
	started := make(chan struct{})
	close(started)
	probe := &fakeProbe{log: log, started: started, ready: make(chan error, 1), stop: make(chan struct{})}
	out := filepath.Join(t.TempDir(), "trace.jsonl")
	tr, warn := newFakeTracer(t, Config{Image: "nginx", Duration: 100 * time.Millisecond, Output: out, PID: 4242}, &fakeRuntime{log: log}, probe)
	if err := tr.Run(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(warn.String(), "--from-start") {
		t.Fatalf("no startup warning: %q", warn.String())
	}
	events, _ := traceio.ReadEvents(out)
	if len(events) != 6 || events[0].CaptureMode != "attached" {
		t.Fatalf("attached mode keeps every event, labelled: %+v", events)
	}
	if _, err := os.Stat(out + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temporary trace left behind")
	}
}

func TestExactlyOneModeIsRequired(t *testing.T) {
	for _, cfg := range []Config{
		{Image: "x", Duration: time.Second},
		{Image: "x", Duration: time.Second, PID: 1, FromStart: true},
		{Image: "x", Duration: time.Second, Synthetic: true, FromStart: true},
	} {
		if err := NewTracer(cfg).Run(); err == nil {
			t.Fatalf("config %+v should be rejected", cfg)
		}
	}
}

func TestPodmanCreateArgsPrecedeImage(t *testing.T) {
	got := strings.Join(createArgs("nginx:latest", []string{"-p", "8080:80", "-e", "A=1"}, nil), " ")
	if got != "-p 8080:80 -e A=1 nginx:latest" {
		t.Fatalf("got %q", got)
	}
	got = strings.Join(createArgs("nginx:latest", []string{"-p", "8080:80"}, []string{"nginx", "-g", "daemon off;"}), "|")
	if got != "-p|8080:80|nginx:latest|nginx|-g|daemon off;" {
		t.Fatalf("the command must follow the image: %q", got)
	}
}

func TestStopEndsCaptureEarlyAndKeepsTrace(t *testing.T) {
	log := &stepLog{}
	started := make(chan struct{})
	emitted := make(chan struct{})
	stop := make(chan struct{})
	rt := &fakeRuntime{log: log, started: started}
	probe := &fakeProbe{log: log, started: started, ready: make(chan error, 1), stop: make(chan struct{}), emitted: emitted}
	out := filepath.Join(t.TempDir(), "trace.jsonl")
	cfg := Config{Image: "nginx", Duration: time.Hour, Output: out, FromStart: true,
		Command: []string{"nginx", "-g", "daemon off;"}, Stop: stop}
	tr, _ := newFakeTracer(t, cfg, rt, probe)
	go func() { <-emitted; close(stop) }()

	done := make(chan error, 1)
	go func() { done <- tr.Run() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Stop did not end the capture before Duration")
	}
	if got := log.String(); got != "create:nginx::nginx -g daemon off;,init,attach,start,remove" {
		t.Fatalf("steps %s", got)
	}
	events, err := traceio.ReadEvents(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 4 || events[0].Syscall != "execve" {
		t.Fatalf("an early stop keeps what was recorded from the execve on: %+v", events)
	}
}

func TestStopBeforeStartNeverStartsTheContainer(t *testing.T) {
	log := &stepLog{}
	stop := make(chan struct{})
	close(stop)
	rt := &fakeRuntime{log: log, started: make(chan struct{})}
	probe := &fakeProbe{log: log, started: rt.started, ready: make(chan error, 1), stop: make(chan struct{})}
	out := filepath.Join(t.TempDir(), "trace.jsonl")
	tr, _ := newFakeTracer(t, Config{Image: "nginx", Duration: time.Hour, Output: out, FromStart: true, Stop: stop}, rt, probe)

	if err := tr.Run(); err == nil {
		t.Fatal("a capture stopped before the container started must not report success")
	}
	if got := log.String(); got != "create:nginx:,init,attach,remove" {
		t.Fatalf("steps %s: the container must not start once stopped", got)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("no trace should be saved")
	}
}
