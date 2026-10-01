package enforce

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ValentinTorassa/autoconfine/internal/bpf"
	"github.com/ValentinTorassa/autoconfine/internal/drift"
	"github.com/ValentinTorassa/autoconfine/internal/models"
)

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

// fakeContainer stands in for Podman. StartAttached lets the probe emit its
// events and returns once they are all sent, like a container that exits.
type fakeContainer struct {
	log      *stepLog
	started  chan struct{}
	emitted  chan struct{}
	runErr   error
	profiles []string // defaultAction of the profile passed to create
}

func (f *fakeContainer) Create(args []string) (string, error) {
	f.log.add("create:" + strings.Join(args, " "))
	for _, arg := range args {
		if path, ok := strings.CutPrefix(arg, "seccomp="); ok {
			loaded, err := LoadProfile(path)
			if err != nil {
				return "", err
			}
			f.profiles = append(f.profiles, loaded["defaultAction"].(string))
		}
	}
	return "c1", nil
}
func (f *fakeContainer) Init(id string) (int, error) { f.log.add("init"); return 4242, nil }
func (f *fakeContainer) StartAttached(id string) error {
	f.log.add("start")
	close(f.started)
	<-f.emitted
	return f.runErr
}
func (f *fakeContainer) Remove(id string) error { f.log.add("remove"); return nil }

// fakeProbe emits runtime-setup noise, then the entrypoint's syscalls, once
// the container has started.
type fakeProbe struct {
	log       *stepLog
	started   <-chan struct{}
	emitted   chan struct{}
	syscalls  []string
	ready     chan error
	attachErr error
	stop      chan struct{}
	once      sync.Once
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
	for _, name := range p.syscalls {
		events <- models.SyscallEvent{Syscall: name, PID: 4242, Comm: "app", Timestamp: time.Now()}
	}
	close(p.emitted)
	<-p.stop
	return nil
}

func writeProfile(t *testing.T, action string, names ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "p.json")
	data, _ := json.Marshal(map[string]interface{}{
		"defaultAction": action,
		"architectures": []string{"SCMP_ARCH_X86_64"},
		"syscalls":      []map[string]interface{}{{"names": names, "action": "SCMP_ACT_ALLOW"}},
	})
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

type harness struct {
	runner *Runner
	log    *stepLog
	ctr    *fakeContainer
	hooks  []bpf.Hook
	out    *bytes.Buffer // drift JSONL
	msgs   *bytes.Buffer // summary and notices
}

func newHarness(t *testing.T, cfg Config, probe *fakeProbe) *harness {
	t.Helper()
	h := &harness{log: &stepLog{}, out: &bytes.Buffer{}, msgs: &bytes.Buffer{}}
	started, emitted := make(chan struct{}), make(chan struct{})
	h.ctr = &fakeContainer{log: h.log, started: started, emitted: emitted}
	probe.log, probe.started, probe.emitted = h.log, started, emitted
	probe.ready, probe.stop = make(chan error, 1), make(chan struct{})
	cfg.DriftReporter = drift.NewJSONReporter(h.out)
	h.runner = NewRunner(cfg)
	h.runner.container = func(bin string) Container { return h.ctr }
	h.runner.newProbe = func(pid int, hook bpf.Hook) bpf.Probe {
		if pid != 4242 {
			t.Errorf("probe got pid %d, want the init PID 4242", pid)
		}
		h.hooks = append(h.hooks, hook)
		return probe
	}
	h.runner.log = h.msgs
	return h
}

func TestMonitorAttachesBeforeStartAndReportsDeniedSyscalls(t *testing.T) {
	path := writeProfile(t, "SCMP_ACT_ERRNO", "execve", "brk", "openat", "exit_group")
	probe := &fakeProbe{syscalls: []string{"mount", "futex", "execve", "brk", "ptrace", "openat", "ptrace", "bind"}}
	h := newHarness(t, Config{ProfilePath: path, Monitor: true}, probe)

	summary, err := h.runner.Run([]string{"podman", "run", "--rm", "alpine", "true"})
	if err != nil {
		t.Fatal(err)
	}
	if got := h.log.String(); got != "create:--security-opt seccomp="+path+" --rm alpine true,init,attach,start" {
		t.Fatalf("steps %s", got)
	}
	if len(h.hooks) != 1 || h.hooks[0] != bpf.SysExit {
		t.Fatalf("hooks %v: denied syscalls only show up at sys_exit", h.hooks)
	}
	if !summary.Started || summary.Events != 6 || summary.Outside != 3 || summary.Syscalls[0].Syscall != "ptrace" {
		t.Fatalf("summary %+v", summary)
	}
	lines := strings.Split(strings.TrimSpace(h.out.String()), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], `"syscall":"ptrace"`) || !strings.Contains(lines[0], `"action":"SCMP_ACT_ERRNO"`) ||
		!strings.Contains(lines[0], `"container_id":"c1"`) || !strings.Contains(lines[2], `"syscall":"bind"`) {
		t.Fatalf("drift reports:\n%s", h.out)
	}
	if msgs := h.msgs.String(); !strings.Contains(msgs, "3 de 6 syscalls observadas fuera del perfil (SCMP_ACT_ERRNO), 2 distintas") ||
		!strings.Contains(msgs, "ptrace") || !strings.Contains(msgs, "pid 4242 (app)") {
		t.Fatalf("summary text:\n%s", msgs)
	}
}

func TestMonitorNeverStartsWhenProbeFails(t *testing.T) {
	path := writeProfile(t, "SCMP_ACT_ERRNO", "execve")
	h := newHarness(t, Config{ProfilePath: path, Monitor: true}, &fakeProbe{attachErr: errors.New("no CAP_BPF")})

	summary, err := h.runner.Run([]string{"podman", "run", "alpine"})
	if err == nil || !strings.Contains(err.Error(), "no CAP_BPF") || summary != nil {
		t.Fatalf("summary %v err %v", summary, err)
	}
	if got := h.log.String(); got != "create:--security-opt seccomp="+path+" alpine,init,remove" {
		t.Fatalf("steps %s: the container must not start unmonitored", got)
	}
}

func TestAuditRunsWithLogProfileAndWatchesSysEnter(t *testing.T) {
	path := writeProfile(t, "SCMP_ACT_ERRNO", "execve", "read")
	probe := &fakeProbe{syscalls: []string{"execve", "read", "exit_group"}}
	h := newHarness(t, Config{ProfilePath: path, Audit: true}, probe)

	summary, err := h.runner.Run([]string{"run", "alpine"})
	if err != nil {
		t.Fatal(err)
	}
	if len(h.ctr.profiles) != 1 || h.ctr.profiles[0] != "SCMP_ACT_LOG" {
		t.Fatalf("applied profile actions %v, want SCMP_ACT_LOG", h.ctr.profiles)
	}
	if len(h.hooks) != 1 || h.hooks[0] != bpf.SysEnter {
		t.Fatalf("hooks %v: logged syscalls run, so sys_enter sees them (exit_group included)", h.hooks)
	}
	if summary.Outside != 1 || summary.Syscalls[0].Syscall != "exit_group" || !strings.Contains(h.out.String(), `"action":"SCMP_ACT_LOG"`) {
		t.Fatalf("summary %+v reports %s", summary, h.out)
	}
	applied := strings.TrimPrefix(strings.Fields(h.log.String())[1], "seccomp=")
	if applied == path {
		t.Fatal("audit must not apply the original profile")
	}
	if _, err := os.Stat(applied); !os.IsNotExist(err) {
		t.Fatalf("temporary audit profile %s left behind", applied)
	}
	if data, _ := os.ReadFile(path); !strings.Contains(string(data), "SCMP_ACT_ERRNO") {
		t.Fatal("the original profile was modified")
	}
}

func TestMonitorReportsContainerFailureAndMissingExec(t *testing.T) {
	path := writeProfile(t, "SCMP_ACT_ERRNO", "execve")
	h := newHarness(t, Config{ProfilePath: path, Monitor: true}, &fakeProbe{syscalls: []string{"mount", "write"}})
	h.ctr.runErr = errors.New("exit status 127")

	summary, err := h.runner.Run([]string{"alpine"})
	if err == nil || !strings.Contains(err.Error(), "exit status 127") || summary == nil || summary.Started {
		t.Fatalf("summary %+v err %v", summary, err)
	}
	if !strings.Contains(h.msgs.String(), "no se observó el execve") {
		t.Fatalf("summary text:\n%s", h.msgs)
	}
}

func TestMonitorRefusesDockerAndWarnsAboutKillActions(t *testing.T) {
	path := writeProfile(t, "SCMP_ACT_ERRNO", "execve")
	h := newHarness(t, Config{ProfilePath: path, Monitor: true}, &fakeProbe{})
	if _, err := h.runner.Run([]string{"docker", "run", "alpine"}); err == nil || !strings.Contains(err.Error(), "Podman") {
		t.Fatalf("err %v", err)
	}
	if h.log.String() != "" {
		t.Fatalf("steps %s", h.log)
	}

	if hook, warning := hookFor("SCMP_ACT_KILL_PROCESS"); hook != bpf.SysExit || warning == "" {
		t.Fatalf("kill action: hook %v warning %q", hook, warning)
	}
}
