package podman

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakePodman is a shell script standing in for the podman binary: it logs
// each invocation and answers create, inspect and start like podman would.
func fakePodman(t *testing.T) (CLI, string) {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	script := `#!/bin/sh
echo "$*" >> "` + log + `"
case "$1" in
create) echo c0ffee ;;
inspect) echo 4242 ;;
start) echo container output; exit 3 ;;
esac
`
	bin := filepath.Join(dir, "podman")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return CLI{Bin: bin}, log
}

func TestCreateInitAndStartAttached(t *testing.T) {
	cli, log := fakePodman(t)
	id, err := cli.Create([]string{"--security-opt", "seccomp=p.json", "--rm", "alpine", "true"})
	if err != nil || id != "c0ffee" {
		t.Fatalf("create: %q %v", id, err)
	}
	pid, err := cli.Init(id)
	if err != nil || pid != 4242 {
		t.Fatalf("init: %d %v", pid, err)
	}
	// The container's exit status comes back as the error, as with podman run.
	var exit *exec.ExitError
	if err := cli.StartAttached(id); !errors.As(err, &exit) || exit.ExitCode() != 3 {
		t.Fatalf("start --attach: %v", err)
	}
	calls, _ := os.ReadFile(log)
	want := "create --security-opt seccomp=p.json --rm alpine true\ninit c0ffee\ninspect --format {{.State.Pid}} c0ffee\nstart --attach c0ffee\n"
	if string(calls) != want {
		t.Fatalf("calls:\n%s\nwant:\n%s", calls, want)
	}
}

func TestCreateReportsPodmanError(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "podman")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho 'Error: unknown shorthand flag: d' >&2\nexit 125\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := CLI{Bin: bin}.Create([]string{"-d", "alpine"})
	if err == nil || !strings.Contains(err.Error(), "unknown shorthand flag") {
		t.Fatalf("err %v", err)
	}
}
