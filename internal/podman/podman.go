// Package podman drives the podman CLI through the steps that let a probe
// attach before a container's entrypoint runs: create the container, have the
// OCI runtime set it up (init), start it, and remove it.
package podman

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

// CLI runs the podman binary. Docker has no equivalent of `podman init`
// (creating the runtime container without starting it), so it is not offered.
type CLI struct{ Bin string }

func (p CLI) bin() string {
	if p.Bin == "" {
		return "podman"
	}
	return p.Bin
}

func (p CLI) run(args ...string) (string, error) {
	cmd := exec.Command(p.bin(), args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", p.bin(), args[0], err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// Create runs `podman create ARGS` (options, image and optional command)
// without running anything, and returns the container ID.
func (p CLI) Create(args []string) (string, error) {
	id, err := p.run(append([]string{"create"}, args...)...)
	if err == nil && id == "" {
		err = fmt.Errorf("%s create returned no container id", p.bin())
	}
	return id, err
}

// Init has the OCI runtime set up the container (cgroup included) and returns
// the host PID of its init process, which waits until Start.
func (p CLI) Init(id string) (int, error) {
	if _, err := p.run("init", id); err != nil {
		return 0, err
	}
	out, err := p.run("inspect", "--format", "{{.State.Pid}}", id)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(out)
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("container %s has no init PID after init (got %q)", id, out)
	}
	return pid, nil
}

func (p CLI) Start(id string) error {
	_, err := p.run("start", id)
	return err
}

// StartAttached starts the container with its output on this process's
// stdout and stderr and waits until it exits, like the second half of
// `podman run`; the error carries podman's exit status. Stdin is not
// attached. Ctrl-C reaches podman directly (same process group) and podman
// passes it on; a SIGTERM sent only to this process is forwarded, so the
// caller survives both and can still report once the container is gone.
func (p CLI) StartAttached(id string) error {
	cmd := exec.Command(p.bin(), "start", "--attach", id)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case sig := <-signals:
				if sig == syscall.SIGTERM {
					_ = cmd.Process.Signal(sig)
				}
			case <-done:
				return
			}
		}
	}()
	return cmd.Wait()
}

func (p CLI) Remove(id string) error {
	_, err := p.run("rm", "--force", "--time", "0", id)
	return err
}
