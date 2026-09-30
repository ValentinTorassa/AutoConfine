package learn

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// ContainerRuntime is the part of Podman that capture-from-exec needs.
type ContainerRuntime interface {
	// Create makes the container without running anything; args go before the image.
	Create(image string, args []string) (string, error)
	// Init has the OCI runtime set up the container (cgroup included) and
	// returns the host PID of its init process, which waits until Start.
	Init(id string) (int, error)
	Start(id string) error
	Remove(id string) error
}

// Podman drives the podman CLI. Docker has no equivalent of `podman init`
// (creating the runtime container without starting it), so it is not offered.
type Podman struct{ Bin string }

func (p Podman) bin() string {
	if p.Bin == "" {
		return "podman"
	}
	return p.Bin
}

func (p Podman) run(args ...string) (string, error) {
	cmd := exec.Command(p.bin(), args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", p.bin(), args[0], err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

func createArgs(image string, args []string) []string {
	return append(append([]string{"create"}, args...), image)
}

func (p Podman) Create(image string, args []string) (string, error) {
	id, err := p.run(createArgs(image, args)...)
	if err == nil && id == "" {
		err = fmt.Errorf("%s create returned no container id", p.bin())
	}
	return id, err
}

func (p Podman) Init(id string) (int, error) {
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

func (p Podman) Start(id string) error {
	_, err := p.run("start", id)
	return err
}

func (p Podman) Remove(id string) error {
	_, err := p.run("rm", "--force", "--time", "0", id)
	return err
}
