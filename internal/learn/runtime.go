package learn

import "github.com/ValentinTorassa/autoconfine/internal/podman"

// ContainerRuntime is the part of Podman that capture-from-exec needs.
type ContainerRuntime interface {
	// Create makes the container without running anything; args go before
	// the image and command, if any, replaces the image's default command.
	Create(image string, args, command []string) (string, error)
	// Init has the OCI runtime set up the container (cgroup included) and
	// returns the host PID of its init process, which waits until Start.
	Init(id string) (int, error)
	Start(id string) error
	Remove(id string) error
}

// Podman is the ContainerRuntime learn uses: the podman CLI, with the image
// after the user's `podman create` options and the command after the image.
type Podman struct{ podman.CLI }

func (p Podman) Create(image string, args, command []string) (string, error) {
	return p.CLI.Create(createArgs(image, args, command))
}

func createArgs(image string, args, command []string) []string {
	out := append(append([]string{}, args...), image)
	return append(out, command...)
}
