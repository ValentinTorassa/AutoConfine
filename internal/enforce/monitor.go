package enforce

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/ValentinTorassa/autoconfine/internal/bpf"
	"github.com/ValentinTorassa/autoconfine/internal/drift"
	"github.com/ValentinTorassa/autoconfine/internal/models"
	"github.com/ValentinTorassa/autoconfine/internal/profile"
)

// Container is the part of Podman a monitored run needs.
type Container interface {
	// Create makes the container from `podman run` arguments (options, image
	// and command) without starting it.
	Create(args []string) (string, error)
	// Init has the OCI runtime set the container up and returns the host PID
	// of its init process, which waits until the container starts.
	Init(id string) (int, error)
	// StartAttached starts it in the foreground and waits until it exits.
	StartAttached(id string) error
	Remove(id string) error
}

// hookFor picks where the probe must look to see the syscalls outside the
// profile. Seccomp runs before sys_enter: a call it lets run (SCMP_ACT_LOG in
// audit mode) reaches sys_enter, but one it denies with an errno only shows
// up at sys_exit.
func hookFor(action string) (bpf.Hook, string) {
	switch action {
	case "SCMP_ACT_LOG", "SCMP_ACT_ALLOW":
		return bpf.SysEnter, ""
	case "SCMP_ACT_ERRNO":
		return bpf.SysExit, ""
	}
	return bpf.SysExit, fmt.Sprintf("el perfil usa %s por defecto; el monitoreo ve las syscalls denegadas con un errno (SCMP_ACT_ERRNO), no las que matan o señalizan al proceso. --audit las deja correr y las ve todas", action)
}

// monitor runs the container under the profile with a probe attached before
// its entrypoint starts (the learn --from-start sequence: create, init,
// attach, start) and reports each syscall outside the profile as it happens.
// If the probe cannot attach, the container is removed without starting.
func (r *Runner) monitor(args []string) (summary *drift.Summary, err error) {
	bin, rest, err := split(args)
	if err != nil {
		return nil, err
	}
	if filepath.Base(bin) != "podman" {
		return nil, fmt.Errorf("el monitoreo necesita Podman (podman init arma el contenedor sin arrancarlo); %s no tiene un equivalente", bin)
	}
	if err := profile.ValidateProfile(r.cfg.ProfilePath); err != nil {
		return nil, err
	}
	allowed, err := profile.AllowedSyscalls(r.cfg.ProfilePath)
	if err != nil {
		return nil, fmt.Errorf("leer perfil: %w", err)
	}
	loaded, err := LoadProfile(r.cfg.ProfilePath)
	if err != nil {
		return nil, fmt.Errorf("leer perfil: %w", err)
	}
	action, _ := loaded["defaultAction"].(string)
	applied := r.cfg.ProfilePath
	if r.cfg.Audit {
		if applied, err = writeAuditProfile(loaded); err != nil {
			return nil, err
		}
		defer os.Remove(applied)
		action = "SCMP_ACT_LOG"
	}
	hook, warning := hookFor(action)
	if warning != "" {
		fmt.Fprintf(r.log, "enforce: aviso: %s\n", warning)
	}

	ctr := r.container(bin)
	id, err := ctr.Create(append([]string{"--security-opt", "seccomp=" + applied}, rest...))
	if err != nil {
		return nil, fmt.Errorf("crear contenedor: %w", err)
	}
	// Until it starts the container is ours to clean up; afterwards it is
	// the user's, as with podman run (--rm removes it).
	started := false
	defer func() {
		if started {
			return
		}
		if rmErr := ctr.Remove(id); rmErr != nil && err == nil {
			err = fmt.Errorf("borrar contenedor %s: %w", id, rmErr)
		}
	}()
	pid, err := ctr.Init(id)
	if err != nil {
		return nil, fmt.Errorf("inicializar contenedor: %w", err)
	}

	probe := r.newProbe(pid, hook)
	events := make(chan models.SyscallEvent, 1<<16)
	raised := make(chan error, 1)
	go func() { raised <- probe.Attach("", events) }()
	abort := func() {
		probe.Detach()
		drain(events)
		<-raised
	}
	select {
	case err := <-probe.Ready():
		if err != nil {
			abort()
			return nil, fmt.Errorf("activar monitoreo (el contenedor no se arrancó): %w", err)
		}
	case <-time.After(r.attachTO):
		abort()
		return nil, errors.New("el monitoreo no se activó a tiempo; el contenedor no se arrancó")
	}

	mon := &drift.Monitor{Allowed: drift.ProfileSet(allowed), Profile: r.cfg.ProfilePath,
		ContainerID: id, Action: action, Reporter: r.cfg.DriftReporter}
	type result struct {
		summary *drift.Summary
		err     error
	}
	watched := make(chan result, 1)
	go func() {
		s, err := mon.Watch(events)
		watched <- result{s, err}
	}()

	fmt.Fprintf(r.log, "enforce: monitoreo activo (%s, %s por defecto); arrancando el contenedor %.12s\n", r.cfg.ProfilePath, action, id)
	started = true
	runErr := ctr.StartAttached(id)
	probe.Detach()
	res := <-watched
	probeErr := <-raised

	writeSummary(r.log, res.summary, action)
	switch {
	case probeErr != nil:
		return res.summary, fmt.Errorf("monitoreo incompleto, el resumen puede faltar syscalls: %w", probeErr)
	case res.err != nil:
		return res.summary, res.err
	case runErr != nil:
		return res.summary, fmt.Errorf("el contenedor terminó con error: %w", runErr)
	}
	return res.summary, nil
}

// writeAuditProfile writes a copy of the profile whose default action is
// SCMP_ACT_LOG, so a syscall outside it runs and the kernel logs it instead
// of failing. The caller removes the file.
func writeAuditProfile(loaded map[string]interface{}) (string, error) {
	audit := make(map[string]interface{}, len(loaded))
	for k, v := range loaded {
		audit[k] = v
	}
	audit["defaultAction"] = "SCMP_ACT_LOG"
	delete(audit, "defaultErrnoRet") // only meaningful with SCMP_ACT_ERRNO
	file, err := os.CreateTemp("", "autoconfine-audit-*.json")
	if err != nil {
		return "", fmt.Errorf("perfil de auditoría: %w", err)
	}
	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	if err := enc.Encode(audit); err != nil {
		file.Close()
		os.Remove(file.Name())
		return "", fmt.Errorf("perfil de auditoría: %w", err)
	}
	if err := file.Close(); err != nil {
		os.Remove(file.Name())
		return "", fmt.Errorf("perfil de auditoría: %w", err)
	}
	return file.Name(), nil
}

// writeSummary prints what the monitor saw, once the container has exited.
func writeSummary(w io.Writer, s *drift.Summary, action string) {
	switch {
	case !s.Started:
		fmt.Fprintln(w, "enforce: monitoreo: no se observó el execve del entrypoint, así que no hubo syscalls del contenedor para comparar; revisar el error de podman")
	case s.Outside == 0:
		fmt.Fprintf(w, "enforce: monitoreo: %d syscalls observadas desde el execve del entrypoint, ninguna fuera del perfil\n", s.Events)
	default:
		fmt.Fprintf(w, "enforce: monitoreo: %d de %d syscalls observadas fuera del perfil (%s), %d distintas:\n", s.Outside, s.Events, action, len(s.Syscalls))
		for _, c := range s.Syscalls {
			fmt.Fprintf(w, "enforce:   %-20s %6d  primera vez %s, pid %d (%s)\n", c.Syscall, c.Events, c.First.Local().Format("15:04:05.000"), c.PID, c.Comm)
		}
	}
}

func drain(events <-chan models.SyscallEvent) {
	for range events {
	}
}
