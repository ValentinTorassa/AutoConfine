package learn

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ValentinTorassa/autoconfine/internal/bpf"
	"github.com/ValentinTorassa/autoconfine/internal/models"
)

// Config define parámetros de la fase de aprendizaje.
type Config struct {
	Image    string
	Duration time.Duration
	Output   string
	// Exactamente uno de los tres modos:
	PID       int  // adjuntarse a un contenedor ya en ejecución (se pierde el arranque)
	FromStart bool // crear el contenedor, adjuntarse y recién entonces arrancarlo
	Synthetic bool // traza simulada, solo para pruebas
	// FromStart: argumentos de `podman create` antes de la imagen, y si se conserva.
	CreateArgs []string
	Keep       bool
}

// Tracer encapsula la observación de syscalls.
type Tracer struct {
	cfg      Config
	newProbe func(pid int) bpf.Probe
	runtime  ContainerRuntime
	warn     io.Writer
	attachTO time.Duration
}

// NewTracer crea un nuevo tracer.
func NewTracer(cfg Config) *Tracer {
	return &Tracer{
		cfg: cfg,
		newProbe: func(pid int) bpf.Probe {
			if cfg.Synthetic {
				return bpf.NewNoopProbe()
			}
			return bpf.NewEBPFProbe(pid)
		},
		runtime:  Podman{},
		warn:     os.Stderr,
		attachTO: 30 * time.Second,
	}
}

func (t *Tracer) validate() error {
	if t.cfg.Image == "" {
		return fmt.Errorf("se requiere --image")
	}
	if t.cfg.Duration <= 0 {
		return fmt.Errorf("--duration debe ser positivo")
	}
	modes := 0
	for _, on := range []bool{t.cfg.PID > 0, t.cfg.FromStart, t.cfg.Synthetic} {
		if on {
			modes++
		}
	}
	if modes != 1 {
		return fmt.Errorf("elegir un modo: --from-start (recomendado), --pid PID de un contenedor en ejecución, o --synthetic")
	}
	return nil
}

func (t *Tracer) captureMode() string {
	switch {
	case t.cfg.Synthetic:
		return "synthetic"
	case t.cfg.FromStart:
		return "from-exec"
	default:
		return "attached"
	}
}

// Run ejecuta el aprendizaje y persiste la traza.
func (t *Tracer) Run() (err error) {
	if err := t.validate(); err != nil {
		return err
	}
	pid := t.cfg.PID
	containerID := ""
	if t.cfg.FromStart {
		containerID, err = t.runtime.Create(t.cfg.Image, t.cfg.CreateArgs)
		if err != nil {
			return fmt.Errorf("crear contenedor: %w", err)
		}
		if !t.cfg.Keep {
			defer func() {
				if rmErr := t.runtime.Remove(containerID); rmErr != nil && err == nil {
					err = fmt.Errorf("borrar contenedor %s: %w", containerID, rmErr)
				}
			}()
		}
		pid, err = t.runtime.Init(containerID)
		if err != nil {
			return fmt.Errorf("inicializar contenedor: %w", err)
		}
	} else if t.cfg.PID > 0 {
		fmt.Fprintln(t.warn, "learn: aviso: --pid se adjunta a un contenedor ya arrancado; sus syscalls de arranque (execve, carga de bibliotecas, bind, setuid) no quedan en la traza y un perfil derivado puede impedir que el contenedor arranque. Preferir --from-start.")
	}

	probe := t.newProbe(pid)
	// Big enough for a startup burst: the probe refuses to block and fails
	// the trace instead of dropping events when this fills up.
	events := make(chan models.SyscallEvent, 1<<16)
	raised := make(chan error, 1)
	go func() { raised <- probe.Attach(t.cfg.Image, events) }()

	select {
	case err := <-probe.Ready():
		if err != nil {
			probe.Detach()
			drain(events)
			<-raised
			return fmt.Errorf("activar captura: %w", err)
		}
	case <-time.After(t.attachTO):
		probe.Detach()
		drain(events)
		<-raised
		return errors.New("la captura no se activó a tiempo")
	}

	file, err := os.Create(t.cfg.Output + ".tmp")
	if err != nil {
		probe.Detach()
		drain(events)
		<-raised
		return fmt.Errorf("crear traza: %w", err)
	}
	defer os.Remove(t.cfg.Output + ".tmp")

	type result struct {
		count int
		err   error
	}
	written := make(chan result, 1)
	go func() {
		enc := json.NewEncoder(file)
		count := 0
		// From-start: the container's init process runs runtime setup code
		// after `start` and before it execs the entrypoint; the profile only
		// applies from that execve on, so earlier syscalls are left out.
		started := !t.cfg.FromStart
		for evt := range events {
			if !started {
				if !evt.IsExec() {
					continue
				}
				started = true
			}
			evt.CaptureMode = t.captureMode()
			if err := enc.Encode(evt); err != nil {
				probe.Detach()
				drain(events)
				written <- result{count, fmt.Errorf("escribir evento: %w", err)}
				return
			}
			count++
		}
		written <- result{count, nil}
	}()

	if t.cfg.FromStart {
		if err := t.runtime.Start(containerID); err != nil {
			probe.Detach()
			<-written
			<-raised
			file.Close()
			return fmt.Errorf("arrancar contenedor: %w", err)
		}
	}
	time.Sleep(t.cfg.Duration)
	probe.Detach()

	res := <-written
	if err := <-raised; err != nil {
		file.Close()
		return err
	}
	if res.err != nil {
		file.Close()
		return res.err
	}
	if res.count == 0 {
		file.Close()
		if t.cfg.FromStart {
			return fmt.Errorf("no se observó el execve del contenedor ni syscalls posteriores; no se guarda una traza vacía")
		}
		return fmt.Errorf("no se observaron syscalls; no se guarda una traza vacía")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(t.cfg.Output+".tmp", t.cfg.Output)
}

func drain(events <-chan models.SyscallEvent) {
	for range events {
	}
}
