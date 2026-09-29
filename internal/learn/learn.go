package learn

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ValentinTorassa/autoconfine/internal/bpf"
	"github.com/ValentinTorassa/autoconfine/internal/models"
)

// Config define parámetros de la fase de aprendizaje.
type Config struct {
	Image     string
	Duration  time.Duration
	Output    string
	PID       int
	Synthetic bool
}

// Tracer encapsula la observación de syscalls.
type Tracer struct {
	cfg Config
	bpf bpf.Probe
}

// NewTracer crea un nuevo tracer.
func NewTracer(cfg Config) *Tracer {
	var probe bpf.Probe = bpf.NewEBPFProbe(cfg.PID)
	if cfg.Synthetic {
		probe = bpf.NewNoopProbe()
	}
	return &Tracer{
		cfg: cfg,
		bpf: probe,
	}
}

// Run ejecuta el aprendizaje y persiste la traza.
func (t *Tracer) Run() error {
	if t.cfg.Image == "" {
		return fmt.Errorf("se requiere --image")
	}
	if !t.cfg.Synthetic && t.cfg.PID <= 0 {
		return fmt.Errorf("se requiere --pid del contenedor en ejecución")
	}
	if t.cfg.Duration <= 0 {
		return fmt.Errorf("--duration debe ser positivo")
	}

	raised := make(chan error, 1)
	events := make(chan models.SyscallEvent, 1024)

	go func() {
		raised <- t.bpf.Attach(t.cfg.Image, events)
	}()

	go func() {
		time.Sleep(t.cfg.Duration)
		t.bpf.Detach()
	}()

	file, err := os.Create(t.cfg.Output + ".tmp")
	if err != nil {
		return fmt.Errorf("crear traza: %w", err)
	}
	defer os.Remove(t.cfg.Output + ".tmp")

	enc := json.NewEncoder(file)
	count := 0
	for evt := range events {
		if err := enc.Encode(evt); err != nil {
			file.Close()
			return fmt.Errorf("escribir evento: %w", err)
		}
		count++
	}

	if err := <-raised; err != nil {
		file.Close()
		return err
	}
	if count == 0 {
		file.Close()
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
