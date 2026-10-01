package enforce

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ValentinTorassa/autoconfine/internal/bpf"
	"github.com/ValentinTorassa/autoconfine/internal/drift"
	"github.com/ValentinTorassa/autoconfine/internal/podman"
)

// Config define parámetros de ejecución protegida.
type Config struct {
	ProfilePath string
	// Monitor observa el contenedor con eBPF mientras corre con el perfil y
	// reporta en vivo cada syscall fuera de él (root y Podman).
	Monitor bool
	// Audit aplica el perfil con SCMP_ACT_LOG como acción por defecto: una
	// syscall fuera del perfil se ejecuta y queda registrada en lugar de
	// fallar. Implica Monitor.
	Audit         bool
	DriftReporter drift.Reporter
}

// Runner ejecuta Podman con un perfil seccomp.
type Runner struct {
	cfg       Config
	container func(bin string) Container
	newProbe  func(pid int, hook bpf.Hook) bpf.Probe
	log       io.Writer
	attachTO  time.Duration
}

// NewRunner crea un runner.
func NewRunner(cfg Config) *Runner {
	return &Runner{
		cfg:       cfg,
		container: func(bin string) Container { return podman.CLI{Bin: bin} },
		newProbe: func(pid int, hook bpf.Hook) bpf.Probe {
			probe := bpf.NewEBPFProbe(pid)
			probe.Hook = hook
			return probe
		},
		log:      os.Stderr,
		attachTO: 30 * time.Second,
	}
}

// command arma la invocación del runtime con el perfil aplicado. Acepta:
//
//	podman run --rm nginx   (la forma documentada)
//	podman --rm nginx       (sin "run")
//	run --rm nginx          (runtime por defecto: podman)
//	--rm nginx              (solo argumentos de run)
//
// y siempre inserta --security-opt seccomp=PERFIL justo después de "run".
func command(profile string, args []string) (string, []string, error) {
	bin, rest, err := split(args)
	if err != nil {
		return "", nil, err
	}
	argv := append([]string{"run", "--security-opt", "seccomp=" + profile}, rest...)
	return bin, argv, nil
}

// split separa el runtime (podman por defecto) de los argumentos de run
// (opciones, imagen y comando), en cualquiera de las formas de command.
func split(args []string) (string, []string, error) {
	if len(args) == 0 {
		return "", nil, fmt.Errorf("se requiere el comando del contenedor, p. ej. -- podman run --rm IMAGEN")
	}
	bin, rest := "podman", args
	if base := filepath.Base(args[0]); base == "podman" || base == "docker" {
		bin, rest = args[0], args[1:]
	}
	if len(rest) > 0 && rest[0] == "run" {
		rest = rest[1:]
	}
	if len(rest) == 0 {
		return "", nil, fmt.Errorf("falta la imagen a ejecutar")
	}
	for i, arg := range rest {
		if strings.HasPrefix(arg, "seccomp=") && i > 0 && rest[i-1] == "--security-opt" ||
			strings.HasPrefix(arg, "--security-opt=seccomp=") {
			return "", nil, fmt.Errorf("el comando ya trae un perfil seccomp (%s); quitarlo para aplicar el generado", arg)
		}
	}
	return bin, rest, nil
}

// Run ejecuta el contenedor con el perfil aplicado. Con Monitor o Audit
// devuelve además lo que observó el monitoreo (nil si no llegó a arrancarlo).
func (r *Runner) Run(args []string) (*drift.Summary, error) {
	info, err := os.Stat(r.cfg.ProfilePath)
	if err != nil {
		return nil, fmt.Errorf("perfil no encontrado: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("la ruta del perfil es un directorio")
	}
	if r.cfg.Monitor || r.cfg.Audit {
		return r.monitor(args)
	}
	bin, argv, err := command(r.cfg.ProfilePath, args)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(bin, argv...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return nil, cmd.Run()
}

// LoadProfile lee un perfil seccomp desde disco.
func LoadProfile(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var profile map[string]interface{}
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil, err
	}
	return profile, nil
}
