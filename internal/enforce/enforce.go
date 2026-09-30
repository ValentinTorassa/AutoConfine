package enforce

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ValentinTorassa/autoconfine/internal/drift"
)

// Config define parámetros de ejecución protegida.
type Config struct {
	ProfilePath   string
	Audit         bool
	DriftReporter drift.Reporter
}

// Runner ejecuta Podman con un perfil seccomp.
type Runner struct {
	cfg Config
}

// NewRunner crea un runner.
func NewRunner(cfg Config) *Runner {
	return &Runner{cfg: cfg}
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
	argv := append([]string{"run", "--security-opt", "seccomp=" + profile}, rest...)
	return bin, argv, nil
}

// Run ejecuta el contenedor con el perfil aplicado.
func (r *Runner) Run(args []string) error {
	info, err := os.Stat(r.cfg.ProfilePath)
	if err != nil {
		return fmt.Errorf("perfil no encontrado: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("la ruta del perfil es un directorio")
	}
	bin, argv, err := command(r.cfg.ProfilePath, args)
	if err != nil {
		return err
	}
	cmd := exec.Command(bin, argv...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if r.cfg.Audit {
		if err := r.reportAuditHeader(); err != nil {
			return err
		}
	}

	return cmd.Run()
}

func (r *Runner) reportAuditHeader() error {
	return r.cfg.DriftReporter.Report(drift.Event{Syscall: "audit_mode_enabled"})
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
