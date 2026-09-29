package generate

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Config define parámetros de generación.
type Config struct {
	DefaultAction string
}

// Generator transforma trazas en perfiles seccomp.
type Generator struct {
	cfg Config
}

// NewGenerator crea un generador con configuración por defecto.
func NewGenerator(cfg Config) *Generator {
	if cfg.DefaultAction == "" {
		cfg.DefaultAction = "SCMP_ACT_ERRNO"
	}
	return &Generator{cfg: cfg}
}

// SeccompProfile es un subconjunto mínimo del esquema OCI.
type SeccompProfile struct {
	DefaultAction string    `json:"defaultAction"`
	Architectures []string  `json:"architectures"`
	Syscalls      []Syscall `json:"syscalls"`
}

// Syscall representa una regla del perfil.
type Syscall struct {
	Names  []string `json:"names"`
	Action string   `json:"action"`
}

// Generate lee una traza JSONL y escribe un perfil seccomp.
func (g *Generator) Generate(tracePath, outPath string) error {
	file, err := os.Open(tracePath)
	if err != nil {
		return fmt.Errorf("abrir traza: %w", err)
	}
	defer file.Close()

	seen := make(map[string]struct{})
	sc := bufio.NewScanner(file)
	var raw map[string]interface{}
	for sc.Scan() {
		if err := json.Unmarshal(sc.Bytes(), &raw); err != nil {
			continue // mejorar: logear eventos malformados
		}
		if name, ok := raw["syscall"].(string); ok {
			seen[name] = struct{}{}
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("leer traza: %w", err)
	}
	if len(seen) == 0 {
		return fmt.Errorf("la traza no contiene syscalls")
	}

	syscalls := make([]string, 0, len(seen))
	for s := range seen {
		if strings.HasPrefix(s, "syscall_") {
			return fmt.Errorf("syscall %s no tiene nombre seccomp conocido; revisar la traza antes de generar", s)
		}
		syscalls = append(syscalls, s)
	}
	sort.Strings(syscalls)

	profile := SeccompProfile{
		DefaultAction: g.cfg.DefaultAction,
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []Syscall{
			{
				Names:  syscalls,
				Action: "SCMP_ACT_ALLOW",
			},
		},
	}

	out, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("crear perfil: %w", err)
	}
	defer out.Close()

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(profile)
}
