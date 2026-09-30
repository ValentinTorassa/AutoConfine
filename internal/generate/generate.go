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
	// AllowSynthetic acepta trazas que no se observaron con eBPF (solo pruebas),
	// igual que `drift --allow-synthetic`.
	AllowSynthetic bool
}

// Result describe lo que se usó de la traza y lo que conviene revisar.
type Result struct {
	Events    int
	Malformed int
	Warnings  []string
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
func (g *Generator) Generate(tracePath, outPath string) (*Result, error) {
	file, err := os.Open(tracePath)
	if err != nil {
		return nil, fmt.Errorf("abrir traza: %w", err)
	}
	defer file.Close()

	res := &Result{}
	seen := make(map[string]struct{})
	notObserved := make(map[string]int)
	attached := 0
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if len(strings.TrimSpace(sc.Text())) == 0 {
			continue
		}
		// A fresh value per line: reusing one map let a line without
		// "syscall" inherit the previous line's name.
		var evt struct {
			Syscall     string `json:"syscall"`
			Phase       string `json:"phase"`
			CaptureMode string `json:"capture_mode"`
		}
		if err := json.Unmarshal(sc.Bytes(), &evt); err != nil || evt.Syscall == "" {
			res.Malformed++
			continue
		}
		res.Events++
		seen[evt.Syscall] = struct{}{}
		if evt.Phase != "observed-ebpf" {
			phase := evt.Phase
			if phase == "" {
				phase = "sin procedencia"
			}
			notObserved[phase]++
		}
		if evt.CaptureMode == "attached" {
			attached++
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("leer traza: %w", err)
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("la traza no contiene syscalls")
	}
	if len(notObserved) > 0 {
		kinds := make([]string, 0, len(notObserved))
		for phase, n := range notObserved {
			kinds = append(kinds, fmt.Sprintf("%d %s", n, phase))
		}
		sort.Strings(kinds)
		if !g.cfg.AllowSynthetic {
			return nil, fmt.Errorf("la traza tiene eventos no observados con eBPF (%s); un perfil así no describe al contenedor. Usar --allow-synthetic solo para pruebas", strings.Join(kinds, ", "))
		}
		res.Warnings = append(res.Warnings, fmt.Sprintf("perfil de prueba: incluye eventos no observados (%s); no usarlo para confinar un contenedor real", strings.Join(kinds, ", ")))
	}
	if attached > 0 {
		res.Warnings = append(res.Warnings, "la traza se tomó adjuntándose a un contenedor ya arrancado (--pid): faltan sus syscalls de arranque y el perfil puede impedir que arranque; repetir con learn --from-start")
	}
	if res.Malformed > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%d líneas malformadas o sin syscall se ignoraron", res.Malformed))
	}

	syscalls := make([]string, 0, len(seen))
	for s := range seen {
		if strings.HasPrefix(s, "syscall_") {
			return nil, fmt.Errorf("syscall %s no tiene nombre seccomp conocido; revisar la traza antes de generar", s)
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
		return nil, fmt.Errorf("crear perfil: %w", err)
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(profile); err != nil {
		out.Close()
		return nil, err
	}
	return res, out.Close()
}
