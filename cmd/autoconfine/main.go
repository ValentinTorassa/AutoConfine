package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ValentinTorassa/autoconfine/internal/config"
	"github.com/ValentinTorassa/autoconfine/internal/drift"
	"github.com/ValentinTorassa/autoconfine/internal/enforce"
	"github.com/ValentinTorassa/autoconfine/internal/generate"
	"github.com/ValentinTorassa/autoconfine/internal/learn"
	"github.com/ValentinTorassa/autoconfine/internal/profile"
	"github.com/ValentinTorassa/autoconfine/internal/traceio"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "learn":
		os.Exit(runLearn(os.Args[2:]))
	case "generate":
		os.Exit(runGenerate(os.Args[2:]))
	case "enforce":
		os.Exit(runEnforce(os.Args[2:]))
	case "summary":
		os.Exit(runSummary(os.Args[2:]))
	case "validate":
		os.Exit(runValidate(os.Args[2:]))
	case "compare":
		os.Exit(runCompare(os.Args[2:]))
	case "drift":
		os.Exit(runDrift(os.Args[2:]))
	case "merge":
		os.Exit(runMerge(os.Args[2:]))
	case "version":
		fmt.Println("autoconfine", config.Version)
		os.Exit(0)
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "Uso: autoconfine <learn|generate|enforce|summary|validate|compare|drift|merge|version> [opciones]")
}

func runDrift(args []string) int {
	fs := flag.NewFlagSet("drift", flag.ExitOnError)
	path := fs.String("profile", "", "perfil seccomp de referencia")
	allowSynthetic := fs.Bool("allow-synthetic", false, "aceptar una traza simulada solo para pruebas")
	pos, _ := parseArgs(fs, args)
	if *path == "" || len(pos) != 1 {
		fmt.Fprintln(os.Stderr, "drift: usar --profile perfil.json traza.jsonl")
		return 1
	}
	allowed, err := profile.AllowedSyscalls(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "drift: %v\n", err)
		return 1
	}
	events, err := traceio.ReadEvents(pos[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "drift: %v\n", err)
		return 1
	}
	if len(events) == 0 {
		fmt.Fprintln(os.Stderr, "drift: empty trace")
		return 1
	}
	for _, event := range events {
		if event.Phase != "observed-ebpf" && !*allowSynthetic {
			fmt.Fprintln(os.Stderr, "drift: trace is not observed-ebpf (use --allow-synthetic only for tests)")
			return 1
		}
	}
	set := drift.ProfileSet(allowed)
	reporter := drift.NewJSONReporter(os.Stdout)
	missing := 0
	for _, event := range events {
		if drift.Allowed(set, event.Syscall) {
			continue
		}
		missing++
		if err := reporter.Report(drift.Event{Timestamp: event.Timestamp, Syscall: event.Syscall,
			Image: event.Image, PID: event.PID, Comm: event.Comm, Profile: *path}); err != nil {
			fmt.Fprintf(os.Stderr, "drift: %v\n", err)
			return 1
		}
	}
	fmt.Fprintf(os.Stderr, "drift: %d of %d events outside profile\n", missing, len(events))
	if missing > 0 {
		return 2
	}
	return 0
}

func runLearn(args []string) int {
	fs := flag.NewFlagSet("learn", flag.ExitOnError)
	image := fs.String("image", "", "imagen OCI a observar")
	duration := fs.Duration("duration", 30*time.Second, "duración de la fase de aprendizaje")
	out := fs.String("out", "autoconfine.trace.jsonl", "archivo de traza de salida")
	fromStart := fs.Bool("from-start", false, "crear el contenedor con Podman, adjuntar la sonda y recién entonces arrancarlo (captura el arranque)")
	keep := fs.Bool("keep", false, "con --from-start, no borrar el contenedor al terminar")
	pid := fs.Int("pid", 0, "PID host de un contenedor ya en ejecución (cgroup v2); no captura su arranque")
	synthetic := fs.Bool("synthetic", false, "emitir una traza simulada, explícitamente")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Uso: autoconfine learn --image IMAGEN (--from-start | --pid PID | --synthetic) [--duration 30s] [--out traza.jsonl] [-- ARGS de podman create]")
		fs.PrintDefaults()
	}
	pos, createArgs := parseArgs(fs, args)
	if len(pos) > 0 {
		fmt.Fprintf(os.Stderr, "learn: argumento inesperado %q; las opciones de podman create van después de --\n", pos[0])
		return 1
	}

	cfg := learn.Config{
		Image:      *image,
		Duration:   *duration,
		Output:     *out,
		PID:        *pid,
		FromStart:  *fromStart,
		Synthetic:  *synthetic,
		CreateArgs: createArgs,
		Keep:       *keep,
	}
	if len(cfg.CreateArgs) > 0 && !cfg.FromStart {
		fmt.Fprintln(os.Stderr, "learn: los argumentos después de -- son para podman create y solo valen con --from-start")
		return 1
	}

	tracer := learn.NewTracer(cfg)
	if err := tracer.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "learn: %v\n", err)
		return 1
	}
	fmt.Printf("Traza guardada en %s\n", *out)
	return 0
}

func runGenerate(args []string) int {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	out := fs.String("out", "autoconfine.seccomp.json", "perfil seccomp de salida")
	allowSynthetic := fs.Bool("allow-synthetic", false, "aceptar una traza simulada o sin procedencia, solo para pruebas")
	pos, _ := parseArgs(fs, args)

	if len(pos) != 1 {
		fmt.Fprintln(os.Stderr, "generate: se requiere una ruta de traza")
		return 1
	}

	gen := generate.NewGenerator(generate.Config{AllowSynthetic: *allowSynthetic})
	res, err := gen.Generate(pos[0], *out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate: %v\n", err)
		return 1
	}
	for _, warning := range res.Warnings {
		fmt.Fprintf(os.Stderr, "generate: aviso: %s\n", warning)
	}
	fmt.Printf("Perfil seccomp guardado en %s (%d eventos)\n", *out, res.Events)
	return 0
}

func runEnforce(args []string) int {
	fs := flag.NewFlagSet("enforce", flag.ExitOnError)
	profile := fs.String("profile", "", "ruta al perfil seccomp generado")
	monitor := fs.Bool("monitor", false, "observar el contenedor con eBPF mientras corre y reportar en vivo cada syscall que el perfil deniega (root y Podman)")
	audit := fs.Bool("audit", false, "modo audit: aplicar el perfil con SCMP_ACT_LOG (no bloquea) y reportar en vivo cada syscall fuera de él; implica --monitor")
	out := fs.String("out", "", "con --monitor o --audit, archivo JSONL para los eventos de drift (por defecto stderr)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Uso: autoconfine enforce --profile PERFIL [--monitor | --audit] [--out drift.jsonl] -- podman run [OPCIONES] IMAGEN [COMANDO]")
		fs.PrintDefaults()
	}
	// Everything from the first non-flag on (or after --) is the container
	// command, including its own flags, so no interspersed parsing here.
	fs.Parse(args)
	command := fs.Args()

	if *profile == "" {
		fmt.Fprintln(os.Stderr, "enforce: se requiere --profile")
		return 1
	}
	monitoring := *monitor || *audit
	if *out != "" && !monitoring {
		fmt.Fprintln(os.Stderr, "enforce: --out solo vale con --monitor o --audit")
		return 1
	}
	// stdout belongs to the container, so drift reports go to stderr or --out.
	reporter := drift.NewJSONReporter(os.Stderr)
	if *out != "" {
		file, err := os.Create(*out)
		if err != nil {
			fmt.Fprintf(os.Stderr, "enforce: %v\n", err)
			return 1
		}
		defer file.Close()
		reporter = drift.NewJSONReporter(file)
	}

	cfg := enforce.Config{
		ProfilePath:   *profile,
		Monitor:       monitoring,
		Audit:         *audit,
		DriftReporter: reporter,
	}

	runner := enforce.NewRunner(cfg)
	summary, err := runner.Run(command)
	if err != nil {
		fmt.Fprintf(os.Stderr, "enforce: %v\n", err)
	}
	// Like drift: 2 when a syscall fell outside the profile, even if the
	// container then failed (often because of it).
	if summary != nil && summary.Outside > 0 {
		return 2
	}
	if err != nil {
		return 1
	}
	return 0
}

func runSummary(args []string) int {
	fs := flag.NewFlagSet("summary", flag.ExitOnError)
	defaultAllowed := fs.Int("default-allowed", 304, "syscalls permitidas por el perfil por defecto")
	jsonOut := fs.String("json", "", "guardar análisis como JSON")
	reportOut := fs.String("report", "", "guardar reporte markdown")
	pos, _ := parseArgs(fs, args)

	if len(pos) != 1 {
		fmt.Fprintln(os.Stderr, "summary: se requiere una ruta de traza")
		return 1
	}

	stats, err := profile.AnalyzeTrace(pos[0], *defaultAllowed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "summary: %v\n", err)
		return 1
	}

	fmt.Printf("Syscalls únicas: %d\n", stats.GeneratedAllowed)
	fmt.Printf("Origen de traza: %s (%d eventos)\n", stats.TraceSource, stats.EventsCount)
	fmt.Printf("Reducción vs default (%d): %.2f%%\n", stats.DefaultAllowed, stats.ReductionPercent)

	if *jsonOut != "" {
		if err := profile.WriteReportJSON(stats, *jsonOut); err != nil {
			fmt.Fprintf(os.Stderr, "summary json: %v\n", err)
			return 1
		}
	}
	if *reportOut != "" {
		if err := profile.WriteReport(stats, pos[0], *reportOut); err != nil {
			fmt.Fprintf(os.Stderr, "summary report: %v\n", err)
			return 1
		}
	}
	return 0
}

func runValidate(args []string) int {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	pos, _ := parseArgs(fs, args)

	if len(pos) != 1 {
		fmt.Fprintln(os.Stderr, "validate: se requiere la ruta del perfil seccomp")
		return 1
	}

	if err := profile.ValidateProfile(pos[0]); err != nil {
		fmt.Fprintf(os.Stderr, "validate: %v\n", err)
		return 1
	}
	fmt.Println("Perfil válido")
	return 0
}

func runCompare(args []string) int {
	fs := flag.NewFlagSet("compare", flag.ExitOnError)
	profiles := fs.Bool("profiles", false, "comparar como perfiles seccomp en lugar de trazas")
	pos, _ := parseArgs(fs, args)

	if len(pos) != 2 {
		fmt.Fprintln(os.Stderr, "compare: se requieren dos rutas")
		return 1
	}

	var res *profile.CompareResult
	var err error
	if *profiles {
		res, err = profile.CompareProfiles(pos[0], pos[1])
	} else {
		res, err = profile.CompareTraces(pos[0], pos[1])
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "compare: %v\n", err)
		return 1
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(res); err != nil {
		fmt.Fprintf(os.Stderr, "compare: %v\n", err)
		return 1
	}
	return 0
}

func runMerge(args []string) int {
	fs := flag.NewFlagSet("merge", flag.ExitOnError)
	out := fs.String("out", "merged.trace.jsonl", "ruta de salida")
	pos, _ := parseArgs(fs, args)

	if len(pos) < 2 {
		fmt.Fprintln(os.Stderr, "merge: se requieren al menos dos trazas")
		return 1
	}

	if err := profile.MergeTraces(pos, *out); err != nil {
		fmt.Fprintf(os.Stderr, "merge: %v\n", err)
		return 1
	}
	fmt.Printf("Traza combinada guardada en %s\n", *out)
	return 0
}
