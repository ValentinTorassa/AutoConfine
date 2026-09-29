package profile

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ValentinTorassa/autoconfine/internal/traceio"
)

// Stats resume el análisis de reducción de syscalls.
type Stats struct {
	DefaultAllowed   int      `json:"default_allowed"`
	GeneratedAllowed int      `json:"generated_allowed"`
	ReductionPercent float64  `json:"reduction_percent"`
	UniqueSyscalls   []string `json:"unique_syscalls"`
	TraceSource      string   `json:"trace_source"`
	EventsCount      int      `json:"events_count"`
}

// AnalyzeTrace compara syscalls de una traza contra un perfil por defecto.
func AnalyzeTrace(tracePath string, defaultAllowed int) (*Stats, error) {
	events, err := traceio.ReadEvents(tracePath)
	if err != nil {
		return nil, fmt.Errorf("analyze trace: %w", err)
	}
	counts := make(map[string]int)
	source := "unknown"
	for i, event := range events {
		if event.Syscall == "" {
			continue
		}
		counts[event.Syscall]++
		phase := event.Phase
		if phase == "" {
			phase = "unknown"
		}
		if i == 0 {
			source = phase
		} else if source != phase {
			source = "mixed"
		}
	}
	unique := traceio.UniqueSyscalls(counts)
	reduction := 0.0
	if defaultAllowed > 0 {
		reduction = float64(defaultAllowed-len(unique)) / float64(defaultAllowed) * 100
	}
	return &Stats{
		DefaultAllowed:   defaultAllowed,
		GeneratedAllowed: len(unique),
		ReductionPercent: reduction,
		UniqueSyscalls:   unique,
		TraceSource:      source,
		EventsCount:      len(events),
	}, nil
}

// WriteReport genera un reporte markdown de análisis.
func WriteReport(stats *Stats, tracePath, outPath string) error {
	file, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("crear reporte: %w", err)
	}
	defer file.Close()

	fmt.Fprintf(file, "# Reporte de análisis - AutoConfine\n\n")
	fmt.Fprintf(file, "- **Traza analizada:** `%s`\n", tracePath)
	fmt.Fprintf(file, "- **Origen declarado:** %s (%d eventos)\n", stats.TraceSource, stats.EventsCount)
	fmt.Fprintf(file, "- **Syscalls permitidas por defecto:** %d\n", stats.DefaultAllowed)
	fmt.Fprintf(file, "- **Syscalls en perfil generado:** %d\n", stats.GeneratedAllowed)
	fmt.Fprintf(file, "- **Reducción:** %.2f%%\n\n", stats.ReductionPercent)
	fmt.Fprintln(file, "La reducción compara nombres vistos en esta muestra con un número de referencia; no demuestra cobertura completa ni seguridad del perfil.")
	fmt.Fprintln(file)
	fmt.Fprintf(file, "## Syscalls permitidas\n\n")
	for _, s := range stats.UniqueSyscalls {
		fmt.Fprintf(file, "- `%s`\n", s)
	}
	return nil
}

// WriteReportJSON escribe el análisis como JSON.
func WriteReportJSON(stats *Stats, outPath string) error {
	data, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outPath, data, 0644)
}
