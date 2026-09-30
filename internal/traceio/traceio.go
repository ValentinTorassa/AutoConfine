package traceio

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/ValentinTorassa/autoconfine/internal/models"
)

// ReadSyscalls lee una traza JSONL y devuelve el conjunto de syscalls únicas.
func ReadSyscalls(path string) (map[string]int, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("abrir traza: %w", err)
	}
	defer file.Close()
	return scanSyscalls(file)
}

// scanSyscalls cuenta syscalls desde cualquier reader.
func scanSyscalls(r io.Reader) (map[string]int, error) {
	counts := make(map[string]int)
	sc := bufio.NewScanner(r)
	malformed := 0
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		// A fresh value per line, so a line without "syscall" cannot inherit
		// the previous line's name.
		var evt struct {
			Syscall string `json:"syscall"`
		}
		if err := json.Unmarshal(sc.Bytes(), &evt); err != nil || evt.Syscall == "" {
			malformed++
			continue
		}
		counts[evt.Syscall]++
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("leer traza: %w", err)
	}
	reportMalformed(malformed)
	return counts, nil
}

// Malformed is where skipped-line notices go; tests can silence it.
var Malformed io.Writer = os.Stderr

func reportMalformed(n int) {
	if n > 0 {
		fmt.Fprintf(Malformed, "traceio: %d líneas malformadas o sin syscall se ignoraron\n", n)
	}
}

// ReadEvents lee todos los eventos de una traza.
func ReadEvents(path string) ([]models.SyscallEvent, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("abrir traza: %w", err)
	}
	defer file.Close()

	var events []models.SyscallEvent
	sc := bufio.NewScanner(file)
	malformed := 0
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var evt models.SyscallEvent
		if err := json.Unmarshal(sc.Bytes(), &evt); err != nil {
			malformed++
			continue
		}
		events = append(events, evt)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("leer eventos: %w", err)
	}
	reportMalformed(malformed)
	return events, nil
}

// WriteEvents escribe eventos como JSONL.
func WriteEvents(path string, events []models.SyscallEvent) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("crear traza: %w", err)
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	for _, evt := range events {
		if err := enc.Encode(evt); err != nil {
			return fmt.Errorf("escribir evento: %w", err)
		}
	}
	return nil
}

// UniqueSyscalls devuelve la lista ordenada de syscalls distintas.
func UniqueSyscalls(counts map[string]int) []string {
	seen := make([]string, 0, len(counts))
	for name := range counts {
		seen = append(seen, name)
	}
	// Inserción simple; suficiente para perfiles pequeños.
	for i := 1; i < len(seen); i++ {
		j := i
		for j > 0 && seen[j-1] > seen[j] {
			seen[j-1], seen[j] = seen[j], seen[j-1]
			j--
		}
	}
	return seen
}
