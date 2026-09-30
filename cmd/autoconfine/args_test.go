package main

import (
	"flag"
	"strings"
	"testing"
)

func TestParseArgsAcceptsFlagsAfterPositionals(t *testing.T) {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	out := fs.String("out", "default.json", "")
	allow := fs.Bool("allow-synthetic", false, "")
	pos, pass := parseArgs(fs, []string{"trace.jsonl", "--out", "p.json", "--allow-synthetic"})
	if *out != "p.json" || !*allow || strings.Join(pos, ",") != "trace.jsonl" || len(pass) != 0 {
		t.Fatalf("out=%s allow=%v pos=%v pass=%v", *out, *allow, pos, pass)
	}
}

func TestParseArgsKeepsEverythingAfterDoubleDash(t *testing.T) {
	fs := flag.NewFlagSet("enforce", flag.ContinueOnError)
	profile := fs.String("profile", "", "")
	pos, pass := parseArgs(fs, []string{"--profile", "p.json", "--", "podman", "run", "--rm", "-p", "80:80", "nginx"})
	if *profile != "p.json" || len(pos) != 0 || strings.Join(pass, " ") != "podman run --rm -p 80:80 nginx" {
		t.Fatalf("profile=%s pos=%v pass=%v", *profile, pos, pass)
	}
}
