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

func TestSplitCommandSeparatesCreateOptionsFromCommand(t *testing.T) {
	create, command := splitCommand([]string{"-p", "8080:80", "--", "sh", "-c", "x", "--", "y"})
	if strings.Join(create, " ") != "-p 8080:80" || strings.Join(command, " ") != "sh -c x -- y" {
		t.Fatalf("create=%v command=%v", create, command)
	}
	create, command = splitCommand([]string{"-p", "8080:80"})
	if strings.Join(create, " ") != "-p 8080:80" || command != nil {
		t.Fatalf("without a second -- everything is a create option: create=%v command=%v", create, command)
	}
	create, command = splitCommand([]string{"--", "true"})
	if len(create) != 0 || strings.Join(command, " ") != "true" {
		t.Fatalf("command only: create=%v command=%v", create, command)
	}
}
