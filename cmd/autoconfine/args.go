package main

import "flag"

// parseArgs parses flags wherever they appear before a "--", so the documented
// `generate traza.jsonl --out perfil.json` works (the flag package alone stops
// at the first positional argument and would ignore --out). It returns the
// positional arguments and, separately, everything after "--" untouched.
func parseArgs(fs *flag.FlagSet, args []string) (positional, passthrough []string) {
	for i, arg := range args {
		if arg == "--" {
			args, passthrough = args[:i], args[i+1:]
			break
		}
	}
	for {
		_ = fs.Parse(args) // ExitOnError: a bad flag exits with usage
		args = fs.Args()
		if len(args) == 0 {
			return positional, passthrough
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

// splitCommand separates learn's passthrough arguments at the next "--":
// `podman create` options before it, the container command after it, so
// `learn ... -- -p 8080:80 -- nginx -g 'daemon off;'` creates the container
// with that command instead of the image's. Any later "--" is part of the
// command.
func splitCommand(passthrough []string) (createArgs, command []string) {
	for i, arg := range passthrough {
		if arg == "--" {
			return passthrough[:i], passthrough[i+1:]
		}
	}
	return passthrough, nil
}
