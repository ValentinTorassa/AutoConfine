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
