package enforce

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	content := `{"defaultAction":"SCMP_ACT_ERRNO","architectures":["SCMP_ARCH_X86_64"]}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	profile, err := LoadProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if profile["defaultAction"] != "SCMP_ACT_ERRNO" {
		t.Fatalf("defaultAction = %v", profile["defaultAction"])
	}
}

func TestRunnerMissingProfile(t *testing.T) {
	r := NewRunner(Config{ProfilePath: "/no/existe.json"})
	_, err := r.Run([]string{"podman", "run", "nginx"})
	if err == nil {
		t.Fatal("se esperaba error por perfil inexistente")
	}
}

// The README and Makefile document `enforce --profile p -- podman run --rm
// nginx`; that exact argv used to become `podman run --security-opt ... run
// --rm nginx`, so "run" was taken as the image.
func TestCommandForDocumentedForm(t *testing.T) {
	bin, argv, err := command("nginx.seccomp.json", []string{"podman", "run", "--rm", "nginx"})
	if err != nil {
		t.Fatal(err)
	}
	if bin != "podman" || strings.Join(argv, " ") != "run --security-opt seccomp=nginx.seccomp.json --rm nginx" {
		t.Fatalf("%s %v", bin, argv)
	}
}

func TestCommandAcceptsShorterForms(t *testing.T) {
	want := "run --security-opt seccomp=p.json --rm nginx"
	for _, args := range [][]string{
		{"podman", "--rm", "nginx"},
		{"run", "--rm", "nginx"},
		{"--rm", "nginx"},
		{"/usr/bin/podman", "run", "--rm", "nginx"},
	} {
		_, argv, err := command("p.json", args)
		if err != nil || strings.Join(argv, " ") != want {
			t.Errorf("%v -> %v %v", args, argv, err)
		}
	}
	if bin, _, _ := command("p.json", []string{"docker", "run", "alpine"}); bin != "docker" {
		t.Errorf("docker kept as runtime, got %s", bin)
	}
}

func TestCommandRefusesMissingImageAndSecondProfile(t *testing.T) {
	for _, args := range [][]string{nil, {"podman"}, {"podman", "run"}, {"podman", "run", "--security-opt", "seccomp=other.json", "nginx"}, {"run", "--security-opt=seccomp=x.json", "nginx"}} {
		if _, _, err := command("p.json", args); err == nil {
			t.Errorf("%v should be refused", args)
		}
	}
}
