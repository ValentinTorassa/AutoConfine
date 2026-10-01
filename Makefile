.PHONY: build test vet bpf bpf-check clean run-learn run-learn-pid run-generate run-enforce run-monitor run-audit

BINARY := autoconfine
CMD := ./cmd/autoconfine
CLANG ?= clang
BPF_SRC := internal/bpf/syscalls.bpf.c
BPF_OBJ := internal/bpf/syscalls_bpfel.o

build:
	go build -o $(BINARY) $(CMD)

test:
	go test -race ./...

vet:
	go vet ./...

# The object is committed so `go install` needs no clang. It is built from the
# source directory with a relative path and -fdebug-prefix-map, so no absolute
# build path ends up in the debug info and the same clang produces the same
# bytes anywhere (CI rebuilds it with Debian trixie's clang 19 and compares).
bpf:
	cd internal/bpf && $(CLANG) -O2 -g -target bpf -fdebug-prefix-map=$$(pwd)=. \
		-fno-ident -c syscalls.bpf.c -o syscalls_bpfel.o

bpf-check: bpf
	git diff --exit-code -- $(BPF_OBJ)

clean:
	rm -f $(BINARY) *.trace.jsonl *.seccomp.json coverage.out

# Needs root (or CAP_BPF + CAP_PERFMON) and Podman: creates the container,
# attaches before it starts, and removes it afterwards.
run-learn: build
	sudo ./$(BINARY) learn --image nginx --from-start --duration 10s --out nginx.trace.jsonl

# Attach to an already running container (misses its startup syscalls).
run-learn-pid: build
	@test -n "$(PID)" || { echo "usage: make run-learn-pid PID=<host pid of the container>"; exit 1; }
	sudo ./$(BINARY) learn --image nginx --pid $(PID) --duration 10s --out nginx.trace.jsonl

run-generate: build
	./$(BINARY) generate nginx.trace.jsonl --out nginx.seccomp.json

run-enforce: build
	./$(BINARY) enforce --profile nginx.seccomp.json -- podman run --rm nginx

# Needs root (or CAP_BPF + CAP_PERFMON) and Podman: runs nginx under the
# profile and reports each syscall it denies as it happens. Ctrl-C stops
# nginx and prints the summary; the exit code is 2 if anything was denied.
run-monitor: build
	sudo ./$(BINARY) enforce --profile nginx.seccomp.json --monitor -- podman run --rm nginx

# Same, but the profile only logs (SCMP_ACT_LOG), so nothing is denied.
run-audit: build
	sudo ./$(BINARY) enforce --profile nginx.seccomp.json --audit -- podman run --rm nginx
