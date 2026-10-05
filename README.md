# AutoConfine

[![Go Report Card](https://goreportcard.com/badge/github.com/ValentinTorassa/autoconfine)](https://goreportcard.com/report/github.com/ValentinTorassa/autoconfine)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

[Español](README.es.md) | **English**

**AutoConfine** builds least-privilege seccomp profiles for [OCI](https://opencontainers.org/) containers from what the container actually does. An eBPF probe records every syscall a container makes from its entrypoint's `execve` on; AutoConfine turns that trace into a profile that allows only those syscalls, compares and merges traces from several runs, and watches a running container for syscalls its profile does not allow, including the ones the profile is already denying. A GitHub Action runs the whole loop in CI while your tests exercise the container.

Container runtimes apply a default seccomp profile that allows hundreds of syscalls ([Podman's upstream default profile](https://github.com/containers/container-libs/blob/45bfa0b68bf93bd6eba219cac2bcecd88353196f/common/pkg/seccomp/seccomp.json) allows 413 syscall names); most services use far fewer. AutoConfine measures that gap for your container and gives you a starting profile that narrows it.

## Status

Prototype. Generating, validating, comparing and merging need no privileges (CI also builds the tool for macOS). The eBPF capture and the live drift monitor run on Linux amd64 with Podman, and were exercised end to end on a disposable GitHub runner on 2026-10-01 ([drill run](https://github.com/ValentinTorassa/AutoConfine/actions/runs/36905476621), [script](scripts/live-ebpf-drill.sh)):

- `learn --from-start` recorded **2443 events** of an `nginx:alpine` startup, `execve` included, all labelled `observed-ebpf` and `from-exec`; `generate` produced a profile that `validate` accepted.
- Running `id` in the same image under test profiles with four identity syscalls removed produced **20 drift events** with `enforce --audit` (starting from the learned nginx profile) and **8** with `enforce --monitor` (starting from Podman's default profile); both exited with code 2 as intended.
- The same drill found the main limit described under [Limits](#limits): a profile learned from one short run stopped `podman init` from starting a container (`crun: cannot setresgid to 0: Operation not permitted`).

The [GitHub Action](#github-action) is new and is exercised by the [Action demo workflow](.github/workflows/action-demo.yml) on the same runner image. A public lab, [Seccomp: observe a toy workload before blocking](https://github.com/ValentinTorassa/Open-Security-Labs/blob/main/src/content/labs/ciberseguridad/seccomp-observar-antes-de-bloquear.mdx) (in Spanish), walks through capture, provenance review and audit mode on a disposable VM.

The CLI's messages and flag help are in Spanish for now.

## Quick start

### CLI

```bash
go install github.com/ValentinTorassa/autoconfine/cmd/autoconfine@latest
```

The eBPF object is precompiled and embedded, so installing needs no clang or kernel headers. Capture and live monitoring need:

- Linux amd64 with cgroup v2, raw tracepoints, the BPF ring buffer and `bpf_get_current_ancestor_cgroup_id` for tracing programs (roughly kernel 5.10 or later).
- Root, or `CAP_BPF` + `CAP_PERFMON`.
- Podman 4.0 or later. Docker has no equivalent of `podman init`, so with Docker only `learn --pid` (without the startup) and plain `enforce` are available.

```bash
# 1. Learn: create the container, attach the probe, then start it. Options after
#    the first -- go to `podman create`; a second -- gives the container command.
#    --duration is the upper bound: Ctrl-C (SIGINT) or SIGTERM ends the capture
#    early, saves the trace and removes the container.
sudo autoconfine learn --image docker.io/library/nginx:alpine --from-start \
  --duration 5m --out nginx.trace.jsonl -- -p 8080:80

# 2. Learn again while exercising other paths, then merge the runs.
sudo autoconfine learn --image docker.io/library/nginx:alpine --from-start \
  --duration 5m --out nginx-2.trace.jsonl -- -p 8080:80 -- nginx -g 'daemon off;'
autoconfine merge nginx.trace.jsonl nginx-2.trace.jsonl --out merged.trace.jsonl

# 3. Generate and check the profile; compare it with Podman's default.
autoconfine generate merged.trace.jsonl --out nginx.seccomp.json
autoconfine validate nginx.seccomp.json
autoconfine compare --profiles /usr/share/containers/seccomp.json nginx.seccomp.json

# 4. Watch it live before relying on it: --audit only logs (nothing is denied),
#    --monitor enforces and reports each denied syscall as it happens.
sudo autoconfine enforce --profile nginx.seccomp.json --audit --out drift.jsonl -- podman run --rm -p 8080:80 docker.io/library/nginx:alpine
sudo autoconfine enforce --profile nginx.seccomp.json --monitor --out drift.jsonl -- podman run --rm -p 8080:80 docker.io/library/nginx:alpine

# 5. Offline drift: which syscalls in a new trace fall outside the profile (exit 2 if any).
autoconfine drift --profile nginx.seccomp.json nginx-3.trace.jsonl
```

Before step 4 matters in production, read [Limits](#limits): a profile learned only from the entrypoint on can block the OCI runtime itself.

| Command | What it does |
|---|---|
| `learn` | Capture a trace. `--from-start` (recommended) creates the container with Podman and attaches before it starts; `--pid PID` joins a running container and misses its startup; `--synthetic` emits a fake trace for tests. |
| `generate` | Turn a trace into an OCI seccomp profile (`defaultAction: SCMP_ACT_ERRNO`, one allow rule). Refuses synthetic traces and traces without provenance unless `--allow-synthetic`. |
| `merge` | Combine traces from several runs into one. |
| `compare` | Syscalls added, removed and common between two traces, or two profiles with `--profiles`. |
| `drift` | Report, as JSONL, every event in a trace outside a profile; exit code 2 if there is any. |
| `enforce` | Run the container with the profile (`podman run --security-opt seccomp=...`). `--monitor` and `--audit` add live drift detection. |
| `summary` | Unique syscalls and a reduction figure against a fixed reference count (`--default-allowed`, 304 by default), with optional JSON and Markdown reports. |
| `validate` | Check that a profile parses and has the minimum structure. |
| `version` | Print the version. |

### GitHub Action

The action learns your container while your own test command runs, generates the profile, reports the reduction against Podman's default profile on the pull request, uploads the profile and trace, and can fail the build when the container starts needing syscalls a committed profile does not allow.

```yaml
name: Seccomp profile
on: [pull_request]

permissions:
  contents: read
  pull-requests: write # the report comment

jobs:
  seccomp:
    runs-on: ubuntu-26.04
    steps:
      - uses: actions/checkout@v7
      - run: docker build -t myapp:ci .
      - uses: ValentinTorassa/AutoConfine@v0.1.0
        with:
          image: myapp:ci
          create-args: -p 8080:8080 -e APP_ENV=test
          test-command: ./scripts/smoke-test.sh http://127.0.0.1:8080
          drift-profile: security/myapp.seccomp.json # optional: fail on new syscalls
```

What happens, step by step:

1. Checks the runner (Linux amd64, cgroup v2, passwordless `sudo`, Podman) and builds AutoConfine from the action's own source with `actions/setup-go`.
2. Makes the image available to root Podman: it is used as is if root Podman already has it, copied with `docker save | sudo podman load` if an earlier step built it with Docker, and pulled otherwise.
3. Starts `sudo autoconfine learn --from-start` in the background. Once the container is running it runs `test-command` on the runner (`bash -eo pipefail`, in the workspace, with the container name in `AUTOCONFINE_CONTAINER`), then sends learn SIGTERM so the capture ends with the tests. Without a `test-command` it captures until the container exits. `timeout` caps the capture; a test command still running when it expires, or one that fails, fails the step.
4. Generates and validates the profile, and counts how many of the syscall names allowed by the default profile it leaves out.
5. Writes the report to the job summary, uploads profile, trace, report and logs as an artifact (also after a failed capture, for debugging), and posts one pull request comment that later runs update in place.
6. With `drift-profile`, runs `autoconfine drift` on the new trace against the committed profile and fails the job if the container made any syscall outside it (unless `fail-on-drift: false`).

| Input | Default | Description |
|---|---|---|
| `image` | (required) | Image to learn. Use a fully qualified name (`docker.io/library/nginx:alpine`) for registry images. |
| `command` | image default | Container command. Split like shell words (quotes respected, nothing expanded). |
| `create-args` | | Extra `podman create` options (ports, env, volumes), split the same way. `--name`, `--rm` and `--` are reserved. |
| `test-command` | | Command that exercises the container. Empty: capture until the container exits. |
| `timeout` | `10m` | Upper bound for the capture (Go duration). |
| `runtime` | `podman` | Only `podman` is supported. |
| `default-profile` | Podman's | Profile the reduction is measured against; defaults to `/usr/share/containers/seccomp.json` (or `/etc/containers/seccomp.json`) on the runner. |
| `output` | `autoconfine.seccomp.json` | Where the generated profile is written. Also keys the PR comment. |
| `drift-profile` | | Committed profile to check the new capture against. |
| `fail-on-drift` | `true` | Fail when the drift check finds syscalls outside `drift-profile`. |
| `comment` | `true` | Post or update the pull request comment. |
| `github-token` | `github.token` | Token for the comment; needs `pull-requests: write`. |
| `artifact-name` | `autoconfine-profile` | Artifact name; must be unique within the run. |
| `setup-go` | `true` | Install Go with `actions/setup-go`; set to `false` if Go 1.22+ is already on PATH. |

| Output | Description |
|---|---|
| `profile`, `trace`, `report` | Paths of the generated profile, the trace (JSONL) and the Markdown report. |
| `syscalls` | Syscalls the generated profile allows. |
| `default-syscalls` | Syscall names the default profile allows. |
| `reduction` | Percentage of those default syscalls the generated profile leaves out, one decimal. |
| `drift-status` | `clean`, `found`, or `skipped` without `drift-profile`. |
| `new-syscalls` | Comma-separated syscalls outside `drift-profile`. |
| `artifact-url` | URL of the uploaded artifact. |

Notes:

- Pin a release tag, as in the example. A tag can be moved and a commit cannot, so the hardened option is the full commit SHA the tag points to, with the tag in a comment: `uses: ValentinTorassa/AutoConfine@<40-character SHA> # v0.1.0`. `gh api repos/ValentinTorassa/AutoConfine/commits/v0.1.0 --jq .sha` prints it. The action builds AutoConfine from the source at that ref, so the pin also fixes the CLI version.
- The container runs under rootful Podman (`sudo podman`) and the probe loads as root, as in the drill. Use disposable runners, such as GitHub-hosted ones.
- A pull request from a fork gets a read-only token, so the comment fails with a warning; the report is still in the job summary and the artifact.
- The reduction counts names in the default profile's allow rules, including rules that only apply with certain arguments or capabilities. It describes the size of the allow list, not the security of the profile.
- The action fails rather than report a partial capture: the kernel dropping events, a timeout during the tests or a failing test command all fail the step.

## How it works

**The probe.** `internal/bpf/syscalls.bpf.c` holds two raw tracepoint programs, one for `sys_enter` and one for `sys_exit`; user space loads only the one it needs. Each matches a task when its cgroup v2 is the target container's cgroup or a descendant of it (`bpf_get_current_ancestor_cgroup_id` at the target's level), so processes the container moves into child cgroups still count. Each event (kernel timestamp, PID, TID, syscall number, errno, `comm`) goes into a 4 MiB ring buffer. When the buffer is full the kernel side increments a per-CPU drop counter instead, and AutoConfine refuses the trace if that counter is not zero; if user space cannot keep up it also stops rather than drop events. Stopping flushes the ring buffer, so the last syscalls before a container exits are kept. Syscall numbers are named with an amd64 table. The object is committed (`internal/bpf/syscalls_bpfel.o`) so `go install` needs no clang, and CI checks that it matches the source.

**From-start capture.** `learn --from-start` runs `podman create`, then `podman init`: the OCI runtime sets up the container and its cgroup, and the init process waits. The probe attaches to that cgroup, and only then does `podman start` run the entrypoint. If the probe cannot attach, the container is removed without ever starting. Events before the entrypoint's `execve` (the runtime finishing its setup) are dropped, so the trace starts at the program the profile is meant for. Every event is labelled `phase: observed-ebpf` and `capture_mode: from-exec` (`attached` for `--pid`, `synthetic` for tests); `generate` and `drift` refuse traces that were not observed unless told otherwise, and `generate` warns when a trace lacks the startup.

**Merging runs.** One run covers one path through the program. `merge` combines traces from several runs (different inputs, error paths, shutdown, a longer soak) and drops duplicate events (same PID, command, syscall and millisecond); `generate` on the merged trace allows the union. `compare` shows what one run added to another, as traces or as profiles.

**Drift detection.** `drift` checks a saved trace against a profile offline: every event outside it is a JSONL line, and the exit code is 2 if there is any. This is what the Action's drift check runs. Live, `enforce --monitor` runs the container under the profile with the same create, init, attach, start sequence, and reports each syscall outside the profile the moment it happens (JSONL on stderr or `--out`, with the action and errno), then prints a per-syscall summary and exits 2 if there was any. It attaches to `sys_exit`, not `sys_enter`, for a reason: seccomp runs before the `sys_enter` tracepoint, so a syscall the profile denies with `SCMP_ACT_ERRNO` never reaches it, but it still returns through `sys_exit` (`kernel/entry/common.c`). The program reads the syscall number from `pt_regs->orig_ax`, which the denial leaves intact (the offset is checked against the running kernel's BTF in tests). `enforce --audit` instead applies a temporary copy of the profile with `SCMP_ACT_LOG` as the default action, so nothing is denied, and watches `sys_enter`, which also sees calls that never return, such as `exit_group`.

## Limits

- **Linux amd64 only.** Syscall names come from an amd64 table and the `sys_exit` program reads an x86_64 register offset; the probe refuses other architectures. An unnamed syscall becomes `syscall_N` and `generate` refuses it.
- **Podman only** for capture from the start, live monitoring and the Action. With Docker, `learn --pid` attaches to a running container (missing its startup) and `enforce` without monitoring works.
- **Root**, or `CAP_BPF` + `CAP_PERFMON`, to load the probe.
- **A profile is what ran.** Paths the capture did not exercise (rare errors, signal handlers, log rotation, a different config) are not in it, and their syscalls fail with `EPERM`: the generated profile sets no `defaultErrnoRet`, while [Podman's default profile](https://github.com/containers/container-libs/blob/45bfa0b68bf93bd6eba219cac2bcecd88353196f/common/pkg/seccomp/seccomp.json) sets it to `ENOSYS` (38), which some programs treat as "unsupported, fall back". A short CI run gives a short profile.
- **The runtime's own syscalls are not in the trace.** The trace starts at the entrypoint's `execve`, but the OCI runtime may load the filter before it finishes setting up the process and make calls such as `setresgid` under it. In the drill, a profile learned from a short nginx run made `podman init` fail with `crun: cannot setresgid to 0: Operation not permitted` for a different command. `enforce --monitor` and `--audit` do not report those calls either: they check from the entrypoint's `execve` on. `--monitor` also does not see syscalls the profile answers by killing or signalling the process instead of returning an errno, does not attach stdin (no `-it`), and `podman create` rejects `-d`.
- **What the drill did not verify:** other kernels, long-running workloads, and ring buffer loss under pressure. Its `--monitor` case used a test profile derived from Podman's default profile, not the learned nginx profile.

**Building a profile you can enforce: baseline, merge, check.**

1. Capture several runs that cover startup, your test suite, error paths and shutdown, and `merge` the traces. In CI, keep each run's trace (the Action uploads it).
2. Add the syscalls your OCI runtime makes before the entrypoint, which no trace contains. The drill hit `setresgid`; the Security Profiles Operator publishes runtime base profiles as a starting point, for example [crun 1.29.1](https://github.com/kubernetes-sigs/security-profiles-operator/blob/v1.1.0/examples/baseprofile-crun.yaml) and [runc](https://github.com/kubernetes-sigs/security-profiles-operator/blob/v1.1.0/examples/baseprofile-runc.yaml). AutoConfine does not add them for you: add them to the generated allow list and run `validate`.
3. Run the real workload with `enforce --audit`, then `enforce --monitor`, until neither reports drift and `podman init` succeeds. A failure at `podman init` points to step 2.
4. Commit the profile and point the Action's `drift-profile` at it. When the check reports a syscall that is legitimate, merge the new trace with the earlier ones, regenerate, re-add the runtime baseline, and commit the result.

## Prior art

Three maintained open-source projects already record container syscalls with eBPF and generate seccomp profiles. Facts below are from their repositories at the versions linked (checked 2026-10-03).

| | [oci-seccomp-bpf-hook][hook] v1.3.0 | [Security Profiles Operator][spo] v1.1.0 | [Inspektor Gadget][ig] v0.56.2 | AutoConfine |
|---|---|---|---|---|
| Where it runs | OCI prestart hook for Podman, enabled per container with the `io.containers.trace-syscall` annotation | Kubernetes operator (`ProfileRecording` resources); `spoc` CLI records a single command | `kubectl gadget` on Kubernetes, `ig` on Linux hosts (`advise_seccomp` gadget) | CLI driving Podman; GitHub Action |
| Recording | `raw_syscalls:sys_enter`, syscalls from the container's PID namespace, perf buffer; BCC compiles the C code at run time | eBPF recorder on `raw_syscalls/sys_enter`, keyed by mount namespace; or seccomp audit records from auditd or syslog | `raw_tracepoint/sys_enter`, per mount namespace | raw tracepoint `sys_enter`, container cgroup v2 subtree, ring buffer with a drop counter |
| Output | Profile written when the container exits | `SeccompProfile` resources when the recorded workload is removed; `spoc` writes YAML or JSON | Profile printed when the gadget stops | JSONL trace with provenance; `generate` makes the profile from it |
| Runtime base syscalls | Not documented; an `if:` input profile serves as a baseline | Base profiles for runc and crun; `spoc record` adds base syscalls by default | Not documented | Not added; see [Limits](#limits) |
| Combining runs | New syscalls are added to the `if:` baseline; syscalls it blocks stay blocked | `mergeStrategy: Containers` merges per-container recordings | Not documented | `merge` combines traces |
| Watching a deployed profile | Not documented | Log enricher reads seccomp audit records | `audit_seccomp` gadget, which sees a syscall only when the filter makes the kernel log it: `SECCOMP_FILTER_FLAG_LOG` (runc 1.2.0+) with any non-allow action, or `SCMP_ACT_LOG` / `SCMP_ACT_KILL*` without it | `enforce --monitor` at `sys_exit` (sees `SCMP_ACT_ERRNO` denials); `--audit` with `SCMP_ACT_LOG` |

Sources: hook [README][hook-readme]; SPO [seccomp recording, base syscalls and merging][spo-profiles], [`spoc record`][spo-cli] and the [recorder's BPF source][spo-bpf]; Inspektor Gadget [`advise_seccomp` docs][ig-advise] and [source][ig-advise-bpf], [`audit_seccomp` docs][ig-audit].

**What AutoConfine adds:**

- **Seeing the syscalls a profile already denies, live, without audit logging.** All three recorders hook `sys_enter`, which is right for learning but never fires for a syscall that seccomp denies with an errno. Inspektor Gadget's `audit_seccomp` sees denials only when the filter produces audit records (the log flag, or a log or kill action). `enforce --monitor` reads `sys_exit`, so a deny-mode profile with `SCMP_ACT_ERRNO` can be watched as it is, with each denied call reported as it happens, the errno it returned, and exit code 2.
- **Evidence kept apart from the profile.** A capture is a JSONL trace that records how it was obtained (`observed-ebpf` or `synthetic`, `from-exec` or `attached`). `generate`, `merge`, `compare` and `drift` work on those files, and `generate` and `drift` refuse traces that were not observed. The three recorders above go straight to a profile or a profile resource.
- **A checkable capture boundary on Podman.** Create, init, attach, start: the probe is live before the entrypoint runs, the container never starts if it cannot attach, and the trace starts at the entrypoint's `execve`.
- **The loop in CI.** The Action learns while the project's tests run, reports the reduction against the runtime's default profile on the pull request, and gates merges on syscalls outside a committed profile.

**What they do that AutoConfine does not:** Kubernetes integration and runtimes other than Podman (SPO, Inspektor Gadget), SELinux and AppArmor profiles, profile binding and runtime base profiles (SPO), and a one-annotation integration into `podman run` (the hook).

[hook]: https://github.com/containers/oci-seccomp-bpf-hook
[hook-readme]: https://github.com/containers/oci-seccomp-bpf-hook/blob/v1.3.0/README.md
[spo]: https://github.com/kubernetes-sigs/security-profiles-operator
[spo-profiles]: https://github.com/kubernetes-sigs/security-profiles-operator/blob/v1.1.0/profiles.md
[spo-cli]: https://github.com/kubernetes-sigs/security-profiles-operator/blob/v1.1.0/cli.md#record-seccomp-profiles-for-a-command
[spo-bpf]: https://github.com/kubernetes-sigs/security-profiles-operator/blob/v1.1.0/internal/pkg/daemon/bpfrecorder/bpf/recorder.bpf.c
[ig]: https://github.com/inspektor-gadget/inspektor-gadget
[ig-advise]: https://github.com/inspektor-gadget/inspektor-gadget/blob/v0.56.2/docs/gadgets/advise_seccomp.mdx
[ig-advise-bpf]: https://github.com/inspektor-gadget/inspektor-gadget/blob/v0.56.2/gadgets/advise_seccomp/program.bpf.c
[ig-audit]: https://github.com/inspektor-gadget/inspektor-gadget/blob/v0.56.2/docs/gadgets/audit_seccomp.mdx

## Development

`make test` (with `-race`), `make vet`, `make bpf` / `make bpf-check`, and `python3 -m unittest discover -s scripts/action` for the Action's helpers. With `sudo` and Podman: `make run-learn` captures nginx, and `make run-monitor` / `make run-audit` run it under the resulting profile with live monitoring, which is how to try for real what the unit tests cover with fakes.

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   learn     │────▶│  generate   │────▶│   enforce   │
│   (eBPF)    │     │ (seccomp)   │     │  (Podman)   │
└─────────────┘     └─────────────┘     └─────────────┘
       │                                       │
       ▼                                       ▼
┌─────────────┐                         ┌─────────────┐
│ merge,      │                         │ live drift  │
│ compare,    │                         │ (--monitor, │
│ drift       │                         │  --audit)   │
└─────────────┘                         └─────────────┘
```

## License

Apache 2.0, see [LICENSE](LICENSE).

---

Submitted to the **Premio CAI Pre-Ingeniería 2026** by **Valentín Torassa Colombero**.
