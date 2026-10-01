#!/usr/bin/env bash
# Disposable integration drill for a Linux amd64 VM with Podman and eBPF.
set -euo pipefail

image=docker.io/library/nginx:alpine
run_dir="$(mktemp -d)"
chmod 700 "$run_dir"

podman pull "$image" >/dev/null

# Attach before the entrypoint starts. The app removes this container itself.
./autoconfine learn --image "$image" --from-start --duration 8s \
  --out "$run_dir/trace.jsonl"

python3 - "$run_dir/trace.jsonl" <<'PY'
import json, sys
events = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
assert events, "startup capture produced no events"
assert all(event.get("phase") == "observed-ebpf" for event in events)
assert all(event.get("capture_mode") == "from-exec" for event in events)
assert any(event.get("syscall") in ("execve", "execveat") for event in events)
print("startup capture:", len(events), "observed events")
PY

./autoconfine generate "$run_dir/trace.jsonl" --out "$run_dir/profile.json"
./autoconfine validate "$run_dir/profile.json"

# Deny the harmless identity calls made by `id`, so both live hooks must
# report real drift while the test container is allowed to terminate.
python3 - "$run_dir/profile.json" "$run_dir/drift-profile.json" <<'PY'
import json, sys
profile = json.load(open(sys.argv[1]))
deny = {"getuid", "geteuid", "getgid", "getegid"}
for rule in profile["syscalls"]:
    rule["names"] = [name for name in rule["names"] if name not in deny]
profile["syscalls"] = [rule for rule in profile["syscalls"] if rule["names"]]
with open(sys.argv[2], "w") as out:
    json.dump(profile, out)
print("drift profile prepared")
PY
./autoconfine validate "$run_dir/drift-profile.json"

# The nginx trace starts at its entrypoint, so it omits syscalls that crun
# needs before execve (for example setresgid). Use Podman's normal runtime
# profile for the separate `id` command, then remove only its identity calls.
default_profile="$(podman info --format '{{.Host.Security.SeccompProfilePath}}')"
if [[ ! -f "$default_profile" ]]; then
  echo "Podman default seccomp profile is unavailable: $default_profile" >&2
  exit 1
fi
python3 - "$default_profile" "$run_dir/monitor-profile.json" <<'PY'
import json, sys
profile = json.load(open(sys.argv[1]))
deny = {"getuid", "geteuid", "getgid", "getegid"}
for rule in profile["syscalls"]:
    rule["names"] = [name for name in rule["names"] if name not in deny]
profile["syscalls"] = [rule for rule in profile["syscalls"] if rule["names"]]
with open(sys.argv[2], "w") as out:
    json.dump(profile, out)
print("monitor profile prepared from Podman default")
PY
./autoconfine validate "$run_dir/monitor-profile.json"

set +e
./autoconfine enforce --profile "$run_dir/drift-profile.json" --audit \
  --out "$run_dir/audit.jsonl" -- podman run --rm --entrypoint /bin/sh \
  "$image" -c 'id >/dev/null'
audit_rc=$?
./autoconfine enforce --profile "$run_dir/monitor-profile.json" --monitor \
  --out "$run_dir/monitor.jsonl" -- podman run --rm --entrypoint /bin/sh \
  "$image" -c 'id >/dev/null'
monitor_rc=$?
set -e

python3 - "$run_dir/audit.jsonl" "$run_dir/monitor.jsonl" "$audit_rc" "$monitor_rc" <<'PY'
import json, sys
for label, path, code in (("audit", sys.argv[1], int(sys.argv[3])),
                          ("monitor", sys.argv[2], int(sys.argv[4]))):
    events = [json.loads(line) for line in open(path) if line.strip()]
    assert code == 2, f"{label} exit {code}, expected drift exit 2"
    assert events, f"{label} found no live drift"
    assert any(event.get("syscall") in {"getuid", "geteuid", "getgid", "getegid"}
               for event in events), f"{label} missed the identity calls"
    print(label + ":", len(events), "live drift events")
PY
