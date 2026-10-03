#!/usr/bin/env python3
"""Steps behind action.yml: check the runner, prepare the image, learn while
the project's tests run, write the report, and post it on the pull request.

Every setting arrives in an AC_* environment variable set by action.yml, so
no workflow input is ever pasted into a shell script. Standard library only:
GitHub's Ubuntu runners ship python3, nothing else is assumed.
"""

import hashlib
import json
import os
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_PROFILES = ("/usr/share/containers/seccomp.json", "/etc/containers/seccomp.json")
RESERVED_CREATE_ARGS = ("--", "--name", "--rm")
COMMENT_LIMIT = 60000  # GitHub rejects comment bodies over 65536 characters


class ActionError(Exception):
    """A failure to report as a workflow error annotation."""


def env(name, default=""):
    return os.environ.get(name, default)


def escape_command(value):
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def annotate(level, message):
    print("::%s title=AutoConfine::%s" % (level, escape_command(message)), flush=True)


def set_output(name, value):
    path = env("GITHUB_OUTPUT")
    if not path:
        print("output %s=%s" % (name, value))
        return
    delimiter = "AUTOCONFINE_%s" % os.urandom(8).hex()
    with open(path, "a", encoding="utf-8") as out:
        out.write("%s<<%s\n%s\n%s\n" % (name, delimiter, value, delimiter))


def split_words(value, what):
    """Split an input into words like a shell would (quotes, backslashes),
    without expanding variables, globs or command substitutions."""
    try:
        return shlex.split(value, comments=False, posix=True)
    except ValueError as err:
        raise ActionError("%s: %s" % (what, err))


def check_create_args(args):
    for arg in args:
        name = arg.split("=", 1)[0]
        if name in RESERVED_CREATE_ARGS:
            raise ActionError(
                "create-args must not contain %s: the action names the container, "
                "removes it after the capture and passes the command itself" % name)


def group(title):
    print("::group::%s" % title, flush=True)


def endgroup():
    print("::endgroup::", flush=True)


# --- setup -----------------------------------------------------------------

def setup():
    if env("AC_RUNTIME", "podman") != "podman":
        raise ActionError(
            "runtime %r is not supported: capture from the start needs `podman init`, "
            "which Docker has no equivalent for; use runtime: podman" % env("AC_RUNTIME"))
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
        raise ActionError("AutoConfine captures on Linux amd64 only (this runner is %s %s)"
                          % (platform.system(), platform.machine()))
    if not Path("/sys/fs/cgroup/cgroup.controllers").exists():
        raise ActionError("cgroup v2 is required (no /sys/fs/cgroup/cgroup.controllers)")
    if subprocess.call(["sudo", "-n", "true"]) != 0:
        raise ActionError("passwordless sudo is required to load the eBPF probe and run rootful Podman")
    if shutil.which("podman") is None:
        raise ActionError("podman is not installed on this runner")
    base = Path(tempfile.mkdtemp(prefix="autoconfine.", dir=env("RUNNER_TEMP") or None))
    out_dir = base / "out"
    out_dir.mkdir()
    (base / "bin").mkdir()
    default = resolve_default_profile(env("AC_DEFAULT_PROFILE"))
    print("default profile for the reduction: %s" % default)
    set_output("dir", str(out_dir))
    set_output("bin", str(base / "bin" / "autoconfine"))
    set_output("default-profile", default)


def resolve_default_profile(given):
    if given:
        if not Path(given).is_file():
            raise ActionError("default-profile %s does not exist" % given)
        return given
    for candidate in DEFAULT_PROFILES:
        if Path(candidate).is_file():
            return candidate
    raise ActionError("Podman's default seccomp profile was not found in %s; set default-profile"
                      % " or ".join(DEFAULT_PROFILES))


# --- image -----------------------------------------------------------------

def podman(*args, **kwargs):
    return subprocess.run(["sudo", "podman", *args], **kwargs)


def prepare_image():
    image = env("AC_IMAGE")
    if not image:
        raise ActionError("image is required")
    if podman("image", "exists", image).returncode == 0:
        print("%s is already in root Podman storage" % image)
        return
    docker = shutil.which("docker")
    if docker and subprocess.run([docker, "image", "inspect", image],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
        # Built with Docker earlier in the job: copy it into root Podman
        # storage under the same reference, so `podman create IMAGE` finds it.
        print("copying %s from Docker into root Podman storage" % image)
        save = subprocess.Popen([docker, "save", image], stdout=subprocess.PIPE)
        load = podman("load", stdin=save.stdout, stdout=subprocess.PIPE, universal_newlines=True)
        save.stdout.close()
        if save.wait() != 0 or load.returncode != 0:
            raise ActionError("could not copy %s from Docker to Podman" % image)
        print(load.stdout.strip())
        loaded = loaded_name(load.stdout)
        if loaded and podman("tag", loaded, image).returncode != 0:
            raise ActionError("could not tag %s as %s in Podman" % (loaded, image))
        return
    if podman("pull", image).returncode != 0:
        raise ActionError("podman pull %s failed (use a fully qualified name such as "
                          "docker.io/library/nginx:alpine)" % image)


def loaded_name(output):
    """The first image name in `podman load` output ("Loaded image: NAME",
    or "Loaded image(s): A,B" in older versions)."""
    for line in output.splitlines():
        if line.startswith("Loaded image"):
            names = line.split(":", 1)[1].strip()
            return names.split(",")[0].strip()
    return ""


# --- learn -----------------------------------------------------------------

def container_state(name):
    res = podman("container", "inspect", "--format", "{{.State.Status}}", name,
                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True)
    return res.stdout.strip() if res.returncode == 0 else ""


def learn_argv(binary, image, timeout, trace, name, create_args, command):
    argv = [binary, "learn", "--image", image, "--from-start", "--duration", timeout,
            "--out", str(trace), "--", "--name", name] + list(create_args)
    if command:
        argv += ["--"] + list(command)
    return argv


def learn():
    binary, image = env("AC_BIN"), env("AC_IMAGE")
    out_dir = Path(env("AC_OUT_DIR"))
    create_args = split_words(env("AC_CREATE_ARGS"), "create-args")
    check_create_args(create_args)
    command = split_words(env("AC_COMMAND"), "command")
    test_command = env("AC_TEST_COMMAND").strip()
    name = "autoconfine-learn-%s-%s-%d" % (env("GITHUB_RUN_ID", "local"),
                                           env("GITHUB_RUN_ATTEMPT", "1"), os.getpid())
    trace, log_path = out_dir / "trace.jsonl", out_dir / "learn.log"
    pidfile = Path(tempfile.mkdtemp(dir=env("RUNNER_TEMP") or None)) / "learn.pid"
    pidfile.touch()
    argv = learn_argv(binary, image, env("AC_TIMEOUT", "10m"), trace, name, create_args, command)
    print("+ sudo " + " ".join(shlex.quote(a) for a in argv), flush=True)

    # sh writes its PID and execs learn, so that PID is learn itself: the
    # action signals it directly instead of relying on sudo to relay.
    with open(log_path, "wb") as log:
        proc = subprocess.Popen(["sudo", "sh", "-c", 'echo "$$" > "$1"; shift; exec "$@"',
                                 "sh", str(pidfile)] + argv, stdout=log, stderr=subprocess.STDOUT)
    learn_pid = ""
    test_rc = None
    try:
        learn_pid = wait_for_pid(proc, pidfile)
        state = wait_for_container(proc, name)
        if proc.poll() is None:
            print("container %s is %s" % (name, state), flush=True)
            if test_command:
                group("Test command")
                test_rc = subprocess.call(
                    ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", test_command],
                    env=dict(os.environ, AUTOCONFINE_CONTAINER=name))
                endgroup()
            else:
                print("no test-command: capturing until the container exits", flush=True)
                while proc.poll() is None and container_state(name) not in ("exited", "stopped", ""):
                    time.sleep(1)
        ended_on_its_own = proc.poll() is not None
        stop(proc, learn_pid)
    finally:
        if proc.poll() is None:  # cancelled or failed mid-way: still end the capture
            stop(proc, learn_pid)
        group("autoconfine learn output")
        print(log_path.read_text(errors="replace"), end="", flush=True)
        endgroup()

    if proc.returncode != 0:
        raise ActionError("autoconfine learn exited %d; see its output above" % proc.returncode)
    if test_command and ended_on_its_own:
        raise ActionError("the capture reached timeout (%s) before the test command finished; "
                          "raise timeout" % env("AC_TIMEOUT", "10m"))
    if test_rc:
        raise ActionError("the test command exited %d; the trace and logs are in the artifact" % test_rc)
    subprocess.call(["sudo", "chown", "%d:%d" % (os.getuid(), os.getgid()), str(trace)])
    set_output("trace", str(trace))


def wait_for_pid(proc, pidfile, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        pid = pidfile.read_text().strip()
        if pid:
            return pid
        if proc.poll() is not None:
            return ""
        time.sleep(0.1)
    raise ActionError("autoconfine learn did not start")


def wait_for_container(proc, name, timeout=300):
    deadline = time.time() + timeout
    while proc.poll() is None:
        state = container_state(name)
        if state in ("running", "exited", "stopped"):
            return state
        if time.time() > deadline:
            raise ActionError("container %s did not start within %ds (last state %r)"
                              % (name, timeout, state))
        time.sleep(0.5)
    return ""


def stop(proc, learn_pid, timeout=180):
    """End the capture with SIGTERM (learn saves the trace and removes the
    container) and wait for learn to exit."""
    if proc.poll() is None and learn_pid:
        subprocess.call(["sudo", "kill", "-TERM", learn_pid], stderr=subprocess.DEVNULL)
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        if learn_pid:
            subprocess.call(["sudo", "kill", "-KILL", learn_pid], stderr=subprocess.DEVNULL)
        proc.wait()
        raise ActionError("autoconfine learn did not exit %ds after SIGTERM" % timeout)


# --- report ----------------------------------------------------------------

def run(argv):
    print("+ " + " ".join(shlex.quote(a) for a in argv), flush=True)
    if subprocess.call(argv) != 0:
        raise ActionError("%s %s failed" % (Path(argv[0]).name, argv[1]))


def compare_profiles(binary, a, b):
    out = subprocess.run([binary, "compare", "--profiles", str(a), str(b)],
                         stdout=subprocess.PIPE, universal_newlines=True)
    if out.returncode != 0:
        raise ActionError("autoconfine compare --profiles %s %s failed" % (a, b))
    res = json.loads(out.stdout)
    return {key: res.get(key) or [] for key in ("added", "removed", "common")}


def reduction(cmp):
    """Size of each allow list and the share of the default profile's
    syscalls that the generated one leaves out. cmp compares the default
    profile (A) with the generated one (B)."""
    default = len(cmp["removed"]) + len(cmp["common"])
    generated = len(cmp["common"]) + len(cmp["added"])
    percent = 100.0 * len(cmp["removed"]) / default if default else 0.0
    return default, generated, round(percent, 1)


def allowed_names(path):
    data = json.loads(Path(path).read_text())
    names = set()
    for rule in data.get("syscalls") or []:
        if rule.get("action") == "SCMP_ACT_ALLOW":
            names.update(rule.get("names") or [])
    return sorted(names)


def drift_names(path):
    names = set()
    for line in Path(path).read_text().splitlines():
        if line.strip():
            names.add(json.loads(line).get("syscall", ""))
    names.discard("")
    return sorted(names)


def count_events(path):
    with open(path, "rb") as trace:
        return sum(1 for line in trace if line.strip())


def report():
    binary = env("AC_BIN")
    out_dir = Path(env("AC_OUT_DIR"))
    trace = out_dir / "trace.jsonl"
    profile = Path(env("AC_OUTPUT") or "autoconfine.seccomp.json")
    default = env("AC_DEFAULT_PROFILE")
    profile.parent.mkdir(parents=True, exist_ok=True)
    run([binary, "generate", str(trace), "--out", str(profile)])
    run([binary, "validate", str(profile)])
    if (out_dir / profile.name).resolve() != profile.resolve():
        shutil.copy(profile, out_dir / profile.name)

    default_count, generated_count, percent = reduction(compare_profiles(binary, default, profile))
    facts = {
        "image": env("AC_IMAGE"),
        "command": env("AC_COMMAND").strip(),
        "test_command": env("AC_TEST_COMMAND").strip(),
        "events": count_events(trace),
        "syscalls": allowed_names(profile),
        "generated": generated_count,
        "default": default_count,
        "default_profile": default,
        "reduction": percent,
        "profile": str(profile),
        "drift": None,
    }

    status, new = "skipped", []
    committed = env("AC_DRIFT_PROFILE")
    if committed:
        if not Path(committed).is_file():
            raise ActionError("drift-profile %s does not exist" % committed)
        drift_out = out_dir / "drift.jsonl"
        argv = [binary, "drift", "--profile", committed, str(trace)]
        print("+ " + " ".join(shlex.quote(a) for a in argv), flush=True)
        with open(drift_out, "w") as out:
            rc = subprocess.call(argv, stdout=out)
        if rc not in (0, 2):
            raise ActionError("autoconfine drift exited %d" % rc)
        new = drift_names(drift_out)
        status = "found" if rc == 2 else "clean"
        unused = compare_profiles(binary, committed, profile)["removed"]
        facts["drift"] = {"profile": committed, "status": status, "new": new, "unused": unused}

    body = render(facts, env("AC_RUN_URL"), env("AC_ARTIFACT_NAME"))
    report_path = out_dir / "report.md"
    report_path.write_text(body)
    summary = env("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as out:
            out.write(body + "\n")
    print(body)
    for key, value in (("profile", str(profile)), ("trace", str(trace)),
                       ("report", str(report_path)), ("syscalls", str(generated_count)),
                       ("default-syscalls", str(default_count)), ("reduction", "%.1f" % percent),
                       ("drift-status", status), ("new-syscalls", ",".join(new))):
        set_output(key, value)


def code(text):
    """Inline code that survives a Markdown table cell: HTML-escaped, pipes
    and newlines neutralised, long commands shortened."""
    text = " ; ".join(line.strip() for line in text.strip().splitlines() if line.strip())
    if len(text) > 200:
        text = text[:197] + "..."
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("|", "&#124;")
    return "<code>%s</code>" % text


def plural(n, word):
    return "%d %s%s" % (n, word, "" if n == 1 else "s")


def name_list(names):
    return " ".join("`%s`" % n for n in names)


def render(facts, run_url="", artifact=""):
    lines = ["### AutoConfine seccomp profile", ""]
    lines.append(
        "%s used **%d distinct syscalls** during this capture (%d events from the entrypoint's "
        "`execve` on). The generated profile allows those %d; the default profile allows %d "
        "syscall names, so this profile leaves out **%.1f%%** of them."
        % (code(facts["image"]), facts["generated"], facts["events"], facts["generated"],
           facts["default"], facts["reduction"]))
    lines += ["", "| | |", "|---|---|"]
    lines.append("| Image | %s |" % code(facts["image"]))
    lines.append("| Container command | %s |" % (code(facts["command"]) if facts["command"] else "image default"))
    lines.append("| Test command | %s |" % (code(facts["test_command"]) if facts["test_command"]
                                           else "none: captured until the container exited"))
    lines.append("| Events captured | %d |" % facts["events"])
    lines.append("| Syscalls in the generated profile | %d |" % facts["generated"])
    lines.append("| Syscall names the default profile allows | %d (%s) |"
                 % (facts["default"], code(facts["default_profile"])))
    lines.append("| Reduction | %.1f%% |" % facts["reduction"])
    drift = facts["drift"]
    if drift is None:
        lines.append("| Drift check | not configured |")
    elif drift["status"] == "found":
        lines.append("| Drift vs %s | **%s outside it:** %s |"
                     % (code(drift["profile"]), plural(len(drift["new"]), "syscall"), name_list(drift["new"])))
    else:
        lines.append("| Drift vs %s | none: every syscall is in the committed profile |" % code(drift["profile"]))
    lines += ["", "<details><summary>The %d syscalls in the generated profile</summary>" % len(facts["syscalls"]),
              "", name_list(facts["syscalls"]), "", "</details>"]
    if drift and drift["unused"]:
        lines += ["", "<details><summary>%s the committed profile allows but this run did not use"
                  "</summary>" % plural(len(drift["unused"]), "syscall"), "", name_list(drift["unused"]), "", "</details>"]
    lines.append("")
    where = "Profile, trace and logs: artifact `%s`" % (artifact or "autoconfine-profile")
    lines.append(where + (" in [this run](%s)." % run_url if run_url else "."))
    lines += ["", "The reduction counts syscall names in the default profile's allow rules, conditional "
              "ones included. The profile covers only what ran during this capture: merge traces from "
              "several runs before enforcing it, and add the syscalls your OCI runtime needs before "
              "the entrypoint starts (see Limits in the AutoConfine README)."]
    return "\n".join(lines)


# --- comment ---------------------------------------------------------------

def marker(key):
    return "<!-- autoconfine-action:%s -->" % hashlib.sha256(key.encode()).hexdigest()[:16]


class GitHub:
    def __init__(self, token, api, repo):
        self.token, self.api, self.repo = token, api.rstrip("/"), repo

    def request(self, method, path, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(self.api + path, data=data, method=method, headers={
            "Authorization": "Bearer " + self.token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "autoconfine-action",
            "Content-Type": "application/json",
        })
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read()
        return json.loads(body) if body else None

    def comments(self, number):
        page = 1
        while True:
            batch = self.request("GET", "/repos/%s/issues/%s/comments?per_page=100&page=%d"
                                 % (self.repo, number, page))
            for item in batch:
                yield item
            if len(batch) < 100:
                return
            page += 1


def upsert_comment(gh, number, body, mark):
    """Update the comment that carries mark, or create one. Returns "updated"
    or "created"."""
    existing = None
    for item in gh.comments(number):
        if mark in (item.get("body") or ""):
            existing = item
            break
    if existing is not None:
        try:
            gh.request("PATCH", "/repos/%s/issues/comments/%s" % (gh.repo, existing["id"]), {"body": body})
            return "updated"
        except urllib.error.HTTPError as err:
            if err.code not in (403, 404):
                raise
            # Not ours to edit (someone else posted the marker): add our own.
    gh.request("POST", "/repos/%s/issues/%s/comments" % (gh.repo, number), {"body": body})
    return "created"


def comment():
    number = env("AC_PR_NUMBER")
    if not number:
        print("not a pull request: the report is only in the job summary")
        return
    body = Path(env("AC_REPORT")).read_text()
    if env("AC_ARTIFACT_URL"):
        body += "\n\n[Download the artifact](%s)" % env("AC_ARTIFACT_URL")
    body = marker(env("AC_MARKER_KEY")) + "\n" + body
    if len(body) > COMMENT_LIMIT:
        body = body[:COMMENT_LIMIT] + "\n\n(truncated; the full report is in the job summary)"
    gh = GitHub(env("AC_TOKEN"), env("GITHUB_API_URL", "https://api.github.com"), env("GITHUB_REPOSITORY"))
    try:
        print("pull request comment %s" % upsert_comment(gh, number, body, marker(env("AC_MARKER_KEY"))))
    except urllib.error.HTTPError as err:
        # A pull request from a fork gets a read-only token; the job summary
        # still has the report, so this is not worth failing the job over.
        annotate("warning", "could not post the pull request comment (HTTP %d). It needs "
                 "`pull-requests: write`; pull requests from forks get a read-only token. "
                 "The report is in the job summary." % err.code)


# ---------------------------------------------------------------------------

COMMANDS = {"setup": setup, "image": prepare_image, "learn": learn, "report": report, "comment": comment}


def main(argv):
    if len(argv) != 2 or argv[1] not in COMMANDS:
        print("usage: %s {%s}" % (argv[0], "|".join(COMMANDS)), file=sys.stderr)
        return 2
    try:
        COMMANDS[argv[1]]()
    except ActionError as err:
        annotate("error", str(err))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
