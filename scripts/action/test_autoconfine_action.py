"""Unit tests for the Action helpers: python3 -m unittest discover -s scripts/action"""

import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path

import autoconfine_action as action


class Words(unittest.TestCase):
    def test_split_respects_quotes_and_expands_nothing(self):
        self.assertEqual(action.split_words("nginx -g 'daemon off;' $HOME `id`", "command"),
                         ["nginx", "-g", "daemon off;", "$HOME", "`id`"])
        self.assertEqual(action.split_words("  \n ", "command"), [])

    def test_unbalanced_quote_is_an_input_error(self):
        with self.assertRaises(action.ActionError):
            action.split_words("sh -c 'oops", "command")

    def test_reserved_create_args(self):
        action.check_create_args(["-p", "8080:80", "-e", "A=--rm"])
        for bad in (["--rm"], ["--name", "x"], ["--name=x"], ["-p", "1:1", "--", "sh"]):
            with self.assertRaises(action.ActionError, msg=bad):
                action.check_create_args(bad)

    def test_learn_argv_puts_command_after_second_double_dash(self):
        argv = action.learn_argv("/bin/ac", "img", "5m", "/t/trace.jsonl", "ctr", ["-p", "1:1"], ["nginx", "-g", "x"])
        self.assertEqual(argv, ["/bin/ac", "learn", "--image", "img", "--from-start", "--duration", "5m",
                                "--out", "/t/trace.jsonl", "--", "--name", "ctr", "-p", "1:1",
                                "--", "nginx", "-g", "x"])
        self.assertNotIn("--", action.learn_argv("/bin/ac", "img", "5m", "t", "ctr", [], [])[10:])


class Report(unittest.TestCase):
    def test_reduction_counts_default_allow_list(self):
        cmp = {"removed": ["a", "b", "c"], "common": ["d"], "added": []}
        self.assertEqual(action.reduction(cmp), (4, 1, 75.0))
        self.assertEqual(action.reduction({"removed": [], "common": [], "added": ["x"]}), (0, 1, 0.0))

    def test_allowed_and_drift_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = Path(tmp, "p.json")
            profile.write_text(json.dumps({"defaultAction": "SCMP_ACT_ERRNO", "syscalls": [
                {"names": ["write", "read"], "action": "SCMP_ACT_ALLOW"},
                {"names": ["ptrace"], "action": "SCMP_ACT_ERRNO"}]}))
            self.assertEqual(action.allowed_names(profile), ["read", "write"])
            drift = Path(tmp, "d.jsonl")
            drift.write_text('{"syscall":"bind"}\n\n{"syscall":"bind"}\n{"syscall":"execve"}\n')
            self.assertEqual(action.drift_names(drift), ["bind", "execve"])
            self.assertEqual(action.count_events(drift), 3)

    def facts(self, **over):
        facts = {"image": "docker.io/library/nginx:alpine", "command": "", "test_command": "curl a | grep b\nls",
                 "events": 10, "syscalls": ["read", "write"], "generated": 2, "default": 8,
                 "default_profile": "/usr/share/containers/seccomp.json", "reduction": 75.0,
                 "profile": "p.json", "drift": None}
        facts.update(over)
        return facts

    def test_render_keeps_table_cells_intact(self):
        body = action.render(self.facts(), "https://example.invalid/run", "art")
        row = [line for line in body.splitlines() if line.startswith("| Test command")][0]
        self.assertEqual(row.count("|"), 3, row)  # the command's pipe is escaped
        self.assertIn("curl a &#124; grep b ; ls", row)
        self.assertIn("**75.0%**", body)
        self.assertIn("| Drift check | not configured |", body)
        self.assertIn("artifact `art` in [this run](https://example.invalid/run)", body)

    def test_render_drift(self):
        found = action.render(self.facts(drift={"profile": "c.json", "status": "found",
                                                "new": ["bind"], "unused": ["chmod"]}))
        self.assertIn("**1 syscall outside it:** `bind`", found)
        self.assertIn("1 syscall the committed profile allows but this run did not use", found)
        clean = action.render(self.facts(drift={"profile": "c.json", "status": "clean", "new": [], "unused": []}))
        self.assertIn("none: every syscall is in the committed profile", clean)


class Image(unittest.TestCase):
    def test_loaded_name(self):
        self.assertEqual(action.loaded_name("Getting image source signatures\nLoaded image: localhost/app:ci\n"),
                         "localhost/app:ci")
        self.assertEqual(action.loaded_name("Loaded image(s): docker.io/library/app:ci,app:latest"),
                         "docker.io/library/app:ci")
        self.assertEqual(action.loaded_name("nothing"), "")


class FakeGitHub:
    def __init__(self, comments, deny_patch=False):
        self.repo = "o/r"
        self.comments_list = comments
        self.deny_patch = deny_patch
        self.calls = []

    def comments(self, number):
        return iter(self.comments_list)

    def request(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        if method == "PATCH" and self.deny_patch:
            raise urllib.error.HTTPError(path, 403, "Forbidden", {}, io.BytesIO(b""))
        return {}


class Comment(unittest.TestCase):
    def test_marker_is_stable_and_safe_in_html_comments(self):
        mark = action.marker("demo/a--b.seccomp.json")
        self.assertEqual(mark, action.marker("demo/a--b.seccomp.json"))
        self.assertNotEqual(mark, action.marker("other.json"))
        self.assertNotIn("--", mark[4:-3])

    def test_updates_the_marked_comment(self):
        mark = action.marker("p.json")
        gh = FakeGitHub([{"id": 1, "body": "hi"}, {"id": 7, "body": mark + "\nold"}])
        self.assertEqual(action.upsert_comment(gh, "5", mark + "\nnew", mark), "updated")
        self.assertEqual(gh.calls, [("PATCH", "/repos/o/r/issues/comments/7", {"body": mark + "\nnew"})])

    def test_creates_when_missing_or_not_editable(self):
        mark = action.marker("p.json")
        gh = FakeGitHub([{"id": 1, "body": None}])
        self.assertEqual(action.upsert_comment(gh, "5", "b", mark), "created")
        self.assertEqual(gh.calls, [("POST", "/repos/o/r/issues/5/comments", {"body": "b"})])
        gh = FakeGitHub([{"id": 9, "body": mark}], deny_patch=True)
        self.assertEqual(action.upsert_comment(gh, "5", "b", mark), "created")
        self.assertEqual([c[0] for c in gh.calls], ["PATCH", "POST"])


if __name__ == "__main__":
    unittest.main()
