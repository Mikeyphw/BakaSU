"""Read-only checkout gates and narrowly scoped hosted Android lint retry."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
SHA = re.compile(r"[0-9a-f]{40}\Z")


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def verify_checkout(expected):
    if not SHA.fullmatch(expected or "") or git("rev-parse", "HEAD") != expected:
        raise ValueError("CI checkout does not match expected source SHA")
    return expected


def diff_args(expected, env):
    base, head = env.get("PR_BASE_SHA", ""), env.get("PR_HEAD_SHA", "")
    if base or head:
        if not SHA.fullmatch(base) or not SHA.fullmatch(head):
            raise ValueError("incomplete or invalid pull request identity")
        for commit in (base, head):
            subprocess.run(["git", "merge-base", "--is-ancestor", commit, expected],
                           cwd=ROOT, check=True)
        return ["diff", "--check", base, head, "--"]
    before = env.get("PUSH_BEFORE_SHA", "")
    if before and before != "0" * 40:
        if not SHA.fullmatch(before):
            raise ValueError("invalid push base")
        git("cat-file", "-e", before + "^{commit}")
        return ["diff", "--check", before, expected, "--"]
    parents = git("rev-list", "--parents", "-n", "1", expected).split()
    if len(parents) > 1:
        return ["diff", "--check", parents[1], expected, "--"]
    return ["diff-tree", "--check", "--root", expected, "--"]


def source_gate(env):
    expected = verify_checkout(env.get("GITHUB_SHA", ""))
    for argv in (
        [sys.executable, "-B", "scripts/fork/ci_inventory.py"],
        [sys.executable, "-B", "scripts/fork/source_contract.py", "--check"],
        [sys.executable, "-B", "-m", "unittest", "discover", "-s",
         "scripts/fork/tests", "-p", "test_*.py", "-v"],
        ["git", *diff_args(expected, env)],
    ):
        subprocess.run(argv, cwd=ROOT, check=True)
    verify_checkout(expected)
    print("BK_GAP01_SOURCE_GATE_PASS " + expected)


def run_lint_once(argv, cwd):
    # Stream actual Gradle diagnostics, retain only a bounded rolling window
    # for recognizing Maven's dependency download refusal.
    recent = []
    rate_limited = False
    with subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True, errors="replace") as process:
        assert process.stdout is not None
        for line in iter(lambda: process.stdout.readline(8192), ""):
            print(line, end="", flush=True)
            recent.append(line.strip()[:4096])
            recent = recent[-4:]
            if ("Received status code 429" in line
                    and any("https://repo.maven.apache.org/maven2/" in item for item in recent)
                    and any("Could not download" in item or "Could not GET" in item for item in recent)):
                rate_limited = True
        return process.wait(), rate_limited


def hosted_lint(env, run=run_lint_once, sleep=time.sleep):
    if (env.get("GITHUB_ACTIONS") != "true"
            or env.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise ValueError("Gradle lint is restricted to GitHub-hosted CI")
    expected = verify_checkout(env.get("GITHUB_SHA", ""))
    argv = ["./gradlew", "lintDebug", "--no-configuration-cache", "--no-daemon", "--stacktrace"]
    for attempt in range(3):
        rc, transient = run(argv, ROOT / "manager")
        verify_checkout(expected)
        if rc == 0 or not transient or attempt == 2:
            return rc if rc >= 0 else 128 - rc
        delay = 15 * (attempt + 1)
        print(f"BK_GAP01_MAVEN_429 retry={attempt + 1}/2 delay={delay}s", flush=True)
        sleep(delay)
    raise AssertionError("unreachable")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("source", "checkout", "hosted-lint"))
    args = parser.parse_args()
    try:
        if args.mode == "source":
            source_gate(os.environ)
        elif args.mode == "checkout":
            verify_checkout(os.environ.get("GITHUB_SHA", ""))
        else:
            return hosted_lint(os.environ)
    except subprocess.CalledProcessError as exc:
        return exc.returncode if exc.returncode > 0 else 128 - exc.returncode
    except (ValueError, OSError) as exc:
        print(f"BK_GAP01_CI_REFUSED {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
