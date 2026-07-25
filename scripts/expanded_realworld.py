"""Bigger, less-hand-picked real-world test. Instead of 12 chosen repos, pull the
most-starred repos across many languages via GitHub search, take their real CI
`run:` commands, and run the guardrail over them. Read-only, nothing executed.
Reports the allow/escalate/block split and EVERY false block for inspection.
"""
import json
import subprocess
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent_guardrail.guardrail import Guardrail, Action
from realworld_test import extract_run_commands, list_workflows, fetch_raw  # reuse

LANGS = ["rust", "python", "javascript", "typescript", "go", "cpp", "java", "ruby", "shell"]


def gh_json(path):
    r = subprocess.run(["gh", "api", path], capture_output=True, text=True, timeout=30)
    return json.loads(r.stdout) if r.returncode == 0 else None


def top_repos():
    """Most-starred repos per language (a broad, not-hand-picked sample)."""
    repos = []
    for lang in LANGS:
        d = gh_json(f"search/repositories?q=language:{lang}+stars:>5000&sort=stars&per_page=6")
        if d:
            repos += [r["full_name"] for r in d.get("items", [])]
    return sorted(set(repos))


def main():
    guard = Guardrail()
    tally = {"ALLOW": 0, "ESCALATE": 0, "BLOCK": 0}
    blocked, escalated = [], []
    total, repos_with_ci = 0, 0
    repos = top_repos()
    print(f"sampled {len(repos)} of the most-starred repos across {len(LANGS)} languages\n")
    for repo in repos:
        wfs = list_workflows(repo)[:3]
        if not wfs:
            continue
        repos_with_ci += 1
        n = 0
        for wf in wfs:
            for cmd in extract_run_commands(fetch_raw(repo, wf)):
                total += 1
                n += 1
                d = guard.check(Action("shell", cmd=cmd))
                tally[d.verdict] += 1
                if d.verdict == "BLOCK":
                    blocked.append((repo, cmd, d.reason))
                elif d.verdict == "ESCALATE":
                    escalated.append((repo, cmd))
        if n:
            print(f"  {repo:34s} {n:4d} commands")

    print("\n" + "=" * 64)
    print(f"RESULT: {total} real CI commands from {repos_with_ci} repos")
    print("=" * 64)
    for k in ("ALLOW", "ESCALATE", "BLOCK"):
        print(f"  {k:9s}: {tally[k]:5d}  ({100*tally[k]/max(total,1):4.1f}%)")
    print(f"\n  FALSE BLOCKS on legitimate commands (every one, for inspection): {len(blocked)}")
    for repo, cmd, why in blocked:
        print(f"      [{repo}] {cmd[:72]}\n          -> {why}")
    print(f"\n  ESCALATED (fail-closed, asks a human): {len(escalated)}")
    for repo, cmd in escalated[:20]:
        print(f"      [{repo}] {cmd[:72]}")


if __name__ == "__main__":
    main()
