"""Real-world validation: run the guardrail over ACTUAL shell commands from real
GitHub Actions workflows in genuine, trusted, popular repos. Measures the honest
false-friction rate, how often the guardrail wrongly blocks/escalates legitimate
developer commands. Read-only: nothing is executed. Uses `gh api`.

This tests the panel's #1 adoption risk: a guardrail that over-blocks real work
gets muted after two PRs.
"""
from __future__ import annotations
import json
import re
import subprocess
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from agent_guardrail.guardrail import Guardrail, Action

TRUSTED = [
    "rust-lang/rust", "tokio-rs/tokio", "BurntSushi/ripgrep", "serde-rs/serde",
    "sharkdp/bat", "sharkdp/fd", "clap-rs/clap", "rust-lang/cargo",
    "cli/cli", "denoland/deno", "astral-sh/ruff", "pallets/flask",
]


def gh(path):
    r = subprocess.run(["gh", "api", path], capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        return None
    return r.stdout


def list_workflows(repo):
    out = gh(f"repos/{repo}/contents/.github/workflows")
    if not out:
        return []
    try:
        return [f["path"] for f in json.loads(out) if f["name"].endswith((".yml", ".yaml"))]
    except Exception:
        return []


def fetch_raw(repo, path):
    out = gh(f"repos/{repo}/contents/{path}")
    if not out:
        return ""
    try:
        import base64
        return base64.b64decode(json.loads(out)["content"]).decode("utf-8", "replace")
    except Exception:
        return ""


def extract_run_commands(yaml_text):
    """Pull the shell command lines from `run:` steps (inline and `run: |` blocks).
    Regex-based (robust to the many YAML dialects in real workflows)."""
    cmds = []
    lines = yaml_text.splitlines()
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)-?\s*run:\s*(\|[-+]?|>[-+]?)?\s*(.*)$", lines[i])
        if m:
            indent, block, inline = m.group(1), m.group(2), m.group(3)
            if block:  # multi-line block: gather more-indented lines
                base = len(indent)
                i += 1
                while i < len(lines):
                    if lines[i].strip() == "":
                        i += 1
                        continue
                    cur = len(lines[i]) - len(lines[i].lstrip())
                    if cur <= base:
                        break
                    cmds.append(lines[i].strip())
                    i += 1
                continue
            elif inline.strip():
                cmds.append(inline.strip())
        i += 1
    # drop shell noise that isn't a command line
    out = []
    for c in cmds:
        c = c.strip()
        if not c or c.startswith("#") or re.match(r"^(if|then|else|fi|do|done|for|while|case|esac)\b", c):
            continue
        # skip line-continuations / env assignments only
        out.append(c)
    return out


def main():
    guard = Guardrail()
    tally = {"ALLOW": 0, "ESCALATE": 0, "BLOCK": 0}
    escalated, blocked = [], []
    total_cmds, repos_ok = 0, 0

    WF_PER_REPO = 3   # sample the first N workflow files per repo (disclosed in the result line)
    for repo in TRUSTED:
        wfs = list_workflows(repo)[:WF_PER_REPO]
        if not wfs:
            print(f"  (skip {repo}: no workflows readable)")
            continue
        repos_ok += 1
        rc = 0
        for wf in wfs:
            for cmd in extract_run_commands(fetch_raw(repo, wf)):
                total_cmds += 1
                rc += 1
                d = guard.check(Action("shell", cmd=cmd))
                tally[d.verdict] += 1
                if d.verdict == "ESCALATE":
                    escalated.append((repo, cmd))
                elif d.verdict == "BLOCK":
                    blocked.append((repo, cmd, d.reason))
        print(f"  ✓ {repo:24s} {rc:4d} real run-commands classified")

    print("\n" + "=" * 60)
    print(f"REAL-WORLD RESULT: {total_cmds} legit commands from {repos_ok} trusted repos "
          f"(first {WF_PER_REPO} workflow files each; a sample, not exhaustive)")
    print("=" * 60)
    for k in ("ALLOW", "ESCALATE", "BLOCK"):
        pct = 100 * tally[k] / max(total_cmds, 1)
        print(f"  {k:9s}: {tally[k]:4d}  ({pct:4.1f}%)")
    print()
    print(f"  FALSE BLOCKS on legit commands (must be ~0): {len(blocked)}")
    for repo, cmd, why in blocked[:15]:
        print(f"      ⛔ [{repo}] {cmd[:70]}  {why}")
    print()
    print(f"  ESCALATED (fail-closed, would ask a human), sample of {len(escalated)}:")
    for repo, cmd in escalated[:12]:
        print(f"      ⚠  [{repo}] {cmd[:75]}")


if __name__ == "__main__":
    main()
