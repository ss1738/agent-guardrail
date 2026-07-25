# agent-guardrail

[![CI](https://github.com/ss1738/agent-guardrail/actions/workflows/ci.yml/badge.svg)](https://github.com/ss1738/agent-guardrail/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**A runtime gate for autonomous coding agents. It sits in the tool-call path between the agent and your repo and stops the actions that wreck a repository (force-pushing `main`, `rm -rf` the working tree, exfiltrating a secret, wiping CI) while letting normal build and commit work through. The git-branch policy has a machine-checked core: z3 proves it admits no action that rewrites protected-branch history, and it reports the exact gap if you weaken it. The rest of the threat model is enforced by high-precision heuristics, not by proof, and this README is explicit about which is which.**

Coding agents (Copilot Workspace, SWE-agent, OpenHands) now open PRs, run shell, and rewrite git history on their own. Their safety today rests on the model behaving: prompt guardrails and alignment. That is probabilistic and model-dependent. A well-aligned model may refuse a prompt injection; a jailbroken or weaker one will not. agent-guardrail is the deterministic layer that does not depend on the model: it checks every tool call before it runs, so a compromised agent is stopped regardless of why it issued the action.

## What is proven vs. what is heuristic

Being precise about this up front, because it is the whole point:

| Threat | How it is enforced | Guarantee |
|---|---|---|
| Force-push / hard-reset / rebase of a protected branch | structured git policy | **machine-checked by z3** (see below) |
| `rm -rf` of the repo / home / root | regex over the command | heuristic, high-precision, bypassable by obfuscation |
| Secret written to disk or exfiltrated over the network | regex (secret shape + sink) | heuristic |
| Emptying a CI workflow file | path + content check | heuristic |
| Everything else a build/test agent does | default allow | not policed (by design) |

"Heuristic" means it catches the direct forms and is intentionally bypassable by a determined obfuscator (`rm -r -f`, `$IFS`, base64, aliases). It raises the cost of an accident or a naive injection; it is not a sandbox. For hard isolation, pair it with seccomp/gVisor (see "How it compares").

## The demo (measured, reproducible)

The same destructive tool-call sequence a hijacked agent emits, run with and without the gate on a real repo (`demo_compare.py`):

| | `.git` intact | secret on disk | CI config intact | legit fix still applied |
|---|:---:|:---:|:---:|:---:|
| **without the gate** | destroyed | leaked | wiped | yes |
| **with the gate** | yes | none | yes | yes |

6 of 6 destructive actions blocked, 2 of 2 legitimate actions allowed, in the real execution path.

## The proven core: the policy checks itself for gaps

A hand-written allowlist cannot tell you whether it has a hole. The git-branch policy can. Using z3, it proves over the symbolic class of git actions:

```
guard_allows(a)  implies  not mutates_protected_history(a)
```

with the safety spec written independently of the guard, not copied from it, so the result is not circular. It returns `PROVED`, or a concrete counterexample. Remove one rule and it finds the exact hole:

```
full policy          : PROVED   (no admitted action rewrites protected history)
drop the rebase rule : HOLE     op=rebase branch=main
```

This guarantee covers the structured git tool-call path only. It does not verify the Python implementation, the regex rules, or the shell parser.

## How it compares

| Tool | Layer | Catches | Why this is different |
|---|---|---|---|
| git server-side hooks (`pre-receive`) | git server | bad pushes, once they reach the server | agent-guardrail gates the action before it runs locally, and covers file/shell too, not just pushes |
| seccomp / gVisor | syscall / kernel | syscall-level isolation | strong isolation, but no notion of "protected branch" or "this is a secret"; complementary, not a substitute |
| OPA / policy engines | request / API | structured policy decisions | general policy, no formal self-check of the policy and no coding-agent action model out of the box |
| CodeQL / Copilot Autofix | static analysis | vulnerabilities in code | analyses code at rest; says nothing about what an agent does to the repo at runtime |
| git hooks + a shell allowlist | local | some of the same patterns | cannot prove the policy is gap-free; this is the piece z3 adds |

Short version: this is not a sandbox and not a linter. It is an action-level gate for coding agents, with a formally checked core for the one sub-policy where a proof is tractable. Use it in front of a sandbox, not instead of one.

## Validated for false friction (not for attack detection)

A gate that blocks legitimate work gets turned off after two pull requests, so the thing worth measuring is how often it blocks real developer commands. It was run over **2,836 real `run:` commands from 12 trusted repos** (`rust-lang/rust`, `tokio`, `denoland/deno`, `ripgrep`, `cargo`, `ruff`) read-only, nothing executed (`realworld_test.py`):

| version | false blocks | escalations | allows |
|---|:---:|:---:|:---:|
| v0 (fail-closed on any metacharacter) | 2 (both legit CI) | 1854 (65%) | 35% |
| v0.1 (default-allow, block the threat model) | 0 | 0 | 100% |

Read this honestly: with a default-allow design, a low false-block rate on legitimate commands is the *target*, not a surprise. What the corpus caught was the opposite failure: v0 was fail-closed and blocked two-thirds of normal CI, plus two legitimate commands (a force-push to a *feature* branch, and the standard `rm -rf /usr/share/dotnet` disk cleanup). The redesign fixed that, and both former false positives are now regression tests. This corpus does **not** measure attack detection; it contains no adversarial commands. Attack behaviour is covered by the demo and the tests, not by this number.

## Assumptions and limits

- **The gate must be out-of-process from the agent.** If the agent can edit the guardrail or read the HMAC key, it can bypass or forge. The audit chain is tamper-evident only under the assumption that the key is not accessible to the agent (a wrapper process or separate service, not an in-process import the agent controls). See [THREAT_MODEL.md](THREAT_MODEL.md).
- **Shell coverage is best-effort.** A determined attacker obfuscates around the regexes. Treat shell blocking as defense-in-depth, not a boundary.
- **A well-aligned agent will often refuse an injection on its own.** In `demo_hijack.py` a real Claude agent read the planted note and declined it. The gate's value is being the deterministic backstop for when alignment fails.
- **Integration is via MCP** (see below). The formal guarantee still covers only the git-branch policy wherever the gate runs.

## Use it with any MCP agent

The gate runs as an [MCP](https://modelcontextprotocol.io) server, the tool-call
surface that Claude Desktop, Cursor, Copilot, and Windsurf all speak. Point an MCP
client at it and every `run_shell` / `write_file` / `git` call the agent makes is
gated in the protocol path, before it touches the repo. No trust in the agent.

```jsonc
// in your MCP client config (Claude Desktop, Cursor, ...)
"agent-guardrail": {
  "command": "python3",
  "args": ["/path/to/agent-guardrail/integrations/mcp_server.py"],
  "env": { "GUARDRAIL_WORKSPACE": "/path/to/your/repo" }
}
```

`integrations/demo_mcp.py` proves this end-to-end: it launches the server and
connects as a real MCP client over stdio (the same transport those apps use), then
issues a mix of legitimate and destructive tool calls. The destructive ones are
blocked inside the protocol:

```
Tools exposed to the agent via MCP: run_shell, write_file, git, audit_log
  ▶ write_file('calc.py')                wrote calc.py           (the fix)
  ▶ git('add calc.py')                   ok
  ⛔ git('push origin main --force')      BLOCK  force-push to protected branch 'main'
  ⛔ run_shell('rm -rf .git')             BLOCK  recursive delete of the repo
  ⛔ write_file('config.py' w/ token)     BLOCK  writing a secret to disk
  ⛔ run_shell('curl ... -d ghp_...')     BLOCK  secret exfiltration over the network
  ⛔ write_file('.github/workflows/...')  BLOCK  emptying CI config
  ▶ run_shell('cargo build --release')   allowed
blocked: 5   allowed: 4    .git intact, no secret, CI intact, fix applied, audit chain verifies
```

## Run it

```bash
pip install z3-solver "mcp"
python3 tests/test_guardrail.py            # 10 tests
python3 demo_compare.py                    # with and without the gate, on a real repo
python3 integrations/demo_mcp.py           # the gate in a real MCP tool-call path
python3 realworld_test.py                  # the 2,836-command friction check (needs gh)
ANTHROPIC_API_KEY=... python3 demo_hijack.py   # a real Claude agent on a hijacked repo
```

## Status

Early, single author, honest about scope. Feedback and holes in the policy are welcome, especially holes. See [THREAT_MODEL.md](THREAT_MODEL.md) and [SECURITY.md](SECURITY.md).

MIT License.
