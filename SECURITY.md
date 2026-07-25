# Security policy

## Scope and honest expectations

agent-guardrail is an action-level gate for coding agents with a formally checked
git-branch core and heuristic enforcement of the rest of its threat model (see
[THREAT_MODEL.md](THREAT_MODEL.md)). It is defense in depth, not a sandbox. The
heuristic rules (shell, secret, CI) are intentionally bypassable by obfuscation and
are not claimed to be complete against a determined attacker.

## Reporting a hole

Holes in the policy are the most useful contribution. If you find:

- a protected-history rewrite the z3 core admits (this would contradict the proof),
- an obfuscation that evades the shell/secret/CI heuristics,
- or a way for an out-of-process agent to bypass the gate,

please open an issue, or for anything you consider sensitive, contact the maintainer
before public disclosure. Include the exact tool call and the verdict you expected.

## What is not a vulnerability

- Bypassing a heuristic rule by obfuscation at the shell. This is documented and
  expected; the shell layer is best-effort. Report it anyway if it is a common,
  non-obvious form, but it is a precision improvement, not a boundary break.
- Damage caused when the agent controls the gate process or the HMAC key. That is
  outside the stated assumptions.
