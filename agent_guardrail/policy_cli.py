"""`agent-guardrail-policy`: author and inspect a PolicySpec.

A policy is data: the protected branches plus optional extra secret / shell-denylist patterns. This
tool writes a spec.json, prints its content hash (the commitment a receipt binds), and shows the policy
root a verifier checks. Ship the spec to relying parties; they verify with
`agent-guardrail-verify --policy-spec spec.json`.

    agent-guardrail-policy init --protected main,release --out spec.json
    agent-guardrail-policy show spec.json --policy-id acme-prod --policy-version 1
    agent-guardrail-policy hash spec.json          # just the content hash (scriptable)
"""
from __future__ import annotations

import argparse
import re
import sys

from .guardrail import DEFAULT_SPEC, PolicySpec


def _load(path: str) -> PolicySpec:
    with open(path) as f:
        return PolicySpec.from_json(f.read())


def _bad_patterns(spec: PolicySpec) -> list[tuple[str, str]]:
    bad = []
    for p in tuple(spec.extra_secret_patterns) + tuple(spec.extra_shell_denylist):
        try:
            re.compile(p)
        except re.error as e:
            bad.append((p, str(e)))
    return bad


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="agent-guardrail-policy", description="Author and inspect a PolicySpec.")
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("init", help="write a spec.json")
    pi.add_argument("--protected", default=",".join(DEFAULT_SPEC.protected_branches),
                    help="comma-separated protected branches (default: the built-in set)")
    pi.add_argument("--secret-pattern", action="append", default=[],
                    help="extra regex flagged as a secret (repeatable)")
    pi.add_argument("--shell-deny", action="append", default=[],
                    help="extra regex blocked outright in shell (repeatable)")
    pi.add_argument("--out", help="path to write (default: stdout)")

    ps = sub.add_parser("show", help="inspect a spec.json")
    ps.add_argument("spec")
    ps.add_argument("--policy-id", help="also print the policy root for this id")
    ps.add_argument("--policy-version", default="1")

    ph = sub.add_parser("hash", help="print a spec's content hash")
    ph.add_argument("spec")

    args = p.parse_args(argv)

    if args.cmd == "init":
        protected = tuple(b.strip() for b in args.protected.split(",") if b.strip())
        spec = PolicySpec(protected_branches=protected,
                          extra_secret_patterns=tuple(args.secret_pattern),
                          extra_shell_denylist=tuple(args.shell_deny))
        bad = _bad_patterns(spec)
        if bad:
            for pat, err in bad:
                print(f"error: invalid regex {pat!r}: {err}", file=sys.stderr)
            return 2
        if args.out:
            with open(args.out, "w") as f:
                f.write(spec.to_json() + "\n")
            print(f"wrote {args.out}  (content hash {spec.content_hash()[:16]}...)")
        else:
            print(spec.to_json())
        return 0

    try:
        spec = _load(args.spec)
    except Exception as e:
        print(f"error: could not read spec: {e}", file=sys.stderr)
        return 2

    if args.cmd == "hash":
        print(spec.content_hash())
        return 0

    # show
    print(f"protected branches : {', '.join(spec.protected_branches) or '(none)'}")
    print(f"extra secret pats  : {list(spec.extra_secret_patterns) or '(none)'}")
    print(f"extra shell deny   : {list(spec.extra_shell_denylist) or '(none)'}")
    print(f"ruleset version    : {spec.ruleset_version}")
    print(f"content hash       : {spec.content_hash()}")
    if args.policy_id:
        from .control_plane import Policy
        root = Policy(args.policy_id, args.policy_version, spec).root()
        print(f"policy root        : {root}  (id={args.policy_id} v={args.policy_version})")
    bad = _bad_patterns(spec)
    if bad:
        print(f"WARNING: {len(bad)} invalid regex pattern(s) will fail at load time:", file=sys.stderr)
        for pat, err in bad:
            print(f"  {pat!r}: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
