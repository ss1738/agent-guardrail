"""`agent-guardrail-verify` -- the relying-party side of the Agent Control Plane.

An auditor, bank, or insurer receives a receipt (JSON) and checks it against the policy THEY hold and,
optionally, a public key THEY have pinned to the agent's identity. No operator secret, no trust in the
issuer. Exit 0 = verified, 1 = rejected, 2 = usage error.

    agent-guardrail-verify receipt.json
    cat receipt.json | agent-guardrail-verify -            # from stdin
    agent-guardrail-verify receipt.json --policy-id acme-prod-agent-policy --policy-version 1
    agent-guardrail-verify receipt.json --pin-key <hex-ed25519-public-key>
"""
from __future__ import annotations

import argparse
import sys

from .control_plane import Policy, Receipt, verify_receipt
from .registry import Registry


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="agent-guardrail-verify",
        description="Independently verify an Agent Control Plane receipt.",
    )
    p.add_argument("receipt", help="path to the receipt JSON, or '-' for stdin")
    p.add_argument("--policy-id", help="the policy id YOU expect (default: the receipt's own claim)")
    p.add_argument("--policy-version", help="the policy version YOU expect (default: the receipt's)")
    p.add_argument("--pin-key", help="hex Ed25519 public key pinned to this agent's identity")
    p.add_argument("--registry", help="path to an agent-identity registry (agent_id -> pinned key) YOU control")
    p.add_argument("-q", "--quiet", action="store_true", help="print only VERIFIED/REJECTED")
    args = p.parse_args(argv)

    try:
        raw = sys.stdin.read() if args.receipt == "-" else open(args.receipt).read()
        receipt = Receipt.from_json(raw)
    except FileNotFoundError:
        print(f"error: no such file: {args.receipt}", file=sys.stderr)
        return 2
    except Exception as e:  # malformed JSON / receipt
        print(f"error: could not parse receipt: {e}", file=sys.stderr)
        return 2

    # The verifier supplies the policy THEY trust; default to the receipt's own claim for convenience
    # (the soundness re-run + root commitment are what actually bind it).
    policy = Policy(
        args.policy_id or receipt.policy_id,
        args.policy_version or "1",
    )

    # Pin the agent's key: explicit --pin-key wins; else look it up in the registry (and reject an
    # agent the relying party has not registered).
    pin = args.pin_key
    if args.registry and not pin:
        expected = Registry.load(args.registry).key_for(receipt.agent_id)
        if expected is None:
            print(f"REJECTED: agent '{receipt.agent_id}' is not in the registry", file=sys.stderr)
            return 1
        pin = expected

    result = verify_receipt(receipt, policy, pinned_public_key=pin)

    if args.quiet:
        print("VERIFIED" if result.ok else "REJECTED")
    else:
        n = len(receipt.entries)
        blocked = sum(e.verdict == "BLOCK" for e in receipt.entries)
        head = "VERIFIED" if result.ok else "REJECTED"
        print(f"{head}: {result.reason}")
        print(f"  agent={receipt.agent_id}  policy={receipt.policy_id}  "
              f"actions={n} ({blocked} blocked)  key={receipt.public_key[:16]}...")
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
