"""`qedra-attest`: turn an agent session's audit log into a signed, verifiable receipt.

The hook (`qedra-hook` with GUARDRAIL_AUDIT_LOG set) appends every gated action to a durable, hash-chained
JSONL log as the agent runs. This command reconstructs that log into a single Ed25519-signed Receipt that any
third party -- an auditor, an insurer, a platform, another agent -- can verify with `qedra-verify` using only
the public key. No trust in the operator, no secret shared.

    qedra-attest session.jsonl --agent-id my-agent --out receipt.json
    qedra-verify receipt.json --pin-key <printed-public-key>

The signing key lives at ~/.qedra/signing_key (raw Ed25519, hex, mode 600) and is generated on first use.
Its public key is printed so a relying party can pin the agent's identity to it. The log's integrity is
checked first, so a tampered trail can never be re-signed into a valid receipt. Exit 0 = attested, 1 = the
log failed its integrity check or was unreadable, 2 = usage error.
"""
from __future__ import annotations

import argparse
import os
import sys

from .audit_log import receipt_from_log, verify_log
from .control_plane import Policy


def _load_or_create_key(path: str):
    """Load a raw Ed25519 private key from `path` (hex), or generate + persist one at mode 600."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    path = os.path.expanduser(path)
    if os.path.exists(path):
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(open(path).read().strip()))
    key = Ed25519PrivateKey.generate()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    raw = key.private_bytes_raw().hex()
    # write with restrictive permissions from the start (do not widen a pre-existing file)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(raw)
    return key


def _build_policy(args) -> Policy:
    spec = None
    if args.policy_spec:
        from .guardrail import PolicySpec
        spec = PolicySpec.from_json(open(args.policy_spec).read())
    presets = [p.strip() for p in (args.preset or "").split(",") if p.strip()]
    if presets:
        from .presets import preset_spec
        from .guardrail import DEFAULT_SPEC
        spec = preset_spec(*presets, base=spec or DEFAULT_SPEC)
    return Policy(args.policy_id, args.policy_version, spec)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="qedra-attest",
        description="Sign an agent session's audit log into a verifiable receipt.",
    )
    p.add_argument("log", help="path to the audit log (JSONL) written by the hook via GUARDRAIL_AUDIT_LOG")
    p.add_argument("--agent-id", default=os.environ.get("GUARDRAIL_AGENT_ID", "qedra-agent"),
                   help="the agent identity this receipt is bound to")
    p.add_argument("--policy-id", default=os.environ.get("GUARDRAIL_POLICY_ID", "qedra"))
    p.add_argument("--policy-version", default=os.environ.get("GUARDRAIL_POLICY_VERSION", "1"))
    p.add_argument("--preset", help="comma-separated presets layered on the default spec (e.g. 'devops')")
    p.add_argument("--policy-spec", help="path to a PolicySpec JSON (overrides the built-in default)")
    p.add_argument("--key", default=os.environ.get("GUARDRAIL_SIGNING_KEY", "~/.qedra/signing_key"),
                   help="Ed25519 signing key file (created on first use, mode 600)")
    p.add_argument("--out", help="write the receipt JSON here (default: stdout)")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress the human-readable summary on stderr")
    args = p.parse_args(argv)

    if not os.path.exists(args.log):
        print(f"error: no such log: {args.log}", file=sys.stderr)
        return 1

    # integrity first: refuse to sign a tampered trail
    ok, why = verify_log(args.log)
    if not ok:
        print(f"error: {why}; refusing to attest", file=sys.stderr)
        return 1

    try:
        policy = _build_policy(args)
        key = _load_or_create_key(args.key)
        receipt = receipt_from_log(args.log, args.agent_id, policy, key)
    except Exception as e:
        print(f"error: could not build receipt: {e}", file=sys.stderr)
        return 1

    out_json = receipt.to_json()
    if args.out:
        open(args.out, "w").write(out_json)
    else:
        print(out_json)

    if not args.quiet:
        n = len(receipt.entries)
        blocked = sum(1 for e in receipt.entries if e.verdict == "BLOCK")
        dest = args.out or "stdout"
        print(f"attested: {n} entries ({blocked} blocked), agent '{receipt.agent_id}' -> {dest}",
              file=sys.stderr)
        print(f"public key: {receipt.public_key}", file=sys.stderr)
        verify_target = args.out or "receipt.json"
        print(f"verify with:  qedra-verify {verify_target} --pin-key {receipt.public_key}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
