"""`qedra-redact`: strip a receipt's raw actions for sharing, keeping the proof valid.

An operator holds a full receipt (with the raw commands and file contents). To share it with an auditor
or insurer without leaking that content, redact it: the signature and integrity survive (the chain is
over commitments), and the separately-written witness lets you later disclose any subset to prove those
verdicts sound.

    qedra-redact receipt.json --out redacted.json --witness witness.json
    qedra-redact receipt.json --reveal 2,3 --out redacted.json     # keep the blocked ones in the clear
"""
from __future__ import annotations

import argparse
import json
import sys

from .control_plane import Receipt


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="qedra-redact",
        description="Redact a receipt for sharing; the signature stays valid.",
    )
    p.add_argument("receipt", help="path to the full receipt JSON")
    p.add_argument("--out", required=True, help="path to write the redacted receipt")
    p.add_argument("--witness", help="path to write the disclosure witness (needed to prove soundness later)")
    p.add_argument("--reveal", default="", help="comma-separated entry indices to keep in the clear (default: redact all)")
    args = p.parse_args(argv)

    try:
        with open(args.receipt) as f:
            receipt = Receipt.from_json(f.read())
    except FileNotFoundError:
        print(f"error: no such file: {args.receipt}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"error: could not parse receipt: {e}", file=sys.stderr)
        return 2

    try:
        reveal = [int(x) for x in args.reveal.split(",") if x.strip()]
    except ValueError:
        print("error: --reveal must be comma-separated integers", file=sys.stderr)
        return 2

    redacted, wit = receipt.redact(reveal=reveal)
    with open(args.out, "w") as f:
        f.write(redacted.to_json())
    if args.witness:
        with open(args.witness, "w") as f:
            json.dump(wit, f)

    n = len(redacted.entries)
    kept = len([i for i in reveal if 0 <= i < n])
    msg = f"redacted {n - kept}/{n} actions -> {args.out}"
    if args.witness:
        msg += f"; witness -> {args.witness}"
    print(msg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
