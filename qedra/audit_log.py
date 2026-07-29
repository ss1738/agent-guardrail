"""Durable, append-only audit log for the Agent Control Plane.

The Control Plane keeps the gated action trace in memory and signs a receipt at session end. If the
process crashes or is killed mid-run, that trace is lost. `AuditLog` appends every gated entry to a
JSONL file as it happens, so a dead agent still leaves a trail on disk.

Two properties the persisted log keeps:
  - Integrity (no key needed). The public SHA-256 hash-chain is recomputed over the file, so any
    inserted, deleted, reordered, or altered line is caught by `verify_log`.
  - Authenticity (needs the operator's key). `receipt_from_log` reconstructs a signed `Receipt` from
    the persisted entries, so the durable trail can still be handed to a relying party and verified
    with `verify_receipt` exactly like a live receipt.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict

from .control_plane import GENESIS, Entry, Receipt, _chain_step, _signing_payload


class AuditLog:
    """Append-only JSONL sink for gated entries. Pass an instance to `ControlPlane(audit_log=...)`;
    every recorded action is flushed to disk as it happens."""

    def __init__(self, path: str):
        self.path = path

    def append(self, entry: Entry) -> None:
        with open(self.path, "a") as f:
            f.write(json.dumps(asdict(entry), separators=(",", ":")) + "\n")
            f.flush()
            os.fsync(f.fileno())   # durable: survive a crash right after the write

    @staticmethod
    def load(path: str) -> list[Entry]:
        entries: list[Entry] = []
        if os.path.exists(path):
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entries.append(Entry(**json.loads(line)))
        return entries


def verify_log(path: str) -> tuple[bool, str]:
    """Recompute the public hash-chain over the persisted entries. No key required. Catches any
    inserted / deleted / reordered / altered line."""
    entries = AuditLog.load(path)
    head = GENESIS
    for i, e in enumerate(entries):
        head = _chain_step(head, i, e.commit, e.verdict, e.reason, e.executed)
        if head != e.head:
            return False, f"log broken at entry {i}: the trail was altered"
    return True, f"intact: {len(entries)} entries"


def receipt_from_log(path: str, agent_id: str, policy, signing_key) -> Receipt:
    """Reconstruct a signed Receipt from a persisted log (needs the operator's Ed25519 key). Raises if
    the log fails its integrity check, so a tampered trail can never be re-signed into a valid receipt."""
    from cryptography.hazmat.primitives import serialization

    ok, why = verify_log(path)
    if not ok:
        raise ValueError(why)
    entries = AuditLog.load(path)
    head = entries[-1].head if entries else GENESIS
    sig = signing_key.sign(_signing_payload(agent_id, policy.root(), head, len(entries))).hex()
    pub = signing_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return Receipt(
        agent_id=agent_id, policy_id=policy.policy_id, policy_root=policy.root(),
        entries=entries, final_head=head, public_key=pub, signature=sig,
    )
