"""Agent identity registry: bind an agent_id to a pinned Ed25519 public key.

A receipt is internally sound on its own (chain + signature + policy re-run), but it carries its OWN
public key, so on its own it proves "*some* key signed a policy-compliant trace", not "*this agent's*
key did". The relying party closes that gap by pinning each agent's public key out-of-band, once, in a
registry they control (exactly how a CA or an SSH known_hosts file works). Verification then also checks
the receipt's key matches the registered identity.

The registry is a trust root the verifier holds; it is not signed by the operator (that would be
circular). Keep it under the relying party's control.
"""
from __future__ import annotations

import json
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def _valid_ed25519_hex(pub_hex: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        return True
    except (ValueError, TypeError):
        return False


class Registry:
    """agent_id -> pinned Ed25519 public key (hex). Optionally persisted to a JSON file."""

    def __init__(self, path: str | None = None):
        self.path = path
        self.keys: dict[str, str] = {}

    @classmethod
    def load(cls, path: str) -> "Registry":
        r = cls(path)
        if os.path.exists(path):
            with open(path) as f:
                r.keys = json.load(f)
        return r

    def save(self) -> None:
        if self.path:
            with open(self.path, "w") as f:
                json.dump(self.keys, f, indent=2, sort_keys=True)

    def register(self, agent_id: str, public_key_hex: str) -> None:
        if not _valid_ed25519_hex(public_key_hex):
            raise ValueError(f"not a valid Ed25519 public key: {public_key_hex!r}")
        self.keys[agent_id] = public_key_hex
        self.save()

    def key_for(self, agent_id: str) -> str | None:
        return self.keys.get(agent_id)
