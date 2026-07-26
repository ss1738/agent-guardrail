"""Agent Control Plane: per-agent policy enforcement + an independently-verifiable RECEIPT.

agent-guardrail gates a single stream of tool calls. The Control Plane binds a *named, versioned
policy* to an *agent identity*, records the gated action trace into a public hash-chain, and exports a
compact **receipt** that a third party (an auditor, a bank, an insurer) can verify WITHOUT trusting the
operator, and WITHOUT the operator's secret:

  1. public SHA-256 hash-chain over the trace   -> tamper-evidence (no insert/delete/reorder/alter)
  2. Ed25519 signature over the chain head       -> binds the trace to the agent's key (verify with the
                                                    public key alone; the operator's secret never leaves)
  3. the policy is committed as a hash           -> proves *which* policy was in force
  4. the verifier RE-RUNS the policy on the trace -> catches a forged ALLOW: a receipt that claims a
                                                    dangerous action was permitted fails, because the
                                                    committed policy would have BLOCKed it.

Check 4 is the point: an honest receipt and a forged one are cryptographically distinguishable by anyone
holding only the receipt + the public policy definition. This is the artifact a relying party pays to
trust, and the "0/N forged-SATISFIED" test in the go/no-go.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .guardrail import Action, Guardrail

GENESIS = hashlib.sha256(b"agent-control-plane/genesis").hexdigest()


# ---------------------------------------------------------------------------
# Policy: a named, versioned, committed classifier. Deterministic and pure, so an
# independent verifier can re-run it over a trace.
# ---------------------------------------------------------------------------
class Policy:
    """A named policy over agent actions. `root()` is a commitment to *which* policy this is; two
    parties who both hold the policy definition compute the same root. v0 wraps the built-in
    agent-guardrail ruleset (bump `ruleset_version` when the rules change)."""

    ruleset_version = "agent-guardrail/threat-model/v1"

    def __init__(self, policy_id: str, version: str = "1"):
        self.policy_id = policy_id
        self.version = version
        self._g = Guardrail()  # stateless use: only `_classify`, which is pure

    def classify(self, a: Action) -> tuple[str, str]:
        """Return (verdict, reason). Pure: depends only on the action and the committed ruleset."""
        return self._g._classify(a)

    def root(self) -> str:
        return hashlib.sha256(
            f"{self.policy_id}|{self.version}|{self.ruleset_version}".encode()
        ).hexdigest()


# ---------------------------------------------------------------------------
# Receipt: the exported, independently-verifiable artifact.
# ---------------------------------------------------------------------------
@dataclass
class Entry:
    action: dict     # dataclasses.asdict(Action)
    verdict: str     # ALLOW | BLOCK | ESCALATE (as recorded by the gate)
    reason: str
    executed: bool    # did the operator actually run it (BLOCK must never be executed)
    head: str        # public hash-chain head after this entry


@dataclass
class Receipt:
    agent_id: str
    policy_id: str
    policy_root: str
    entries: list[Entry] = field(default_factory=list)
    final_head: str = GENESIS
    public_key: str = ""   # hex Ed25519 public key
    signature: str = ""    # hex Ed25519 signature over the signing payload

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))

    @staticmethod
    def from_json(s: str) -> "Receipt":
        d = json.loads(s)
        d["entries"] = [Entry(**e) for e in d["entries"]]
        return Receipt(**d)


def _entry_bytes(index: int, action: dict, verdict: str, reason: str, executed: bool) -> bytes:
    """Canonical, deterministic serialization of one trace entry for the hash-chain."""
    ac = json.dumps(action, sort_keys=True, separators=(",", ":"))
    return f"{index}|{ac}|{verdict}|{reason}|{int(executed)}".encode()


def _chain_step(prev_head: str, index: int, action: dict, verdict: str, reason: str, executed: bool) -> str:
    h = hashlib.sha256()
    h.update(prev_head.encode())
    h.update(_entry_bytes(index, action, verdict, reason, executed))
    return h.hexdigest()


def _signing_payload(agent_id: str, policy_root: str, final_head: str, n: int) -> bytes:
    return f"acp/v1|{agent_id}|{policy_root}|{final_head}|{n}".encode()


# ---------------------------------------------------------------------------
# ControlPlane: gate a per-agent action stream, then export a signed receipt.
# ---------------------------------------------------------------------------
class ControlPlane:
    def __init__(self, agent_id: str, policy: Policy, signing_key: Ed25519PrivateKey | None = None):
        self.agent_id = agent_id
        self.policy = policy
        self._key = signing_key or Ed25519PrivateKey.generate()
        self._entries: list[Entry] = []
        self._head = GENESIS

    @property
    def public_key_hex(self) -> str:
        from cryptography.hazmat.primitives import serialization

        return self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()

    def gate(self, action: Action) -> str:
        """Gate one action. Returns the verdict. A BLOCK is recorded as NOT executed (the enforcement
        guarantee); ALLOW/ESCALATE are recorded as executed."""
        verdict, reason = self.policy.classify(action)
        executed = verdict != "BLOCK"
        ad = asdict(action)
        self._head = _chain_step(self._head, len(self._entries), ad, verdict, reason, executed)
        self._entries.append(Entry(ad, verdict, reason, executed, self._head))
        return verdict

    def receipt(self) -> Receipt:
        payload = _signing_payload(self.agent_id, self.policy.root(), self._head, len(self._entries))
        sig = self._key.sign(payload).hex()
        return Receipt(
            agent_id=self.agent_id,
            policy_id=self.policy.policy_id,
            policy_root=self.policy.root(),
            entries=list(self._entries),
            final_head=self._head,
            public_key=self.public_key_hex,
            signature=sig,
        )


# ---------------------------------------------------------------------------
# Independent verification. Needs only the receipt + the policy definition (+ optionally a pinned
# public key). No operator secret. Returns (ok, reason).
# ---------------------------------------------------------------------------
@dataclass
class VerifyResult:
    ok: bool
    reason: str


def verify_receipt(receipt: Receipt, policy: Policy, pinned_public_key: str | None = None) -> VerifyResult:
    # (0) the receipt must name the policy the verifier holds
    if receipt.policy_root != policy.root():
        return VerifyResult(False, "policy mismatch: receipt was issued under a different policy")

    # (1) public hash-chain integrity: recompute from genesis, catch any tamper
    head = GENESIS
    for i, e in enumerate(receipt.entries):
        head = _chain_step(head, i, e.action, e.verdict, e.reason, e.executed)
        if head != e.head:
            return VerifyResult(False, f"chain broken at entry {i}: trace was altered")
    if head != receipt.final_head:
        return VerifyResult(False, "final head mismatch: entries were added, dropped, or reordered")

    # (2) signature binds the trace to the agent's key (verify with the public key only)
    pub_hex = pinned_public_key or receipt.public_key
    if pinned_public_key and receipt.public_key != pinned_public_key:
        return VerifyResult(False, "public key does not match the pinned identity")
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        pub.verify(
            bytes.fromhex(receipt.signature),
            _signing_payload(receipt.agent_id, receipt.policy_root, receipt.final_head, len(receipt.entries)),
        )
    except (InvalidSignature, ValueError):
        return VerifyResult(False, "invalid signature over the chain head")

    # (3) THE soundness re-run: the committed policy, re-run on each action, must reproduce the
    #     recorded verdict. A forged ALLOW on a would-be-BLOCK action is caught here.
    for i, e in enumerate(receipt.entries):
        try:
            v, _ = policy.classify(Action(**e.action))
        except TypeError:
            return VerifyResult(False, f"entry {i}: malformed action")
        if v != e.verdict:
            return VerifyResult(
                False, f"unsound verdict at entry {i}: policy says {v}, receipt claims {e.verdict}"
            )

    # (4) enforcement invariant: a BLOCKed action must never be marked executed
    for i, e in enumerate(receipt.entries):
        if e.verdict == "BLOCK" and e.executed:
            return VerifyResult(False, f"entry {i}: a BLOCKed action was executed")

    return VerifyResult(True, f"verified: {len(receipt.entries)} actions, policy {receipt.policy_id}, untampered and sound")
