"""Agent Control Plane: per-agent policy enforcement + an independently-verifiable RECEIPT.

qedra gates a single stream of tool calls. The Control Plane binds a *named, versioned
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
import secrets
from dataclasses import asdict, dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import zk as _zk
from . import zk_ec as _zk_ec
from .guardrail import DEFAULT_SPEC, Action, Guardrail, PolicySpec

GENESIS = hashlib.sha256(b"agent-control-plane/genesis").hexdigest()

# ZK schemes: name -> (module with commit/prove/verify, its group with ser/deser). Both share the same
# policy layer (encode/allowed_set in zk); only the group differs. MODP is the reviewed-shape default;
# secp256k1 ("ec") is ~10x faster / ~8x smaller but is prototype crypto pending external review.
_SCHEMES = {"modp": (_zk, _zk.MODP), "ec": (_zk_ec, _zk_ec.EC)}


# ---------------------------------------------------------------------------
# Policy: a named, versioned, committed classifier. Deterministic and pure, so an
# independent verifier can re-run it over a trace.
# ---------------------------------------------------------------------------
class Policy:
    """A named, versioned policy over agent actions, defined by a PolicySpec. `root()` commits to
    *which* policy this is: the id, the version, and the CONTENT HASH of the spec. Two parties who hold
    the same spec compute the same root, and a receipt issued under a different ruleset (different
    protected branches, different extra patterns) is detectable, because the content hash changes.
    Defaults to the built-in threat-model spec."""

    def __init__(self, policy_id: str, version: str = "1", spec: PolicySpec | None = None):
        self.policy_id = policy_id
        self.version = version
        self.spec = spec or DEFAULT_SPEC
        self._g = Guardrail(self.spec)  # stateless use: only `_classify`, which is pure

    def classify(self, a: Action) -> tuple[str, str]:
        """Return (verdict, reason). Pure: depends only on the action and the committed ruleset."""
        return self._g._classify(a)

    def root(self) -> str:
        return hashlib.sha256(
            f"{self.policy_id}|{self.version}|{self.spec.content_hash()}".encode()
        ).hexdigest()


# ---------------------------------------------------------------------------
# Receipt: the exported, independently-verifiable artifact.
# ---------------------------------------------------------------------------
@dataclass
class Entry:
    verdict: str     # ALLOW | BLOCK | ESCALATE (as recorded by the gate)
    reason: str
    executed: bool    # did the operator actually run it (BLOCK must never be executed)
    commit: str      # sha256(canonical(action) || salt), OR (zk git entries) the decimal Pedersen C.
                     # The chain is over this string either way, so it survives redaction.
    head: str        # public hash-chain head after this entry
    action: dict | None = None   # the raw action, or None if redacted for privacy
    salt: str = ""               # hex salt (sha) or decimal Pedersen r (zk), or "" if redacted
    zk: dict | None = None       # serialized ZK proof (git-branch entries in zk-mode); None otherwise.
                                 # Zero-knowledge, so it leaks nothing even in a full receipt.
    zk_group: str = ""           # which ZK group the proof + commitment use ("modp" | "ec"); "" if not zk


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

    def redact(self, reveal=None) -> tuple["Receipt", dict]:
        """Return (redacted_receipt, witness). Strip the raw actions + salts so the receipt no longer
        leaks the agent's commands or file contents; the chain is over commitments, so the signature
        stays valid. `reveal` = indices to keep in the clear (e.g. only the BLOCKed actions). The
        witness holds the redacted (action, salt) pairs, so the operator can later disclose any subset
        to a verifier and prove those verdicts sound, without revealing the rest."""
        reveal = set(reveal or ())
        red = Receipt.from_json(self.to_json())  # deep copy
        witness: dict = {}
        for i, e in enumerate(red.entries):
            if i not in reveal:
                witness[str(i)] = {"action": e.action, "salt": e.salt}
                e.action, e.salt = None, ""
        return red, witness


def _canon(action: dict) -> str:
    return json.dumps(action, sort_keys=True, separators=(",", ":"))


def _commit(action: dict, salt_hex: str) -> str:
    """A salted commitment to an action. Hides the action's content (commands, file bytes) while
    binding it, so the chain and signature survive redaction and a disclosed action can be checked."""
    return hashlib.sha256((_canon(action) + salt_hex).encode()).hexdigest()


def _chain_step(prev_head: str, index: int, commit: str, verdict: str, reason: str, executed: bool) -> str:
    h = hashlib.sha256()
    h.update(prev_head.encode())
    h.update(f"{index}|{commit}|{verdict}|{reason}|{int(executed)}".encode())
    return h.hexdigest()


def _signing_payload(agent_id: str, policy_root: str, final_head: str, n: int) -> bytes:
    return f"acp/v1|{agent_id}|{policy_root}|{final_head}|{n}".encode()


# ---------------------------------------------------------------------------
# ControlPlane: gate a per-agent action stream, then export a signed receipt.
# ---------------------------------------------------------------------------
class ControlPlane:
    def __init__(self, agent_id: str, policy: Policy, signing_key: Ed25519PrivateKey | None = None,
                 zk: bool | str = False, audit_log=None, on_block=None):
        self.agent_id = agent_id
        self.policy = policy
        self._key = signing_key or Ed25519PrivateKey.generate()
        self._entries: list[Entry] = []
        self._head = GENESIS
        # audit_log: a durable sink (anything with .append(Entry)) written as each action is recorded,
        # so a crashed agent still leaves a tamper-evident trail. on_block: a callback fired when an
        # action is BLOCKED (for a webhook / Slack alert); its failures never break the gate.
        self._audit = audit_log
        self._on_block = on_block
        # zk-mode: git-branch actions are committed with a Pedersen commitment and carry an eager
        # zero-knowledge proof, so they can be redacted yet remain provably in-policy. Other action
        # kinds keep the sha-256 commitment (ZK over regex/shell is out of scope; see ZK_ROADMAP).
        # zk = True/"modp" -> the reviewed-shape default group; zk = "ec" -> secp256k1 (prototype,
        # ~10x faster / ~8x smaller, pending external review).
        self._zk = bool(zk)
        self._group_name = ""
        if zk:
            self._group_name = "modp" if zk is True else str(zk).lower()
            if self._group_name not in _SCHEMES:
                raise ValueError(f"unknown zk group {self._group_name!r} (expected one of {list(_SCHEMES)})")
            self._scheme_mod, self._scheme_group = _SCHEMES[self._group_name]

    @property
    def public_key_hex(self) -> str:
        from cryptography.hazmat.primitives import serialization

        return self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()

    def resume(self, entries: list["Entry"]) -> None:
        """Seed the in-memory chain from a persisted trail so a fresh process appends entries that
        continue the SAME hash-chain. Used by the per-call Claude Code hook, where each tool call is a
        separate process sharing one durable audit log."""
        self._entries = list(entries)
        self._head = entries[-1].head if entries else GENESIS

    def record(self, action: Action, verdict: str, reason: str, executed: bool) -> None:
        """Append an already-decided action to the trace + chain. Use this from an executor that has
        its own gate, so the receipt records the REAL outcome (whether the action actually ran, e.g.
        an ALLOW that a sandbox backstop still refused is recorded as not executed)."""
        ad = asdict(action)
        if self._zk and _zk.supports(action):
            self._record_zk(action, ad, verdict, executed)
            return
        salt = secrets.token_hex(16)
        commit = _commit(ad, salt)
        self._head = _chain_step(self._head, len(self._entries), commit, verdict, reason, executed)
        entry = Entry(verdict, reason, executed, commit, self._head, action=ad, salt=salt)
        self._entries.append(entry)
        self._after_record(entry, action)

    def _after_record(self, entry: "Entry", action: Action) -> None:
        """Durably persist the entry and fire the block alert. An audit-sink or alert failure must
        never break the gate, so both are guarded."""
        if self._audit is not None:
            try:
                self._audit.append(entry)
            except Exception:
                pass
        if entry.verdict == "BLOCK" and self._on_block is not None:
            try:
                self._on_block(action, entry.reason)
            except Exception:
                pass

    def _record_zk(self, action: Action, ad: dict, verdict: str, executed: bool) -> None:
        """Record a git-branch action with a Pedersen commitment + an eager ZK proof. The reason is
        generic (verdict only) so a redacted entry leaks nothing via the reason string; the ZK proof
        is over the SAME commitment (serialized by the chosen group) that goes into the chain, so a
        verifier cannot swap in a different action than the one chained."""
        protected = tuple(self.policy.spec.protected_branches)
        m = _zk.encode(action.op, action.branch, int(action.force), int(action.hard), protected)
        C, r = self._scheme_mod.commit(m)
        proof = self._scheme_mod.prove(action, r, protected)
        commit, salt, reason = self._scheme_group.ser(C), str(r), f"git-branch policy: {verdict}"
        self._head = _chain_step(self._head, len(self._entries), commit, verdict, reason, executed)
        entry = Entry(verdict, reason, executed, commit, self._head, action=ad, salt=salt,
                      zk=proof.to_dict(), zk_group=self._group_name)
        self._entries.append(entry)
        self._after_record(entry, action)

    def gate(self, action: Action) -> str:
        """Classify + record one action. Returns the verdict. A BLOCK is recorded as NOT executed (the
        enforcement guarantee); ALLOW/ESCALATE are recorded as executed."""
        verdict, reason = self.policy.classify(action)
        self.record(action, verdict, reason, verdict != "BLOCK")
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


def verify_receipt(
    receipt: Receipt,
    policy: Policy,
    pinned_public_key: str | None = None,
    witness: dict | None = None,
) -> VerifyResult:
    """Verify a receipt. Works on a full receipt, a redacted one, or a redacted one plus a `witness`
    (which discloses some actions). Integrity, authenticity, and the policy commitment are always
    checked; the soundness re-run is checked for every action that is disclosed (inline or via the
    witness). The result's reason states the disclosure coverage, so a partly-redacted receipt is
    never mistaken for a fully-sound one."""
    witness = witness or {}

    # (0) the receipt must name the policy the verifier holds
    if receipt.policy_root != policy.root():
        return VerifyResult(False, "policy mismatch: receipt was issued under a different policy")

    # (1) public hash-chain integrity (over commitments, so redaction does not break it)
    head = GENESIS
    for i, e in enumerate(receipt.entries):
        head = _chain_step(head, i, e.commit, e.verdict, e.reason, e.executed)
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

    # (3) soundness. Two ways an entry can be proven sound:
    #   - zk proof: the ZK proof is over the SAME Pedersen commitment that is in the chain, so it
    #     proves the *chained* action is one the policy classifies as the recorded verdict, WITHOUT
    #     disclosing it. A relabelled verdict cannot produce an accepting proof over that commitment.
    #   - disclosure: re-run the committed policy on the revealed action and reproduce its verdict.
    # A forged ALLOW is caught by either, even when re-chained and re-signed. Redacted entries with
    # neither a proof nor a disclosure get integrity + authenticity only.
    disclosed = zk_sound = 0
    for i, e in enumerate(receipt.entries):
        act, salt = e.action, e.salt
        if act is None and str(i) in witness:
            act, salt = witness[str(i)]["action"], witness[str(i)]["salt"]

        if e.zk is not None:
            protected = tuple(policy.spec.protected_branches)   # the zk domain uses the policy's set
            name = e.zk_group or "modp"   # "" defaults to modp for receipts predating the group field
            if name not in _SCHEMES:
                return VerifyResult(False, f"entry {i}: unknown zk group {name!r}")
            scheme_mod, scheme_group = _SCHEMES[name]
            proof = _zk.ZKProof.from_dict(e.zk)
            if proof.verdict != e.verdict:
                return VerifyResult(False, f"entry {i}: zk proof verdict does not match the recorded verdict")
            try:
                C = scheme_group.deser(e.commit)
            except (ValueError, TypeError):
                return VerifyResult(False, f"entry {i}: malformed zk commitment for group {name!r}")
            if not scheme_mod.verify(C, proof, protected):
                return VerifyResult(False, f"entry {i}: invalid zk proof (action not provably {e.verdict})")
            if act is not None:  # disclosed: bind the revealed action to the SAME commitment
                if not salt:
                    return VerifyResult(False, f"entry {i}: disclosed zk action is missing its randomness")
                m = _zk.encode(act.get("op", ""), act.get("branch", ""),
                               int(act.get("force", 0)), int(act.get("hard", 0)), protected)
                if scheme_group.ser(scheme_mod.commit(m, int(salt))[0]) != e.commit:
                    return VerifyResult(False, f"entry {i}: disclosed action does not match its zk commitment")
                try:
                    v, _ = policy.classify(Action(**act))
                except TypeError:
                    return VerifyResult(False, f"entry {i}: malformed action")
                if v != e.verdict:
                    return VerifyResult(False, f"unsound verdict at entry {i}: policy says {v}, receipt claims {e.verdict}")
            zk_sound += 1
            continue

        if act is None:
            continue  # redacted with no witness: integrity + authenticity only for this entry
        if _commit(act, salt) != e.commit:
            return VerifyResult(False, f"entry {i}: disclosed action does not match its commitment")
        try:
            v, _ = policy.classify(Action(**act))
        except TypeError:
            return VerifyResult(False, f"entry {i}: malformed action")
        if v != e.verdict:
            return VerifyResult(False, f"unsound verdict at entry {i}: policy says {v}, receipt claims {e.verdict}")
        disclosed += 1

    # (4) enforcement invariant: a BLOCKed action must never be marked executed
    for i, e in enumerate(receipt.entries):
        if e.verdict == "BLOCK" and e.executed:
            return VerifyResult(False, f"entry {i}: a BLOCKed action was executed")

    n = len(receipt.entries)
    sound = disclosed + zk_sound
    if sound == n:
        cover = "untampered and sound" if not zk_sound else f"untampered and sound ({zk_sound} via zk proof)"
    else:
        got = []
        if disclosed:
            got.append(f"{disclosed} disclosed")
        if zk_sound:
            got.append(f"{zk_sound} zk-proven")
        lead = " and ".join(got) + " and sound, " if got else ""
        cover = f"untampered; {lead}{n - sound} redacted"
    return VerifyResult(True, f"verified: {n} actions, policy {receipt.policy_id}, {cover}")
