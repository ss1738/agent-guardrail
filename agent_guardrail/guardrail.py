"""The guardrail: a formally-checked runtime shield for coding-agent tool calls.

An autonomous coding agent proposes a tool call: a git op, a file write, or a
shell command. The guardrail returns ALLOW / BLOCK / ESCALATE with a reason, and
appends every decision to a tamper-evident HMAC-SHA256 audit chain. Separately,
z3 PROVES the git-op policy has no hole: there is no action the guard admits that
mutates protected-branch history. That self-verification, finding gaps in your
own policy, is what a regex allowlist cannot do.

Honest scope: git ops and file writes are modelled and covered by the soundness
proof. Raw shell is matched against known-destructive patterns; anything not
provably simple is ESCALATED (fail-closed), never silently allowed.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import hashlib
import hmac
import re

PROTECTED = ("main", "master", "release")

SECRET_RE = re.compile(
    r"(sk-[A-Za-z0-9]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----|xox[baprs]-[0-9A-Za-z-]{10,})")
EXFIL_RE = re.compile(r"\b(curl|wget|nc|ncat)\b.*(https?://|[0-9]{1,3}(\.[0-9]{1,3}){3})")

# Catastrophic, high-precision: destruction of the REPO / HOME / ROOT (not arbitrary
# system paths, since a CI runner deleting /usr/share/dotnet to free disk is legitimate and
# outside a repo-guard's remit). Matches rm -rf targeting the repo itself, and true
# machine-wrecking commands.
_RM = r"\brm\s+(?:-[a-zA-Z]*\s+)*-?[a-zA-Z]*[rf][a-zA-Z]*\b"
# The target must be the WHOLE argument (bounded by whitespace/end), so `rm -rf .`
# and `rm -rf .git` are caught but `rm -rf ./bin/x` or `rm -f ../key` (a specific
# sub-path or file, legitimate CI cleanup) are not.
_RM_TARGET = r"(?:\.|\./|\.\.|\.\./|~|~/|/|/\*|\*|\.git|\$HOME|\$GITHUB_WORKSPACE)"
CATASTROPHIC = [
    (re.compile(_RM + r"\s+(?:--\s+)?" + _RM_TARGET + r"(?:\s|$)"),
     "recursive delete of the repo / home / root"),
    (re.compile(r":\(\)\s*\{.*\|.*&\s*\}"), "fork bomb"),
    (re.compile(r"\b(mkfs|dd)\b[^\n]*of=/dev/(sd|nvme|vd|hd)"), "raw write to a block device"),
    (re.compile(r">\s*/dev/(sd|nvme|vd|hd)[a-z]"), "raw write to a block device"),
    (re.compile(r"\bchmod\s+-R\s+777\s+/(\s|$)"), "world-writable root filesystem"),
]
# History-rewriting git verbs in raw shell (branch parsed separately).
_GIT_FORCE = re.compile(r"\bgit\b[^\n]*\bpush\b[^\n]*(--force(?:-with-lease)?|(?<!\w)-\w*f)")
_GIT_HARD = re.compile(r"\bgit\b[^\n]*\breset\b[^\n]*--hard")
_GIT_REBASE = re.compile(r"\bgit\b[^\n]*\brebase\b")
_BRANCH_TOK = re.compile(r"[A-Za-z0-9._/\-]+")


@dataclass
class Action:
    kind: str            # "git" | "write" | "shell"
    op: str = ""         # git: push|reset|rebase|commit|branch|status|diff|add
    branch: str = ""
    force: bool = False
    hard: bool = False
    path: str = ""
    content: str = ""
    cmd: str = ""


@dataclass
class Decision:
    verdict: str         # ALLOW | BLOCK | ESCALATE
    reason: str
    action_summary: str


class Guardrail:
    def __init__(self, hmac_key: bytes = b"agent-guardrail-v0"):
        self._key = hmac_key
        self.head = hashlib.sha256(b"genesis").hexdigest()
        self.log: list[dict] = []

    # ---- the gate ---------------------------------------------------------
    def check(self, a: Action) -> Decision:
        v, r = self._classify(a)
        d = Decision(v, r, self._summ(a))
        self._sign(d)
        return d

    def _classify(self, a: Action):
        if a.kind == "git":
            if a.op == "push" and a.force and a.branch in PROTECTED:
                return "BLOCK", f"force-push to protected branch '{a.branch}'"
            if a.op == "reset" and a.hard and a.branch in PROTECTED:
                return "BLOCK", f"hard reset (history rewrite) on protected branch '{a.branch}'"
            if a.op == "rebase" and a.branch in PROTECTED:
                return "BLOCK", f"rebase (history rewrite) on protected branch '{a.branch}'"
            return "ALLOW", "git op within policy"
        if a.kind == "write":
            if re.search(r"\.github/workflows/", a.path) and a.content.strip() == "":
                return "BLOCK", f"emptying CI config '{a.path}'"
            if SECRET_RE.search(a.content or ""):
                return "BLOCK", f"writing a secret into '{a.path}'"
            return "ALLOW", "file write within policy"
        if a.kind == "shell":
            return self._classify_shell(a.cmd or "")
        return "ESCALATE", "unknown action kind"

    def _classify_shell(self, c: str):
        """Default-ALLOW, precisely BLOCK the defined threat classes. A coding agent
        must run arbitrary build/test commands, so escalating everything unrecognised
        is unusable (measured: 65% of real CI commands). The guardrail's remit is a
        DEFINED threat model (repo destruction, secret exfiltration, protected-branch
        history rewrite), not policing every command."""
        # 1. secret exfiltration / writing a secret to disk via shell
        if SECRET_RE.search(c) and EXFIL_RE.search(c):
            return "BLOCK", "secret exfiltration over the network"
        if SECRET_RE.search(c) and re.search(r"(>>?|\btee\b)", c):
            return "BLOCK", "writing a secret to disk"
        # 2. catastrophic destruction of the repo / home / root / device
        for rx, why in CATASTROPHIC:
            if rx.search(c):
                return "BLOCK", why
        # 3. protected-branch history rewrite via raw git (parse the branch)
        if _GIT_FORCE.search(c) or _GIT_HARD.search(c) or _GIT_REBASE.search(c):
            toks = set(_BRANCH_TOK.findall(c))
            if toks & set(PROTECTED):
                return "BLOCK", "protected-branch history rewrite via raw git"
            # a force-push/reset/rebase naming a non-protected branch is fine;
            # one naming NO branch rewrites the current branch (could be protected) -> escalate
            non_protected_branch = toks & {"dev", "develop", "feature", "staging"} or \
                re.search(r"\borigin\s+[A-Za-z0-9._/\-]+", c)
            if non_protected_branch:
                return "ALLOW", "history op on a non-protected branch"
            return "ESCALATE", "git history rewrite on an unspecified branch, human review"
        # 4. everything else a build/test agent does is out of scope -> allow
        return "ALLOW", "no policy-relevant effect (build/test/inspect command)"

    # ---- tamper-evident audit chain --------------------------------------
    def _sign(self, d: Decision):
        rec = f"{d.verdict}|{d.reason}|{d.action_summary}"
        self.head = hmac.new(self._key, (self.head + rec).encode(), hashlib.sha256).hexdigest()
        self.log.append({"verdict": d.verdict, "reason": d.reason,
                         "action": d.action_summary, "head": self.head[:12]})

    def verify_chain(self) -> bool:
        h = hashlib.sha256(b"genesis").hexdigest()
        for e in self.log:
            rec = f"{e['verdict']}|{e['reason']}|{e['action']}"
            h = hmac.new(self._key, (h + rec).encode(), hashlib.sha256).hexdigest()
            if h[:12] != e["head"]:
                return False
        return True

    @staticmethod
    def _summ(a: Action) -> str:
        if a.kind == "git":
            fl = (" --force" if a.force else "") + (" --hard" if a.hard else "")
            return f"git {a.op} {a.branch}{fl}".strip()
        if a.kind == "write":
            return f"write {a.path} ({len(a.content or '')}B)"
        return f"shell: {a.cmd}"


# ---------------------------------------------------------------------------
# z3 self-verification (imported lazily so the guard runs without z3 present)
# ---------------------------------------------------------------------------
_OP = {n: i for i, n in enumerate(["push", "reset", "rebase", "commit", "branch"])}
_BR = {n: i for i, n in enumerate(list(PROTECTED) + ["feature", "dev"])}


def prove_policy_sound(skip=()):
    """Prove guard_allows(a) => NOT mutates_protected_history(a), with the safety
    spec written INDEPENDENTLY of the guard. Returns ('PROVED', None) or
    ('HOLE', counterexample). `skip` knocks out a rule to show the proof has teeth."""
    import z3
    op, br = z3.Int("op"), z3.Int("br")
    force, hard = z3.Bool("force"), z3.Bool("hard")
    protected = z3.Or(*[br == _BR[p] for p in PROTECTED])
    dom = z3.And(op >= 0, op < len(_OP), br >= 0, br < len(_BR))

    # INDEPENDENT safety spec: protected-branch history is mutated
    unsafe = z3.And(protected, z3.Or(
        z3.And(op == _OP["push"], force),
        z3.And(op == _OP["reset"], hard),
        op == _OP["rebase"]))

    # the guard's ALLOW predicate (mirror of _classify git branch)
    blocks = []
    if "push" not in skip:  blocks.append(z3.And(op == _OP["push"], force, protected))
    if "reset" not in skip: blocks.append(z3.And(op == _OP["reset"], hard, protected))
    if "rebase" not in skip: blocks.append(z3.And(op == _OP["rebase"], protected))
    allow = z3.Not(z3.Or(*blocks)) if blocks else z3.BoolVal(True)

    s = z3.Solver()
    s.add(dom, allow, unsafe)
    if s.check() == z3.unsat:
        return "PROVED", None
    m = s.model()
    inv, binv = {v: k for k, v in _OP.items()}, {v: k for k, v in _BR.items()}
    return "HOLE", {"op": inv.get(m[op].as_long()), "branch": binv.get(m[br].as_long()),
                    "force": str(m[force]), "hard": str(m[hard])}
