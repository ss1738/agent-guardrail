"""Sandboxed tool executor. Real git/file/shell operations, but every call passes
through the Guardrail first; a BLOCK/ESCALATE is never executed. A hard sandbox
backstop refuses any path outside the working dir, so a guardrail bug in this demo
still cannot touch the host (defense in depth: the guardrail is what we measure,
the sandbox is what keeps a demo bug from nuking the box)."""
from __future__ import annotations
import os
import re
import subprocess

from .guardrail import Action, Guardrail


class Executor:
    def __init__(self, sandbox: str, guard: Guardrail, control_plane=None):
        self.sandbox = os.path.realpath(sandbox)
        self.guard = guard
        # Optional Agent Control Plane: records the REAL outcome of every action (verdict + whether it
        # actually ran) into a signed, independently-verifiable receipt for the session.
        self.control_plane = control_plane
        self.blocked: list[str] = []
        self.executed: list[str] = []

    def _record(self, action: Action, decision, executed: bool) -> None:
        if self.control_plane is not None:
            self.control_plane.record(action, decision.verdict, decision.reason, executed)

    def receipt(self):
        """The signed receipt for this session (or None if no control plane is attached)."""
        return self.control_plane.receipt() if self.control_plane is not None else None

    # ---- backstop: nothing escapes the sandbox ---------------------------
    def _in_sandbox(self, path: str) -> bool:
        full = os.path.realpath(os.path.join(self.sandbox, path))
        return full == self.sandbox or full.startswith(self.sandbox + os.sep)

    def _run(self, argv, cwd=None):
        return subprocess.run(argv, cwd=cwd or self.sandbox, capture_output=True,
                              text=True, timeout=30)

    # ---- the three tools the agent can call ------------------------------
    def git(self, args: str) -> str:
        toks = args.split()
        op = toks[0] if toks else ""
        force = "--force" in toks or "-f" in toks
        hard = "--hard" in toks
        branch = ""
        for t in toks:
            if t in ("main", "master", "release", "dev", "feature"):
                branch = t
        if op in ("push", "reset", "rebase") and not branch:
            branch = "main"  # assume current == main in this demo repo
        a = Action("git", op=op, branch=branch, force=force, hard=hard)
        d = self.guard.check(a)
        if d.verdict != "ALLOW":
            self.blocked.append(f"git {args}  ->  {d.verdict}: {d.reason}")
            self._record(a, d, False)
            return f"⛔ GUARDRAIL {d.verdict}: {d.reason}. Command not executed."
        r = self._run(["git"] + toks)
        self.executed.append(f"git {args}")
        self._record(a, d, True)
        return (r.stdout + r.stderr).strip()[:400] or "(ok)"

    def write_file(self, path: str, content: str) -> str:
        a = Action("write", path=path, content=content)
        d = self.guard.check(a)
        if d.verdict != "ALLOW":
            self.blocked.append(f"write {path}  ->  {d.verdict}: {d.reason}")
            self._record(a, d, False)
            return f"⛔ GUARDRAIL {d.verdict}: {d.reason}. File not written."
        if not self._in_sandbox(path):
            self._record(a, d, False)  # allowed by policy, but the sandbox backstop refused it
            return "⛔ SANDBOX: path escapes the working directory. Refused."
        full = os.path.join(self.sandbox, path)
        os.makedirs(os.path.dirname(full) or self.sandbox, exist_ok=True)
        with open(full, "w") as f:
            f.write(content)
        self.executed.append(f"write {path}")
        self._record(a, d, True)
        return f"wrote {path} ({len(content)} bytes)"

    def run_shell(self, cmd: str) -> str:
        a = Action("shell", cmd=cmd)
        d = self.guard.check(a)
        if d.verdict != "ALLOW":
            self.blocked.append(f"shell '{cmd}'  ->  {d.verdict}: {d.reason}")
            self._record(a, d, False)
            return f"⛔ GUARDRAIL {d.verdict}: {d.reason}. Command not executed."
        # backstop: only run inside sandbox, no absolute paths
        if re.search(r"(^|\s)/", cmd):
            self._record(a, d, False)  # allowed by policy, but the sandbox backstop refused it
            return "⛔ SANDBOX: absolute path in command. Refused."
        r = self._run(["bash", "-lc", cmd])
        self.executed.append(f"shell: {cmd}")
        self._record(a, d, True)
        return (r.stdout + r.stderr).strip()[:400] or "(ok)"
