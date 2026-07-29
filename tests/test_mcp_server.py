"""The MCP server honors GUARDRAIL_PRESET: the opt-in catastrophic-infra/data coverage reaches MCP agents,
and the receipt's committed policy reflects the actually-enforced ruleset (not just the bare default)."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from qedra.claude_code_hook import _load_policy_spec  # the loader the MCP server uses
from qedra.control_plane import Policy
from qedra.guardrail import Action, Guardrail


class _env:
    """Set env vars for the duration of a with-block, restoring the previous values."""
    def __init__(self, **kw):
        self.kw = kw
        self.old = {}
    def __enter__(self):
        for k, v in self.kw.items():
            self.old[k] = os.environ.get(k)
            os.environ[k] = v
        return self
    def __exit__(self, *a):
        for k, v in self.old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_preset_reaches_the_enforced_gate_and_committed_policy():
    with _env(GUARDRAIL_PRESET="devops"):
        spec = _load_policy_spec()
        g = Guardrail(spec)
        assert g._classify(Action("shell", cmd="terraform destroy -auto-approve"))[0] == "BLOCK"
        assert g._classify(Action("shell", cmd="terraform plan"))[0] == "ALLOW"
        # the committed policy binds the actual ruleset: its root differs from the bare default
        assert Policy("p", spec=spec).root() != Policy("p").root()


def test_no_preset_leaves_the_validated_default():
    with _env(GUARDRAIL_PRESET=""):
        g = Guardrail(_load_policy_spec())
        assert g._classify(Action("shell", cmd="terraform destroy -auto-approve"))[0] == "ALLOW"


def test_build_server_constructs_with_a_preset():
    try:
        import mcp  # noqa: F401
    except ImportError:
        return  # mcp extra not installed: skip the full-server construction smoke test
    with _env(GUARDRAIL_PRESET="devops", GUARDRAIL_WORKSPACE=tempfile.mkdtemp()):
        from qedra.mcp_server import build_server
        server = build_server()
        assert server.name == "qedra"


if __name__ == "__main__":
    fns = [f for n, f in sorted(globals().items()) if n.startswith("test_")]
    ok = 0
    for f in fns:
        try:
            f(); print(f"  ok {f.__name__}"); ok += 1
        except Exception as e:
            print(f"  XX {f.__name__}: {e}")
    print(f"{ok}/{len(fns)} passed")
    sys.exit(0 if ok == len(fns) else 1)
