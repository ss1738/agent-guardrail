"""`qedra-policy`: author + inspect a PolicySpec. Tests init (stdout + file), hash, show
(with the policy root), regex validation, and that the hash the tool prints is the one a receipt binds."""
import io
import os
import sys
import tempfile
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from qedra import policy_cli
from qedra.control_plane import Policy
from qedra.guardrail import PolicySpec


def _run(argv):
    out = io.StringIO()
    with redirect_stdout(out):
        code = policy_cli.main(argv)
    return code, out.getvalue()


def test_init_to_stdout_is_valid_spec():
    code, out = _run(["init", "--protected", "main,release"])
    assert code == 0
    spec = PolicySpec.from_json(out)
    assert spec.protected_branches == ("main", "release")


def test_init_to_file_and_hash_round_trip():
    d = tempfile.mkdtemp()
    path = os.path.join(d, "spec.json")
    code, _ = _run(["init", "--protected", "trunk", "--secret-pattern", r"ACME_[A-Z]+",
                    "--shell-deny", r"kubectl\s+delete", "--out", path])
    assert code == 0
    spec = PolicySpec.from_json(open(path).read())
    assert spec.protected_branches == ("trunk",)
    assert spec.extra_secret_patterns == (r"ACME_[A-Z]+",)
    # the `hash` subcommand prints exactly the spec's content hash
    code, out = _run(["hash", path])
    assert code == 0 and out.strip() == spec.content_hash()


def test_show_prints_policy_root_matching_the_library():
    d = tempfile.mkdtemp()
    path = os.path.join(d, "spec.json")
    _run(["init", "--protected", "trunk", "--out", path])
    spec = PolicySpec.from_json(open(path).read())
    code, out = _run(["show", path, "--policy-id", "acme-prod", "--policy-version", "2"])
    assert code == 0
    assert spec.content_hash() in out
    # the printed policy root equals what Policy(...).root() computes: the tool and the verifier agree
    assert Policy("acme-prod", "2", spec).root() in out


def test_init_rejects_invalid_regex():
    code, _ = _run(["init", "--secret-pattern", "([unclosed"])
    assert code == 2   # bad regex -> usage error, no spec written


def test_show_warns_on_invalid_regex_in_a_spec():
    # a hand-written spec with a broken pattern: show reports it (exit 1) rather than silently passing
    d = tempfile.mkdtemp()
    path = os.path.join(d, "spec.json")
    open(path, "w").write(PolicySpec(extra_shell_denylist=("([bad",)).to_json())
    code, _ = _run(["show", path])
    assert code == 1


def test_default_init_matches_builtin_default():
    code, out = _run(["init"])
    assert code == 0
    assert PolicySpec.from_json(out).content_hash() == PolicySpec().content_hash()


if __name__ == "__main__":
    fns = [f for n, f in sorted(globals().items()) if n.startswith("test_")]
    passed = 0
    for f in fns:
        try:
            f()
            print(f"  ✓ {f.__name__}")
            passed += 1
        except AssertionError as ex:
            print(f"  ✗ {f.__name__}  {ex}")
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
