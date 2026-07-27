"""The opt-in devops-destruction preset: it blocks catastrophic infra/data commands, does NOT
false-positive on the benign equivalents, and leaves the validated default untouched unless opted in."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent_guardrail.control_plane import Policy
from agent_guardrail.guardrail import Action, Guardrail
from agent_guardrail.presets import PRESETS, preset_names, preset_spec


def v(g, cmd):
    return g._classify(Action("shell", cmd=cmd))[0]


def test_devops_blocks_catastrophic_infra():
    g = Guardrail(preset_spec("devops"))
    for cmd in ["terraform destroy -auto-approve",
                "kubectl delete namespace prod",
                "kubectl delete pods --all -n prod",
                "aws s3 rm s3://prod-bucket --recursive",
                "aws s3 rb s3://prod-bucket --force",
                "aws rds delete-db-instance --db-instance-identifier prod",
                "docker system prune -af",
                "helm uninstall my-release",
                "az group delete --name prod-rg --yes",
                "fly apps destroy myapp",
                "psql -c 'DROP DATABASE production'",
                "mysql -e 'drop table users'",
                "psql -c 'TRUNCATE TABLE orders'"]:
        assert v(g, cmd) == "BLOCK", cmd


def test_devops_allows_the_benign_equivalents():
    g = Guardrail(preset_spec("devops"))
    for cmd in ["terraform plan", "terraform apply -auto-approve",
                "kubectl get pods", "kubectl apply -f deploy.yaml", "kubectl delete pod one-pod",
                "aws s3 ls", "aws s3 cp a.txt s3://bucket/", "aws rds describe-db-instances",
                "docker ps", "docker build -t app .", "helm install app ./chart",
                "psql -c 'SELECT * FROM users'", "cargo test --all", 'git commit -m "fix"']:
        assert v(g, cmd) == "ALLOW", cmd


def test_default_is_unaffected_without_the_preset():
    g = Guardrail()   # the validated default: devops kill-commands are NOT blocked (opt-in only)
    assert v(g, "terraform destroy -auto-approve") == "ALLOW"
    assert v(g, "kubectl delete namespace prod") == "ALLOW"


def test_preset_keeps_the_git_and_default_protection():
    g = Guardrail(preset_spec("devops"))
    assert v(g, "git push origin main --force") == "BLOCK"   # default git protection still there
    assert v(g, "rm -rf .git") == "BLOCK"                    # default catastrophic still there


def test_preset_is_content_addressed():
    assert Policy("p", "1").root() != Policy("p", "1", preset_spec("devops")).root()


def test_unknown_preset_raises():
    try:
        preset_spec("bogus")
        assert False, "unknown preset must raise"
    except ValueError as e:
        assert "bogus" in str(e)


def test_presets_registry():
    assert "devops" in preset_names() and len(PRESETS["devops"]) >= 10


def test_cli_init_preset_roundtrip():
    """`policy init --preset devops` writes a spec that, loaded back, blocks the kill-command."""
    import io
    import tempfile
    from contextlib import redirect_stdout

    from agent_guardrail.guardrail import PolicySpec
    from agent_guardrail.policy_cli import main

    with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False) as fh:
        path = fh.name
    with redirect_stdout(io.StringIO()):
        assert main(["init", "--protected", "main", "--preset", "devops", "--out", path]) == 0
        assert main(["init", "--preset", "nope"]) == 2   # unknown preset -> nonzero
    spec = PolicySpec.from_json(open(path).read())
    g = Guardrail(spec)
    assert v(g, "terraform destroy -auto-approve") == "BLOCK"
    assert v(g, "terraform plan") == "ALLOW"


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
