"""Opt-in policy presets: curated patterns for threats beyond the default git/file/local-shell model.

The built-in default is validated for false friction on thousands of real CI commands, so it stays
lean. But an agent with cloud or database credentials can destroy far more than a repo. These presets
add high-precision, catastrophic infra/data-destruction patterns as an OPT-IN `extra_shell_denylist`,
so a team running an agent with real access can turn them on without changing the validated default.

    from qedra.presets import preset_spec
    policy = Policy("prod", spec=preset_spec("devops"))          # default rules + devops kill-commands

They are heuristics (regex over shell), high-precision but bypassable by obfuscation, exactly like the
built-in shell rules. Catch the direct forms; pair with least-privilege credentials and a sandbox.
"""
from __future__ import annotations

from .guardrail import DEFAULT_SPEC, PolicySpec

# High-risk, rarely-legitimate-for-an-autonomous-agent infra/data destruction. Case-sensitive except
# the SQL verbs (inline (?i)), since terraform/kubectl/aws subcommands are lowercase by convention.
PRESETS: dict[str, tuple[str, ...]] = {
    "devops": (
        r"\bterraform\s+destroy\b",
        r"\bkubectl\s+delete\s+(namespace|ns)\b",
        r"\bkubectl\s+delete\b[^\n]*--all\b",
        r"\bkubectl\s+drain\b[^\n]*--force\b",
        r"\baws\s+s3\s+rm\b[^\n]*--recursive\b",
        r"\baws\s+s3\s+rb\b[^\n]*--force\b",
        r"\baws\s+(rds|dynamodb)\s+delete-\w+\b",
        r"\bgcloud\s+[^\n]*\bdelete\b[^\n]*(--quiet|-q)\b",
        r"\baz\s+group\s+delete\b",
        r"\bdocker\s+system\s+prune\b[^\n]*(--all\b|-[a-z]*a)",
        r"\bhelm\s+(uninstall|delete)\b",
        r"\bfly(ctl)?\s+(destroy|apps\s+destroy)\b",
        r"(?i)\b(drop\s+(database|table|schema)|truncate\s+table)\b",
    ),
}


def preset_names() -> list[str]:
    return sorted(PRESETS)


def preset_spec(*names: str, base: PolicySpec = DEFAULT_SPEC) -> PolicySpec:
    """Return a PolicySpec = `base` plus the extra_shell_denylist of the named preset(s). Unknown names
    raise, so a typo never silently disables protection."""
    extra: list[str] = list(base.extra_shell_denylist)
    for n in names:
        if n not in PRESETS:
            raise ValueError(f"unknown preset {n!r} (available: {preset_names()})")
        extra += [p for p in PRESETS[n] if p not in extra]
    return PolicySpec(
        protected_branches=base.protected_branches,
        extra_secret_patterns=base.extra_secret_patterns,
        extra_shell_denylist=tuple(extra),
        ruleset_version=base.ruleset_version,
    )
