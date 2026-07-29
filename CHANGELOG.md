# Changelog

All notable changes to qedra are recorded here. This project adheres to semantic versioning.

## [0.3.0]

Broadened threat coverage, a first-class verifiable-receipt command, and MCP integration fixes. Every new
blocking rule ships with a paired benign-equivalent test, and the full ruleset is re-validated at **0 false
blocks on 2,848 real shell commands** from 12 trusted popular repositories.

### Added
- **`qedra-attest`** — turn an agent session's durable audit log into a single Ed25519-signed receipt that any
  third party verifies with the public key alone (`qedra-verify`). Manages the signing key at
  `~/.qedra/signing_key` (mode 600), prints the public key, and refuses to sign a tampered log.
- **Cloud metadata (IMDS) credential-theft blocking** — `curl`/`wget`/`python` to `169.254.169.254`,
  `metadata.google.internal`, `100.100.100.200`; the cloud analogue of `curl -d @~/.ssh/id_rsa`, which carried
  no secret and so slipped the exfil rule.
- **DNS-channel exfiltration + DNS tunneling** — `dig`/`nslookup`/`drill` as exfil channels, and lookups whose
  name is built from a command substitution.
- **Reverse shells and backdoor persistence** — `>& /dev/tcp`, `nc -e`/`--exec`, `socat EXEC:`, appending to
  `~/.ssh/authorized_keys`, editing `/etc/sudoers`, piping a crontab from stdin.
- **Broadened `devops` preset** — catastrophic infra/data destruction: k8s PVC/persistentvolume deletion, AWS
  `ec2 terminate-instances`/`eks|ecs delete`/`cloudformation delete-stack`/`s3api delete-bucket`/elasticache,
  `gcloud sql instances delete`, `az vm|aks delete`, `wipefs`, `redis-cli FLUSHALL/FLUSHDB`, `dropdb`,
  `pg_dropcluster`, `mysqladmin drop`, mongo `dropDatabase()`, `npm unpublish`, `cargo yank`.
- **MCP `policy_info` tool** — reports the enforced ruleset (policy id, root commitment, presets, protected
  branches) so a relying party can confirm what is gated.
- **`demo_attest.py`** — a runnable end-to-end story: gated session → `qedra-attest` → verify → forgery caught.

### Fixed
- **Secret detection missed modern provider keys** — `sk-proj-` (OpenAI) and `sk-ant-` (Anthropic), which carry a
  `word-` prefix segment. Now matched, while short strings and benign hyphenated names still pass.
- **The MCP server ignored `GUARDRAIL_PRESET`/`GUARDRAIL_POLICY_SPEC`** — so the opt-in infra/data coverage never
  reached MCP agents, and the receipt's committed policy did not reflect the enforced ruleset. The server now
  loads one spec from the environment and uses it for both the gate and the committed policy.

### Changed
- Threat model (`THREAT_MODEL.md`) and README updated to document the expanded coverage (T7 IMDS, T8 DNS exfil,
  T9 infra/data preset) with honest proven-vs-heuristic labeling.

## [0.2.0]

- Renamed the project to **qedra** (the PyPI name `agent-guardrail` was taken).
- Verifiable receipts (Agent Control Plane): signed, redactable, with an experimental zero-knowledge mode for
  git-branch actions.
- MCP server, Claude Code `PreToolUse` hook, function-calling shim.
- Machine-checked (z3) git-branch sub-policy.
