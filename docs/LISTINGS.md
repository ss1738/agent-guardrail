# MCP directory listings (distribution)

Ready-to-submit listings so the guardrail is discoverable by the exact users who run coding agents. Submit in the order below. Headline number is standardized to **3,790 real commands, 0 false blocks** (the larger, less-hand-picked run).

Facts used (from `pyproject.toml` and `integrations/mcp_server.py`):
- Package: `agent-guardrail` 0.2.0, Python 3.9+, `pip install agent-guardrail`.
- Runs as a stdio MCP server. Client config:
  ```json
  "agent-guardrail": {
    "command": "python3",
    "args": ["/path/to/agent-guardrail/integrations/mcp_server.py"],
    "env": { "GUARDRAIL_WORKSPACE": "/path/to/your/repo" }
  }
  ```
- Differentiator: git-branch policy machine-checked by z3; signed verifiable receipts; MIT.

## Step 0 (prerequisite): a clean MCP entry point
**DONE.** The MCP server now lives in the package at `agent_guardrail/mcp_server.py` with a `main()`, wired as a console script in `pyproject.toml`:
```toml
agent-guardrail-mcp = "agent_guardrail.mcp_server:main"
```
So after `pip install 'agent-guardrail[mcp]'` the server is just `agent-guardrail-mcp`. The old `integrations/mcp_server.py` path still works (backward-compatible shim).

**Remaining:** publish `agent-guardrail` to PyPI so the registries can install it:
```bash
python -m build && twine upload dist/*
```
Do this before the official registry and Smithery entries below (they run the package). The awesome-list and mcp.so entries work even before PyPI.

## 1. awesome-mcp-servers (PR)
Repo: `punkpeye/awesome-mcp-servers`. Add under the Security category (emoji: python + local). One line:

```
- [ss1738/agent-guardrail](https://github.com/ss1738/agent-guardrail) 🐍 🏠 - A runtime gate for coding agents: gates every run_shell / write_file / git call and blocks the ones that wreck a repo (force-push main, rm -rf, secret exfil, CI wipe). Git-branch policy machine-checked by z3.
```

## 2. Official MCP registry (registry.modelcontextprotocol.io)
Save as `server.json` at the repo root, then publish with the `mcp-publisher` CLI (GitHub auth proves the `io.github.ss1738` namespace). Verify the field names against the current registry schema before publishing.

```json
{
  "name": "io.github.ss1738/agent-guardrail",
  "description": "A runtime gate for coding agents. Gates every run_shell/write_file/git tool call and blocks the ones that wreck a repo (force-push main, rm -rf, secret exfil, CI wipe). Git-branch policy machine-checked by z3.",
  "repository": { "url": "https://github.com/ss1738/agent-guardrail", "source": "github" },
  "version": "0.2.0",
  "packages": [
    {
      "registryType": "pypi",
      "identifier": "agent-guardrail",
      "version": "0.2.0",
      "transport": { "type": "stdio" },
      "environmentVariables": [
        { "name": "GUARDRAIL_WORKSPACE", "description": "Absolute path to the repo the agent operates on", "isRequired": true }
      ]
    }
  ]
}
```

## 3. Smithery (smithery.ai)
Save as `smithery.yaml` at the repo root, then connect the GitHub repo on Smithery.

```yaml
startCommand:
  type: stdio
  configSchema:
    type: object
    required: ["workspace"]
    properties:
      workspace:
        type: string
        description: Absolute path to the repo the agent operates on
  commandFunction: |
    (config) => ({
      command: "agent-guardrail-mcp",
      env: { GUARDRAIL_WORKSPACE: config.workspace }
    })
```

## 4. Directory submissions (mcp.so, PulseMCP, Glama)
These take a short submission or index from GitHub. Reusable copy:

- **Name:** agent-guardrail
- **Tagline:** A runtime gate for coding agents that blocks repo-destroying tool calls, with a z3-machine-checked core.
- **Categories / tags:** Security, Developer Tools, AI Agents, Guardrails
- **Description:** agent-guardrail runs as an MCP server in the tool-call path between a coding agent and your repo. Every run_shell, write_file, and git call is checked before it executes, so a compromised or jailbroken agent is stopped regardless of why it issued the action, without trusting the model to behave. It blocks force-pushing main, rm -rf on the working tree, secret exfiltration, and CI wipes, and lets normal build and commit work through. The git-branch sub-policy is machine-checked by z3 (it can find its own gaps); the rest is high-precision heuristics, and the README says which is which. It also exports Ed25519-signed session receipts that a third party can verify with the public key alone. Validated for low false-friction on 3,790 real commands from 49 top-starred repos: 0 false blocks, every tested attack blocked. MIT.
- **Works with:** Claude Desktop, Cursor, Windsurf, Copilot, and any MCP client.
- **Install:** `pip install agent-guardrail`

## Submission order
1. Step 0 entry point + publish to PyPI.
2. awesome-mcp-servers PR (works immediately, high passive-discovery value).
3. Official MCP registry (`server.json` + `mcp-publisher`).
4. Smithery (`smithery.yaml`).
5. mcp.so / PulseMCP / Glama submissions.

Then, and only then, the broadcast (blog, X, Show HN) with links to the listings so the tool is installable the moment someone reads about it.
