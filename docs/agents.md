# Coding agents and gcpctx

Agents get **observation** and **process-scoped execution**. Humans keep **consent**.
Agents cannot self-approve; the optional MCP surface is read-only.

## Tier 1 — `gcpctx run` + strict doctor (default)

No extra packages. Human approves once; the agent inherits scoped credentials for one
process; CI/preflight uses the strict doctor JSON gate:

```bash
gcpctx approve                       # human, once per identity
gcpctx run -- claude                 # agent inherits scoped creds for one process
gcpctx doctor --strict --json        # preflight / CI gate
```

See also the [README coding-agents section](../README.md#coding-agents-cursor-claude-code-codex-copilot).

## Tier 2 — MCP server (optional)

Install the optional extra, then expose a **stdio-only** read-only MCP server:

```bash
pip install 'gcpctx[mcp]'
# or: uv sync --extra mcp
```

Project `.mcp.json` (Claude Code prompts for host-side approval on first use):

```json
{
  "mcpServers": {
    "gcpctx": {
      "type": "stdio",
      "command": "gcpctx",
      "args": ["mcp"]
    }
  }
}
```

Tools (no mutations, no tokens):

| Tool                  | Purpose                                        |
| --------------------- | ---------------------------------------------- |
| `gcpctx_status`       | Activation posture (`status --json` fields)    |
| `gcpctx_doctor`       | Doctor report (`model_dump`; safe fields only) |
| `gcpctx_explain_plan` | Dry-run plan or denial + remediation           |

**Not exposed:** `approve`, `revoke`, `activate`. When `gcpctx_explain_plan` is denied for
missing approval, ask a human to run `gcpctx approve`.

Optional cwd arguments must be existing directories. Bind a workspace root with
`gcpctx mcp --cwd /path/to/repo` or `GCPCTX_MCP_ROOT` so tool `cwd` values outside that
root are refused.

## Tier 3 — Claude Code hook recipes

Hooks are documentation only; gcpctx ships stable exit codes and JSON, not Claude-specific
formats. Schemas evolve with Claude Code — adapt as needed.

### SessionStart posture gate

```json
{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "gcpctx doctor --strict --json || { echo 'gcpctx posture unsafe — run: gcpctx doctor' >&2; exit 2; }"
          }
        ]
      }
    ]
  }
}
```

### PreToolUse guard (block cloud CLIs when inactive)

Block `Bash(gcloud *)` / `Bash(bq *)` / `Bash(terraform *)` when gcpctx is inactive or the
project mismatches. Exit **2** to block; write remediation on stderr for the model:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "cmd=$(jq -r '.tool_input.command // empty' 2>/dev/null); case \"$cmd\" in gcloud\\ *|bq\\ *|terraform\\ *) active=$(gcpctx status --json 2>/dev/null | jq -r '.active // \"false\"'); if [ \"$active\" != \"true\" ]; then echo 'gcpctx inactive — run: gcpctx approve && eval \"$(gcpctx activate)\" or gcpctx run -- …' >&2; exit 2; fi ;; esac"
          }
        ]
      }
    ]
  }
}
```

Tune the matcher and project checks to your repo policy. Prefer **Tier 1**
(`gcpctx run -- <agent>`) so the agent never sees ambient credentials outside the
scoped child process.
