---
name: security-scan
description: Scan the repository for vulnerable dependencies and known CVEs using Trivy, OSV-Scanner, and Grype via the Makefile. Use when the user asks to scan for vulnerabilities, check dependencies for CVEs, run OSV/Trivy/Grype, or run make scan-vulnerabilities.
compatibility: Requires `trivy`, `osv-scanner`, and `grype` on PATH (prefer `make setup-tools` or `mise install --locked` per `mise.toml`). Run from the repository root after `make setup` or `uv sync` so lockfiles and manifests match what you ship.
---

# Security scan: vulnerable dependencies

## Purpose

Run the template’s **filesystem and dependency vulnerability** checks in one place. The canonical entry point is [`Makefile`](../../../Makefile) target **`scan-vulnerabilities`**, which runs **`mise run scan-vulnerabilities`** (Trivy, OSV-Scanner, and Grype serially via `mise.toml` (`scan-trivy`, then `scan-osv`, then `scan-grype`)).

## When to use

- Scan for CVEs or vulnerable dependencies
- Respond to security review requests for third-party packages
- Verify fixes after bumping dependencies (for example `uv lock`, `uv add`, or edits to `pyproject.toml`)

## How to run

From the repository root (after `make setup-tools` or `mise install --locked`):

```bash
make scan-vulnerabilities
```

Equivalent:

```bash
mise run scan-vulnerabilities
```

Individual tasks:

```bash
mise run scan-trivy
mise run scan-osv
mise run scan-grype
```

## Exit codes

- **OSV-Scanner** exits **1** when it reports known vulnerabilities (even if the run succeeded). That is expected and means findings need triage—not a broken install.
- **Trivy** / **Grype** may exit non-zero on findings or network/DB download errors; read the tool output to distinguish.
- Do **not** add shell wrapper scripts; use `mise run` tasks only.

## Fix loop

1. **Identify:** Read each tool’s output. Note file paths (for example `uv.lock`, `pyproject.toml`) and CVE IDs.
2. **Triage:** Separate **direct** dependencies you control from transitive ones; confirm whether findings are reachable in your use case when deciding urgency.
3. **Fix:** Prefer upgrading or replacing packages (`uv lock`, version pins in `pyproject.toml`). Avoid silencing scanners in the template unless the user explicitly wants policy exceptions documented.
4. **Verify:** Run `make scan-vulnerabilities` again; exit 0 only when there are no reported issues (or document accepted risk).

## Termination

- All scanners report no actionable issues (OSV exit 0), or
- Remaining items are documented as accepted risk, or
- You hit a sensible iteration cap (default: 3) and summarize blockers.

## Related commands (repo)

- **Toolchain install:** `make setup-tools` (`mise install --locked`, `mise run trunk-install`).
- **Dependency bumps:** `uv add`, `uv lock`, `uv sync` (see [AGENTS.md](../../../AGENTS.md) and [CLAUDE.md](../../../CLAUDE.md)).
- **Code-level static analysis:** `make codeql` (`mise run codeql`).
- **Broader quality gates:** `make lint` (`mise run lint`).
