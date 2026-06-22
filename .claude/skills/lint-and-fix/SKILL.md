---
name: lint-and-fix
description: Run linters and fix violations, formatting errors, or style mismatches using Trunk. Use when code quality checks fail, before submitting PRs, or to repair "broken" linting states.
---

# Lint and Fix Loop: Trunk

## Purpose

An autonomous loop for the agent to identify, fix, and verify linting and formatting violations using [Trunk](https://trunk.io), plus dead-code detection with [Vulture](https://github.com/jendrikseipp/vulture).

## Trunk CLI resolution

`make lint` and `make format` delegate to **`mise run lint`** and **`mise run format-trunk`** (see `mise.toml`). Resolve Trunk **once** at the start of the loop:

1. After **`make setup-tools`** (or `mise install --locked`), prefer **`make lint`** / **`make format`** so mise activates the pinned `trunk` from `mise.lock`.
2. If `trunk` is on `PATH` (`command -v trunk`), you may also call `trunk check -a` / `trunk fmt -a` directly (same as `mise run lint` / `mise run format-trunk` when shims are active).
3. Otherwise use the NPM launcher: **`npx --yes @trunkio/launcher`** with the same subcommands (for example `npx --yes @trunkio/launcher check -a`, `npx --yes @trunkio/launcher fmt -a`, `npx --yes @trunkio/launcher install`).
4. If Trunk reports missing managed tools, run **`mise run trunk-install`** or **`make setup-tools`** (or the `npx … install` form above) per [AGENTS.md](../../../AGENTS.md).

When `trunk` is missing from `PATH` and mise is not installed, prefer explicit **`npx --yes @trunkio/launcher …`** over `make lint` / `make format`.

## Loop Logic

1. **Identify**:
   - Run **`make lint`** (**`mise run lint`**, Trunk `check -a`) **or**, when Trunk is unavailable, **`npx --yes @trunkio/launcher check -a`**.
   - Run **dead-code detection**: **`make dead-code`** (alias **`make vulture`**, runs **`uv run vulture`** using `[tool.vulture]` in `pyproject.toml`). Fix unused code the tool reports by removing it or wiring it into real usage—do not silence Vulture with broad excludes unless the user asked for that policy change.
2. **Analyze**: Examine the output from Trunk and Vulture, focusing on the file path, line number, and error message.
3. **Fix**:
   - For formatting issues, run **`make format`** (**`mise run format-trunk`** plus `uv run ssort`) **or** **`npx --yes @trunkio/launcher fmt -a`** when using the NPM launcher.
   - For linting violations, apply the minimum necessary change to the source code to resolve the error.
   - Resolve findings by changing code, types, imports, or structure—not with suppressions (see **Constraints**).
4. **Verify**:
   - Re-run **`make lint`** / **`npx --yes @trunkio/launcher check -a`** (Ruff, **Pyright**, Pylint, and security tools via Trunk).
   - Re-run **`make dead-code`** until Vulture is clean or only acceptable leftover findings remain per project policy.
   - For type-only triage, `uv run pyright` also reads `pyproject.toml` `[tool.pyright]`; prefer Trunk for CI parity.
   - When the change affects **executable code** (behavior, types, imports beyond formatting), run **`make test`** after lint and Vulture pass (pytest-cov; see **Resources**). Same entrypoint as CI: `dev/test_python.sh`. Formatting- or comment-only edits may stop after `make lint` and **`make dead-code`**.
   - If passed: Move to the next issue or finish if all are resolved.
   - If failed: Analyze the new failure and repeat the loop.

## Constraints

- Do not silence Trunk/Ruff/Pyright/Pylint/Bandit/Semgrep findings with inline suppressions (for example `# noqa`, `# type: ignore`, `# pylint: disable`, `ruff: noqa`, file-level `# ruff: noqa`, or Trunk inline disable comments).
- Do not broaden project configuration to hide violations (for example new `[tool.ruff.lint]` ignores, Pyright `report*` toggles, or Pylint disables) unless the user explicitly asked for that policy change.
- Prefer **`make format`** / **`npx … fmt -a`** for auto-fixable style; otherwise fix the underlying issue the linter reports.
- If fixes fail after genuine attempts, stop and surface the finding for a human to decide—do not add suppressions to make CI green.

## Termination Criteria

- No more errors reported by **`make lint`** (or equivalent **`npx … check -a`**).
- **`make dead-code`** exits successfully (no unresolved dead-code issues per project expectations).
- When fixes touched executable code: **`make test`** passes.
- Reached max iteration limit (default: 5).

## Examples

### Scenario: Fixing a formatting violation

1. `make lint` reports formatting issues in `src/your_package/main.py`.
2. Agent runs `make format`.
3. `make lint` and `make dead-code` now pass.

### Scenario: `trunk` not on PATH

1. `make lint` fails with “trunk: command not found”.
2. Agent runs `make setup-tools` or `npx --yes @trunkio/launcher check -a` and continues the loop using `npx --yes @trunkio/launcher fmt -a` for formatting until checks pass.

## Resources

- [Trunk Documentation](https://docs.trunk.io/): Official documentation for the Trunk CLI.
- [Install Trunk CLI (including NPM launcher)](https://github.com/trunk-io/docs/blob/main/code-quality/overview/cli/getting-started/install.md): Launcher behavior and `@trunkio/launcher`.
- [pytest-cov](https://pytest-cov.readthedocs.io/) / [Coverage.py](https://coverage.readthedocs.io/): Test coverage used by `make test` / `make coverage`.
