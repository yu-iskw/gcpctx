---
name: setup-dev-env
description: Set up the development environment for the project. Use when starting work on the project, when dependencies are out of sync, or to fix environment setup failures.
---

# Setup Development Environment

Ensure mise, Python, `uv`, and CLI tools match this template, then install dependencies.

## Workflow

1. **Validate tooling** — Read `.python-version` in the repo root; the active interpreter should match. Ensure [mise](https://mise.jdx.dev/) is on `PATH` (see [getting started](https://mise.jdx.dev/getting-started.html) if missing).
2. **Install CLI toolchain** — From the repo root, run `make setup-tools` (or `mise trust` then `mise install --locked`). This installs trunk, trivy, osv-scanner, grype, and codeql from `mise.toml` / `mise.lock` and runs `mise run trunk-install`.
3. **Install Python dependencies** — Run `make setup` (runs `setup-tools` then `setup-python`) or `make setup-python` alone if the toolchain is already present. `dev/setup.sh` installs `uv` from `requirements.setup.txt`, creates the venv, and syncs dependencies.
4. **Optional verification** — Invoke the `verifier` subagent ([../../agents/verifier.md](../../agents/verifier.md)) if you need a full build, lint, and test pass after a broken or fresh environment.

## Success criteria

- Dependencies install without errors into the project virtual environment.
- `mise run lint` or `mise exec trunk@ -- trunk --version` succeeds; Python matches `.python-version`; `uv` is available.
