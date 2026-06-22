# 2. Mise toolchain and attestation settings

Date: 2026-05-23

## Status

Accepted

## Context

The template pins CLI tools (Trunk, Trivy, OSV-Scanner, Grype, CodeQL) with [mise](https://mise.jdx.dev/) using `mise.toml`, `[tasks]`, and a committed `mise.lock`. Releases are gated with `minimum_release_age = "7d"`.

In some environments (restricted CI, air-gapped networks), Sigstore/TUF and GitHub artifact attestation endpoints are unreachable. Mise can verify downloads with cosign, SLSA, and GitHub attestations when those services are available.

## Decision

1. **Invoke tools via mise tasks only** — `mise run <task>` or Makefile targets that delegate to `mise run`. Do not add shell wrapper scripts (e.g. `mise-exec.sh`) to call `mise exec`.
2. **Disable remote attestation checks in `mise.toml`** when the network cannot reach them:
   - `[settings.aqua]` `cosign = false`, `slsa = false`
   - `[settings.github]` `github_attestations = false`
3. **Rely on `mise.lock` checksums** for reproducible installs (`mise install --locked`).
4. **Re-enable attestation** in `mise.toml` when the environment supports Sigstore/TUF and GitHub attestations.

## Consequences

- Installs remain pinned and reproducible via `mise.lock` without live attestation API calls.
- Teams on fully connected networks should consider re-enabling attestation for defense in depth.
- CI validates the toolchain in `.github/workflows/mise_toolchain.yml` using `jdx/mise-action`.

## Python and scanner version policy

- **Application Python**: [uv](https://github.com/astral-sh/uv) + [`.python-version`](../../.python-version) + [`pyproject.toml`](../../pyproject.toml) `requires-python`. CI matrix in [`.github/workflows/test.yml`](../../.github/workflows/test.yml) should include the pinned minor version.
- **Trunk runtime Python**: [`.trunk/trunk.yaml`](../../.trunk/trunk.yaml) `runtimes.enabled` may differ (Trunk-managed); it does not replace the project venv Python.
- **Scanner pins**: Trivy and OSV-Scanner versions are pinned in `.trunk/trunk.yaml`; `mise.lock` should stay aligned when bumping either side. Smoke tests read expected versions from `trunk.yaml`.

## CodeQL on ARM64 hosts

`mise.lock` maps `linux-arm64` and `macos-arm64` to x64 CodeQL bundles. `make setup-tools` skips the version check on those platforms; `make codeql` may require x64 Linux/macOS or Rosetta. Shared logic: [`dev/codeql-platform.sh`](../../dev/codeql-platform.sh).

## Vulnerability scans

`mise run scan-vulnerabilities` runs Trivy, OSV-Scanner, and Grype **serially** to avoid cache/DB contention. OSV-Scanner exits **1** when vulnerabilities are reported (expected gate).

## Global mise config and `--locked`

`make setup-tools` tries `mise install --locked` first, then falls back to `MISE_LOCKED=false mise install` when strict locked mode fails (for example global tools in `~/.config/mise/config.toml` that are not listed in this repo's `mise.lock`). CI smoke tests still require `mise install --locked` on a clean runner.
