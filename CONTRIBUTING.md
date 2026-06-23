# Contributing to gcpctx

This guide is for **developers and maintainers** of the `gcpctx` package. End-user documentation lives in [README.md](README.md).

## Prerequisites

- **Python 3.11+** (see `.python-version`)
- **[uv](https://github.com/astral-sh/uv)** for the Python virtualenv and dependencies
- **[mise](https://mise.jdx.dev/)** for the full CLI toolchain (Trunk, Trivy, OSV-Scanner, Grype, CodeQL)—optional if you only run Python tests

## Getting started

```bash
git clone <repo-url> && cd gcpctx
mise trust                    # first time in this checkout
make setup                    # mise tools + uv sync
# or Python-only:
make setup-python
```

Verify the CLI:

```bash
uv run gcpctx --help
```

## Project layout

```text
src/gcpctx/           # Package source
  cli.py              # Typer CLI entrypoint
  activation.py       # Orchestration
  gcloud.py           # Isolated gcloud subprocesses
  shell.py            # bash/zsh export rendering
  tests/              # Colocated pytest suite
docs/adr/             # Architecture decision records (0003–0009)
dev/                  # CI helper scripts
```

Shared agent/human conventions: [AGENTS.md](AGENTS.md).

## Development commands

```bash
make format           # Ruff format + import sort
make lint             # Trunk check (Ruff, Pyright, Pylint, Bandit, Semgrep)
make test             # pytest with coverage
make build            # Hatch wheel/sdist
make scan-vulnerabilities  # OSV-Scanner, Trivy, Grype (serial)
make codeql           # Local CodeQL (requires mise CodeQL on PATH)
```

Without mise, you can still run:

```bash
uv run pytest src/gcpctx/tests
uv run ruff check src/gcpctx
uv run pyright src/gcpctx
bash dev/build.sh
```

## Code style

- Google Python Style Guide (see `.pylintrc`)
- Type hints on public functions; Ruff is the formatter (100-char lines)
- Max cyclomatic complexity **10** per function (Ruff `C901`)
- Imports sorted by Ruff (`I` rule)

## Testing

Tests live under `src/gcpctx/tests/` and must match `test_*.py`.

```bash
uv run pytest src/gcpctx/tests -v
make test    # with coverage
```

**Fake gcloud fixture** (`conftest.py`): prepends a script to `PATH` that logs argv and `CLOUDSDK_CONFIG` to JSONL. Use for integration tests without a real GCP login.

**Isolated state**: tests monkeypatch `gcpctx.paths.user_cache_path`, `approvals_file`, etc., to temp directories with `0700` permissions.

## Architecture decisions

Design rationale is recorded in [docs/adr/](docs/adr/):

| ADR                                                                        | Topic                             |
| -------------------------------------------------------------------------- | --------------------------------- |
| [0003](docs/adr/0003-directory-scoped-gcp-contexts-via-cloudsdk-config.md) | `CLOUDSDK_CONFIG` isolation       |
| [0004](docs/adr/0004-service-account-impersonation-without-keys.md)        | Impersonation auth model          |
| [0005](docs/adr/0005-repository-trust-model-for-project-local-config.md)   | Approval and config hash          |
| [0006](docs/adr/0006-shell-activation-and-environment-contract.md)         | Shell hook stdout contract        |
| [0007](docs/adr/0007-profile-configuration-security-boundary.md)           | Profile validation, env allowlist |
| [0008](docs/adr/0008-process-scoped-execution-via-gcpctx-run.md)           | `gcpctx run` process-scoped exec  |
| [0009](docs/adr/0009-v0.2-secure-by-default-hardening.md)                  | v0.2 security hardening           |

Use the `manage-adr` skill when adding new ADRs (requires `adr` CLI).

## Pull requests

1. Branch from `main`
2. Run `make lint && make test` before pushing
3. Use [Conventional Commits](https://www.conventionalcommits.org/): `feat(scope): description`
4. Update README for user-facing CLI changes; update ADRs for architectural changes

## Security

- Never log credentials or tokens (`logging.py` writes diagnostics to stderr only)
- `gcloud` subprocesses use arg arrays, never `shell=True`
- Shell export tests must pass `bash -n` syntax validation
- Run `make scan-vulnerabilities` and address or document accepted CVE findings
- See [SECURITY.md](SECURITY.md) for threat model and vulnerability reporting

## Releases

Production publishes to PyPI via GitHub Release using **Trusted Publishing** (OIDC):

1. Register a trusted publisher on PyPI for repository `yu-iskw/gcpctx`, workflow `publish.yml`, environment `release`.
2. Protect the `release` GitHub Environment; require `test.yml` and `mise_toolchain.yml` to pass before deploy.
3. Create a GitHub Release; `.github/workflows/publish.yml` builds wheel/sdist, generates CycloneDX SBOM, publishes to PyPI, and attaches provenance.

TestPyPI publishes use `test-publish.yml` with `TESTPYPI_API_TOKEN` (manual dispatch).
